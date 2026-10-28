package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// :9001 HTTP 文件服务（http_file.py 逐行移植，设计 §3/:9001）。
// 全程流式（内存 ~1MB 级）；realpath 归一化全盘可访问（与 TCP :9000 同级安全模型）；
// multipart 解析保真三 quirk：伪命中分隔集合含 "--"/"\r\n"/裸"\n"、
// 多 file 字段续写首个句柄且 size 只报最后一段、path 值 4096 上限。

const httpServerVersion = "socket_server-file/1.8.2"

// readHTTPPortFrom 读 config 的 http_port= 行；缺省 9001；显式 0 = 关闭。
func readHTTPPortFrom(path string) int {
	data, err := os.ReadFile(path)
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "http_port=") {
				if n, err := strconv.Atoi(strings.TrimSpace(line[len("http_port="):])); err == nil {
					return n
				}
				log.Printf("读 http_port 配置失败,用默认 9001")
				return 9001
			}
		}
	}
	return 9001
}

// ReadHTTPPort 生产入口：读 /opt/socket/config。
func ReadHTTPPort() int { return readHTTPPortFrom("/opt/socket/config") }

// httpNormalize realpath 归一化：词法消 ../ + 绝对化 + 已存在部分的符号链接解析。
func httpNormalize(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	// EvalSymlinks 对不存在路径失败——对最深存在前缀解析后拼接剩余部分
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	dir, base := filepath.Split(abs)
	if resolvedDir, err := filepath.EvalSymlinks(filepath.Clean(dir)); err == nil {
		return filepath.Join(resolvedDir, base)
	}
	return filepath.Clean(abs)
}

// errMultipart 表单畸形类错误 → 400。
var errMultipart = errors.New("multipart malformed")

// ---- 流式 body 读取器（_BodyReader 移植）----

type bodyReader struct {
	r         io.Reader
	remaining int64
	buf       []byte
}

const bodyChunk = 256 * 1024

func newBodyReader(r io.Reader, length int64) *bodyReader {
	return &bodyReader{r: r, remaining: length}
}

func (b *bodyReader) fill(need int) {
	for len(b.buf) < need && b.remaining > 0 {
		chunk := make([]byte, min64(bodyChunk, b.remaining))
		n, err := b.r.Read(chunk)
		if n == 0 {
			if err != nil {
				b.remaining = 0
			}
			if n == 0 {
				b.remaining = 0
				break
			}
		}
		b.buf = append(b.buf, chunk[:n]...)
		b.remaining -= int64(n)
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (b *bodyReader) take(n int) []byte {
	out := b.buf[:n]
	b.buf = b.buf[n:]
	return out
}

func (b *bodyReader) readHeaders() ([]byte, error) {
	for {
		if idx := bytes.Index(b.buf, []byte("\r\n\r\n")); idx != -1 {
			out := b.buf[:idx]
			b.buf = b.buf[idx+4:]
			return out, nil
		}
		if len(b.buf) > 16384 {
			return nil, fmt.Errorf("%w: part headers too large", errMultipart)
		}
		before := len(b.buf)
		b.fill(before + 8192)
		if len(b.buf) == before {
			return nil, fmt.Errorf("%w: truncated(headers)", errMultipart)
		}
	}
}

// streamValue 读字段值至分隔行（不含），经 sink 落地。
// 伪命中处理（RFC 2046 + Python 扩展）：delim 命中后必须后随 "--"/"\r\n"/"\n"
// 才算分隔行；否则 delim 本身是内容，写掉继续扫。
func (b *bodyReader) streamValue(delim []byte, sink func([]byte)) error {
	keep := len(delim) + 1
	for {
		idx := bytes.Index(b.buf, delim)
		if idx != -1 {
			tail := b.buf[idx+len(delim):]
			if bytes.HasPrefix(tail, []byte("--")) || bytes.HasPrefix(tail, []byte("\r\n")) || bytes.HasPrefix(tail, []byte("\n")) {
				sink(b.buf[:idx])
				b.buf = b.buf[idx+len(delim):]
				return nil
			}
			// 伪命中：是内容不是分隔行
			if idx+len(delim)+2 < len(b.buf) {
				sink(b.buf[:idx+len(delim)])
				b.buf = b.buf[idx+len(delim):]
				continue
			}
			// 后续字节未到，等 fill
		}
		if len(b.buf) > keep {
			sink(b.buf[:len(b.buf)-keep])
			b.buf = b.buf[len(b.buf)-keep:]
		}
		before := len(b.buf)
		b.fill(before + bodyChunk)
		if len(b.buf) == before {
			return fmt.Errorf("%w: truncated(value)", errMultipart)
		}
	}
}

// ---- 字段 sink ----

type capSink struct {
	parts [][]byte
	total int
	cap   int
}

func (c *capSink) Write(p []byte) (int, error) {
	c.total += len(p)
	if c.total > c.cap {
		return 0, fmt.Errorf("%w: field value too large", errMultipart)
	}
	c.parts = append(c.parts, p)
	return len(p), nil
}

func (c *capSink) value() string {
	var sb strings.Builder
	for _, p := range c.parts {
		sb.Write(p)
	}
	return sb.String()
}

// parseMultipartStream multipart 全量解析（Python parse_multipart_stream 同构）。
// openFile(pathVal) 由调用方提供落盘策略；返回 path/size/filename/fileSeen。
func parseMultipartStream(body io.Reader, contentLength int64, boundary string, openFile func(pathVal string) io.WriteCloser) (pathVal string, size int64, fileSeen bool, err error) {
	br := newBodyReader(body, contentLength)
	delim := append([]byte("\r\n--"), boundary...)
	br.fill(len(boundary) + 4)
	if !bytes.HasPrefix(br.buf, append([]byte("--"), boundary...)) {
		return "", 0, false, fmt.Errorf("%w: malformed", errMultipart)
	}
	br.take(len(boundary) + 2)

	var fh io.WriteCloser
	defer func() {
		if fh != nil {
			fh.Close()
		}
	}()
	for {
		br.fill(2)
		if len(br.buf) == 0 {
			return "", 0, false, fmt.Errorf("%w: truncated(boundary)", errMultipart)
		}
		if bytes.HasPrefix(br.buf, []byte("--")) {
			break // --boundary-- 结束
		}
		if !bytes.HasPrefix(br.buf, []byte("\r\n")) {
			return "", 0, false, fmt.Errorf("%w: malformed", errMultipart)
		}
		br.take(2)
		headers, err := br.readHeaders()
		if err != nil {
			return "", 0, false, err
		}
		name := fieldName(string(headers))
		switch name {
		case "path":
			sink := &capSink{cap: 4096}
			if err := br.streamValue(delim, func(p []byte) { sink.Write(p) }); err != nil {
				return "", 0, false, err
			}
			pathVal = sink.value()
		case "file":
			if fh == nil {
				fh = openFile(pathVal) // path 晚到（非常规顺序）时 openFile 收 ""
			}
			var seg int64
			if err := br.streamValue(delim, func(p []byte) {
				seg += int64(len(p))
				fh.Write(p)
			}); err != nil {
				return "", 0, false, err
			}
			size = seg // 多 file 字段：只报最后一段（quirk）
			fileSeen = true
		default:
			if err := br.streamValue(delim, func([]byte) {}); err != nil {
				return "", 0, false, err
			}
		}
	}
	return pathVal, size, fileSeen, nil
}

var (
	reFieldName     = regexp.MustCompile(`\bname="([^"]*)"`)
	reFieldFilename = regexp.MustCompile(`\bfilename="([^"]*)"`)
)

// fieldName 从 part 头块解析 name="..."（Python re.search 同语义）。
func fieldName(headers string) string {
	if m := reFieldName.FindStringSubmatch(headers); m != nil {
		return m[1]
	}
	return ""
}

// ---- http.Handler ----

// FileServerHandler :9001 处理器（GET /files 下载流式；POST /files 上传流式）。
func FileServerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/files", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", httpServerVersion)
		switch r.Method {
		case http.MethodGet:
			handleFileGET(w, r)
		case http.MethodPost:
			handleFilePOST(w, r)
		default:
			sendErrorJSON(w, 400, "bad method")
		}
	})
	return mux
}

func sendErrorJSON(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

func handleFileGET(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		sendErrorJSON(w, 400, "bad query")
		return
	}
	raw := q.Get("path")
	if raw == "" {
		sendErrorJSON(w, 400, "missing path parameter")
		return
	}
	path := httpNormalize(raw)
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		sendErrorJSON(w, 404, fmt.Sprintf("file not found: %s", path))
		return
	}
	f, err := os.Open(path)
	if err != nil {
		sendErrorJSON(w, 500, fmt.Sprintf("read failed: %v", err))
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
	w.WriteHeader(200)
	io.Copy(w, io.LimitReader(f, fi.Size())) // 1MB 分块由 net/http 缓冲实现，流式等价
}

func handleFilePOST(w http.ResponseWriter, r *http.Request) {
	length := r.ContentLength
	if h := r.Header.Get("Content-Length"); h != "" {
		if n, err := strconv.ParseInt(h, 10, 64); err == nil {
			length = n
		}
	}
	if length <= 0 {
		sendErrorJSON(w, 400, "bad content-length")
		return
	}
	boundary := boundaryFromContentType(r.Header.Get("Content-Type"))
	if boundary == "" {
		sendErrorJSON(w, 400, "multipart boundary missing")
		return
	}

	// 落盘策略：path 先到直写 <path>.part + 原子 rename；file 先到临时文件后搬运
	var fh io.WriteCloser
	var partPath, tempPath string
	defer func() {
		if fh != nil {
			fh.Close()
		}
		// 失败清理：删 .part 与临时文件
		for _, p := range []string{partPath, tempPath} {
			if p != "" {
				os.Remove(p)
			}
		}
	}()
	openFile := func(pathVal string) io.WriteCloser {
		if fh != nil {
			return fh // 多 file 字段续写首个句柄
		}
		if pathVal != "" {
			dest := httpNormalize(pathVal)
			os.MkdirAll(filepath.Dir(dest), 0o777)
			part := dest + ".part"
			f, err := os.Create(part)
			if err != nil {
				return errWriter{err}
			}
			fh, partPath = f, part
			return f
		}
		tmp, err := os.CreateTemp("", "socketstack-upload-*")
		if err != nil {
			return errWriter{err}
		}
		fh, tempPath = tmp, tmp.Name()
		return tmp
	}

	pathVal, size, fileSeen, err := parseMultipartStream(r.Body, length, boundary, openFile)
	if err != nil {
		if strings.Contains(err.Error(), "field value too large") || errors.Is(err, errMultipart) {
			sendErrorJSON(w, 400, err.Error())
			return
		}
		sendErrorJSON(w, 400, err.Error())
		return
	}
	if pathVal == "" {
		sendErrorJSON(w, 400, "multipart missing path or file field")
		return
	}
	dest := httpNormalize(pathVal)
	if tempPath != "" {
		os.MkdirAll(filepath.Dir(dest), 0o777)
		if err := os.Rename(tempPath, dest); err != nil {
			sendErrorJSON(w, 500, fmt.Sprintf("write failed: %v", err))
			return
		}
		tempPath = "" // 已搬运，别在 defer 里删掉
	} else {
		fh.Close()
		fh = nil
		if err := os.Rename(partPath, dest); err != nil {
			sendErrorJSON(w, 500, fmt.Sprintf("write failed: %v", err))
			return
		}
		partPath = ""
	}
	_ = fileSeen // Python 仅记录 file_seen；成功判定只看 path 字段（size=0 亦 200）
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	fmt.Fprintf(w, `{"ok":true,"path":%q,"size":%d}`, dest, size)
}

type errWriter struct{ err error }

func (e errWriter) Write([]byte) (int, error) { return 0, e.err }
func (e errWriter) Close() error              { return e.err }

// boundaryFromContentType 提取 boundary（缺失/超长 256 → ""）。
func boundaryFromContentType(ct string) string {
	for _, part := range strings.Split(ct, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "boundary=") {
			b := strings.Trim(strings.TrimPrefix(part, "boundary="), `" `)
			if b != "" && len(b) <= 256 {
				return b
			}
			return ""
		}
	}
	return ""
}

// StartHTTPFileServer 双栈启动 :9001（非阻塞）；port=0 关闭；IPv6 失败降级仅 IPv4。
// 返回 stop 函数供优雅关闭。
func StartHTTPFileServer(port int) (stop func(), err error) {
	noop := func() {}
	if port == 0 {
		log.Printf("http_port=0,HTTP 文件服务不启动")
		return noop, nil
	}
	srv := &http.Server{Handler: FileServerHandler(), Addr: fmt.Sprintf(":%d", port)}
	ln4, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return noop, fmt.Errorf("HTTP 文件服务 IPv4 监听失败: %w", err)
	}
	go srv.Serve(ln4)
	ln6, err := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port))
	if err == nil {
		go srv.Serve(ln6)
	} else {
		log.Printf("HTTP 文件服务 IPv6 监听失败:%v,降级为仅 IPv4 模式", err)
	}
	log.Printf("HTTP 文件服务监听 0.0.0.0:%d (IPv4)", port)
	return func() {
		srv.Close()
	}, nil
}
