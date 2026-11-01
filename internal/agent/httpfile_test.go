package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// http_port 读取：/opt/socket/config 的 http_port= 行；缺省 9001；0=关闭
func TestHTTPPortConfig(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	if got := readHTTPPortFrom(filepath.Join(dir, "nope")); got != 9001 {
		t.Fatalf("missing file want 9001, got %d", got)
	}
	p := filepath.Join(dir, "config")
	os.WriteFile(p, []byte("autoupgrade=on\nhttp_port=9002\n"), 0o644)
	if got := readHTTPPortFrom(p); got != 9002 {
		t.Fatalf("want 9002, got %d", got)
	}
	os.WriteFile(p, []byte("http_port=0\n"), 0o644)
	if got := readHTTPPortFrom(p); got != 0 {
		t.Fatalf("explicit 0 must be preserved, got %d", got)
	}
	os.WriteFile(p, []byte("http_port=abc\n"), 0o644)
	if got := readHTTPPortFrom(p); got != 9001 {
		t.Fatalf("bad value falls back 9001, got %d", got)
	}
}

// realpath 归一化：.. 词法消除
func TestHTTPNormalize(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	deep := filepath.Join(dir, "a", "..", "b")
	if got := httpNormalize(deep); got != filepath.Join(dir, "b") {
		t.Fatalf("lexical clean failed: %q", got)
	}
	// 绝对化：相对路径按 cwd
	if !filepath.IsAbs(httpNormalize("x/y")) {
		t.Fatal("must be absolute")
	}
}

// 9001 路径白名单（P3-2，六轮验收）：不做鉴权（P0-1 设计认定不变），但收窄
// 可读写目录防误操作——一次手滑 path= 就能覆盖 current/socket_server 或 unit
// 文件。允许：/home/tmp/ 前缀 + 升级 staging（versions/*/.staging/，dt20 链路
// PushBinary 必经）。测试注入 TempDir 顶替 /home/tmp。
func TestFileServerPathAllowlist(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})

	h := FileServerHandler()

	// GET 白名单内 → 200
	ok := filepath.Join(dir, "cap.pcap")
	os.WriteFile(ok, []byte("PCAP"), 0o644)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/files?path="+ok, nil))
	if w.Code != 200 {
		t.Fatalf("白名单内 GET 应 200，got %d: %s", w.Code, w.Body.String())
	}

	// GET 白名单外 → 403（含允许范围说明）
	for _, p := range []string{"/etc/shadow", "/opt/socket/versions/current/socket_server"} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/files?path="+p, nil))
		if w.Code != 403 {
			t.Fatalf("%s 应 403，got %d: %s", p, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "允许范围") {
			t.Fatalf("403 应说明允许范围: %s", w.Body.String())
		}
	}

	// GET 穿越逃逸 → 403（normalize 后 /etc/passwd 出白名单）
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/files?path="+filepath.Join(dir, "..", "escape"), nil))
	if w.Code != 403 {
		t.Fatalf("穿越应 403，got %d: %s", w.Code, w.Body.String())
	}

	// GET 升级 staging → 200（dt20 链路）
	// 版本号取永不存在的形态：不能写死现网版本——真机上 .staging 可能残留
	// 历史测试/推送的文件（实测踩过），404 前提即被打破
	staging := "/opt/socket/versions/99.99.99/.staging/socket_server"
	// 真实 staging 文件在测试机上不存在 → 404（而非 403），证明白名单放行了
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/files?path="+staging, nil))
	if w.Code != 404 {
		t.Fatalf("staging 应进白名单（404=文件不存在而非 403=拒绝），got %d: %s", w.Code, w.Body.String())
	}

	// POST 白名单内 → 200；白名单外 → 403
	post := func(path string) *httptest.ResponseRecorder {
		body := "--B\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n" + path +
			"\r\n--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\nDATA\r\n--B--\r\n"
		return httpPost(t, h, strings.NewReader(body), "multipart/form-data; boundary=B")
	}
	if w := post(filepath.Join(dir, "up.bin")); w.Code != 200 {
		t.Fatalf("白名单内 POST 应 200，got %d: %s", w.Code, w.Body.String())
	}
	if w := post("/etc/evil"); w.Code != 403 {
		t.Fatalf("白名单外 POST 应 403，got %d: %s", w.Code, w.Body.String())
	}
	// POST 升级 staging → 放行（PushBinary 路径；root 下会真写盘，必须自清——
	// 残留会让下轮全量的 GET 检查拿到 200 而非 404，测试间污染）
	t.Cleanup(func() { os.RemoveAll("/opt/socket/versions/99.99.99") })
	if w := post(staging); w.Code == 403 {
		t.Fatalf("staging POST 不应 403: %s", w.Body.String())
	}
}

// setAllowlistForTest 白名单收窄后，既有各测试的 TempDir 需要放行。
func setAllowlistForTest(t *testing.T, prefixes []string) {
	t.Helper()
	prev := fileAllowlistPrefixes
	t.Cleanup(func() { fileAllowlistPrefixes = prev })
	fileAllowlistPrefixes = prefixes
}

func httpPost(t *testing.T, h http.Handler, body io.Reader, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/files", body)
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// GET：200 流式 + 响应头契约 + 404 JSON + 400 缺参
func TestHTTPGET(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	src := filepath.Join(dir, "dl.bin")
	os.WriteFile(src, bytes.Repeat([]byte("x"), 2<<20), 0o644) // 2MB，超 1MB 分块

	h := FileServerHandler()
	req := httptest.NewRequest("GET", "/files?path="+src, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET 200 want, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Server") == "" {
		t.Fatal("Server header missing")
	}
	if got := w.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("content-type: %q", got)
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, `filename="dl.bin"`) {
		t.Fatalf("disposition: %q", got)
	}
	if cl := w.Header().Get("Content-Length"); cl != fmt.Sprint(2<<20) {
		t.Fatalf("content-length: %q", cl)
	}
	if w.Body.Len() != 2<<20 {
		t.Fatalf("body len %d", w.Body.Len())
	}

	// 404 JSON
	req = httptest.NewRequest("GET", "/files?path="+filepath.Join(dir, "nope"), nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "file not found") {
		t.Fatalf("404 JSON: %d %s", w.Code, w.Body.String())
	}
	// 400 缺 path
	req = httptest.NewRequest("GET", "/files", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("missing path want 400, got %d", w.Code)
	}
}

// POST 标准上传：path 先到 → .part 直写 + 原子 rename；父目录自动创建
func TestHTTPPOSTStandard(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	h := FileServerHandler()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("path", filepath.Join(dir, "up", "f.bin"))
	fw, _ := mw.CreateFormFile("file", "f.bin")
	fw.Write([]byte("uploaded-data"))
	mw.Close()

	w := httpPost(t, h, &buf, mw.FormDataContentType())
	if w.Code != 200 {
		t.Fatalf("POST 200 want, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Ok   bool   `json:"ok"`
		Path string `json:"path"`
		Size int    `json:"size"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	want := filepath.Join(dir, "up", "f.bin")
	if !resp.Ok || resp.Path != want || resp.Size != 13 {
		t.Fatalf("resp wrong: %+v", resp)
	}
	data, _ := os.ReadFile(want)
	if string(data) != "uploaded-data" {
		t.Fatalf("file content: %q", data)
	}
	if _, err := os.Stat(want + ".part"); !os.IsNotExist(err) {
		t.Fatal(".part must be renamed away")
	}
}

// file 字段先到 → 落临时文件后搬运
func TestHTTPPOSTFileFirst(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	h := FileServerHandler()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "x.bin")
	fw.Write([]byte("second-order"))
	mw.WriteField("path", filepath.Join(dir, "ff.bin"))
	mw.Close()

	w := httpPost(t, h, &buf, mw.FormDataContentType())
	if w.Code != 200 {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(dir, "ff.bin"))
	if err != nil || string(data) != "second-order" {
		t.Fatalf("file-first move failed: %v %q", err, data)
	}
}

// 多 file 字段：续写首个句柄，size 只报最后一段
func TestHTTPPOSTMultiFile(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	h := FileServerHandler()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("path", filepath.Join(dir, "multi.bin"))
	fw, _ := mw.CreateFormFile("file", "a")
	fw.Write([]byte("AAAA"))
	fw2, _ := mw.CreateFormFile("file", "b")
	fw2.Write([]byte("BB"))
	mw.Close()

	w := httpPost(t, h, &buf, mw.FormDataContentType())
	if w.Code != 200 {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	data, _ := os.ReadFile(filepath.Join(dir, "multi.bin"))
	if string(data) != "AAAABB" {
		t.Fatalf("append semantics broken: %q", data)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["size"] != float64(2) {
		t.Fatalf("size must report last segment only: %v", resp["size"])
	}
}

// 缺 path：400（body 全量消费后）
func TestHTTPPOSTMissingPath(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	h := FileServerHandler()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "x")
	fw.Write([]byte("zzz"))
	mw.Close()
	w := httpPost(t, h, &buf, mw.FormDataContentType())
	if w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
	// 残留临时文件应被清理
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("temp litter: %v", entries)
	}
}

// 分隔行尾部容忍（Python stream_value 伪命中集合 = {"--", "\r\n", "\n"}）：
// 终界符尾部裸 \n 合法解析（值不含分隔串）；中段裸 \n 尾分隔行 → malformed
// （Python parse 循环同样报错——容忍范围仅指伪命中判定，非全 LF framing）。
func TestHTTPPOSTDelimiterTailTolerance(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	h := FileServerHandler()
	boundary := "BNDRS123"
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	fmt.Fprintf(&buf, "Content-Disposition: form-data; name=\"path\"\r\n\r\n")
	fmt.Fprintf(&buf, "%s\r\n--%s\r\n", filepath.Join(dir, "lf.bin"), boundary)
	fmt.Fprintf(&buf, "Content-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\n")
	fmt.Fprintf(&buf, "LINE-DATA\r\n--%s--\n", boundary) // 终界符尾部裸 \n
	w := httpPost(t, h, &buf, "multipart/form-data; boundary="+boundary)
	if w.Code != 200 {
		t.Fatalf("LF tail on final delimiter must parse: %d %s", w.Code, w.Body.String())
	}
	data, _ := os.ReadFile(filepath.Join(dir, "lf.bin"))
	if string(data) != "LINE-DATA" {
		t.Fatalf("content mismatch: %q", data)
	}
}

func TestHTTPPOSTMidBodyLFBoundaryFails(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	h := FileServerHandler()
	boundary := "BNDRS123"
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	fmt.Fprintf(&buf, "Content-Disposition: form-data; name=\"path\"\r\n\r\n")
	fmt.Fprintf(&buf, "%s\r\n--%s\n", filepath.Join(dir, "lf2.bin"), boundary)
	fmt.Fprintf(&buf, "Content-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\n")
	fmt.Fprintf(&buf, "X\r\n--%s--\r\n", boundary)
	w := httpPost(t, h, &buf, "multipart/form-data; boundary="+boundary)
	if w.Code != 400 {
		t.Fatalf("mid-body LF-tail delimiter must fail as Python does, got %d", w.Code)
	}
}

func TestHTTPPOSTNoBoundary(t *testing.T) {
	h := FileServerHandler()
	w := httpPost(t, h, bytes.NewReader([]byte("junk")), "multipart/form-data")
	if w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// path 字段值超 4096 → 400
func TestHTTPPOSTPathTooLarge(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	h := FileServerHandler()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("path", filepath.Join(dir, strings.Repeat("p", 5000)))
	fw, _ := mw.CreateFormFile("file", "x")
	fw.Write([]byte("q"))
	mw.Close()
	w := httpPost(t, h, &buf, mw.FormDataContentType())
	if w.Code != 400 || !strings.Contains(w.Body.String(), "field value too large") {
		t.Fatalf("want 400 field value too large, got %d %s", w.Code, w.Body.String())
	}
}

// GET query 字面 %（非法转义）：Python 宽容保留原样 → 应取到文件名含 % 的文件
func TestHTTPGETLiteralPercent(t *testing.T) {
	dir := t.TempDir()
	setAllowlistForTest(t, []string{dir + "/"})
	name := "50%off.txt"
	os.WriteFile(filepath.Join(dir, name), []byte("pct"), 0o644)
	h := FileServerHandler()
	req := httptest.NewRequest("GET", "/files?path="+filepath.Join(dir, name), nil) // 未编码 %
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("literal %% must be lenient (Python unquote keeps invalid), got %d %s", w.Code, w.Body.String())
	}
}
