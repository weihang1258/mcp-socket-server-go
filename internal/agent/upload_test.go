package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/weihang1258/mcp-socket-server-go/internal/frame"
)

// 等待指定 inline ack（"21 ok" 等）
func waitAck(t *testing.T, c net.Conn, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	c.SetReadDeadline(deadline)
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 64)
	var got []byte
	for time.Now().Before(deadline) {
		n, err := c.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
			if string(got) == want {
				return
			}
		}
		if err != nil {
			t.Fatalf("waitAck %q: %v (got %q)", want, err, got)
		}
	}
	t.Fatalf("waitAck %q timeout, got %q", want, got)
}

// 上传握手全链路：21→22→23(裸帧)→24，明文内容落盘
func TestUploadHandshakePlaintext(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	dst := filepath.Join(t.TempDir(), "up.bin")

	req, _ := json.Marshal(map[string]any{"filepath": dst, "gzip": false})
	c.Write(frame.Encode(21, req))
	waitAck(t, c, "21 ok")

	content := []byte("hello upload 123")
	l := make([]byte, 8)
	binary.LittleEndian.PutUint64(l, uint64(len(content)))
	c.Write(frame.Encode(22, l))
	waitAck(t, c, "22 ok")

	// step23：裸帧 [4B len][content]，分两片发。
	// 注意：两帧背靠背写入若被 TCP 合成一次读取，会触发服务端超收全弃 quirk
	// （Python 同样如此）——帧间必须留出服务端消化间隔。
	c.Write(frame.EncodeRaw(content[:5]))
	time.Sleep(200 * time.Millisecond)
	c.Write(frame.EncodeRaw(content[5:]))
	waitAck(t, c, "23 ok")

	c.Write(frame.Encode(24, nil))
	waitAck(t, c, "24 ok")

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("file content mismatch: %q", got)
	}
}

// gzip 内容：解压后落盘
func TestUploadHandshakeGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("gzipped-data"))
	zw.Close()

	addr := startTestAgent(t)
	c := dial(t, addr)
	dst := filepath.Join(t.TempDir(), "up.gz")

	req, _ := json.Marshal(map[string]any{"filepath": dst, "gzip": true})
	c.Write(frame.Encode(21, req))
	waitAck(t, c, "21 ok")
	l := make([]byte, 8)
	binary.LittleEndian.PutUint64(l, uint64(buf.Len()))
	c.Write(frame.Encode(22, l))
	waitAck(t, c, "22 ok")
	c.Write(frame.EncodeRaw(buf.Bytes()))
	waitAck(t, c, "23 ok")
	c.Write(frame.Encode(24, nil))
	waitAck(t, c, "24 ok")

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "gzipped-data" {
		t.Fatalf("want decompressed, got %q", got)
	}
}

// `^$` 特例：写空文件
func TestUploadCaretDollarEmptyFile(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	dst := filepath.Join(t.TempDir(), "empty.bin")

	req, _ := json.Marshal(map[string]any{"filepath": dst, "gzip": false})
	c.Write(frame.Encode(21, req))
	waitAck(t, c, "21 ok")
	l := make([]byte, 8)
	binary.LittleEndian.PutUint64(l, 2)
	c.Write(frame.Encode(22, l))
	waitAck(t, c, "22 ok")
	c.Write(frame.EncodeRaw([]byte("^$")))
	waitAck(t, c, "23 ok")
	c.Write(frame.Encode(24, nil))
	waitAck(t, c, "24 ok")

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty file, got %q", got)
	}
}

// dt23 内容超长：断连（RuntimeError 语义）
func TestUploadOversizeDisconnects(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	dst := filepath.Join(t.TempDir(), "over.bin")

	req, _ := json.Marshal(map[string]any{"filepath": dst, "gzip": false})
	c.Write(frame.Encode(21, req))
	waitAck(t, c, "21 ok")
	l := make([]byte, 8)
	binary.LittleEndian.PutUint64(l, 4)
	c.Write(frame.Encode(22, l))
	waitAck(t, c, "22 ok")
	c.Write(frame.EncodeRaw([]byte("toolong"))) // 7 > 4
	// 无 "23 ok"；连接被服务端关闭
	deadline := time.Now().Add(2 * time.Second)
	c.SetReadDeadline(deadline)
	buf := make([]byte, 64)
	for time.Now().Before(deadline) {
		n, err := c.Read(buf)
		if n > 0 && string(buf[:n]) == "23 ok" {
			t.Fatal("oversize must not ack 23 ok")
		}
		if err != nil {
			return // EOF = 服务端关闭
		}
	}
	t.Fatal("expected disconnect on oversize content")
}

// dt3 下载：路径读连接级 filepath，payload 仅 gzip；[8B <Q][content]
func TestDT3Download(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	src := filepath.Join(t.TempDir(), "dl.bin")
	os.WriteFile(src, []byte("download-me"), 0o644)

	req, _ := json.Marshal(map[string]any{"filepath": src, "gzip": false})
	c.Write(frame.Encode(21, req))
	waitAck(t, c, "21 ok")

	c.Write(frame.Encode(3, []byte(`{"gzip":false}`)))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	head := make([]byte, 8)
	if _, err := ioReadFull(c, head); err != nil {
		t.Fatalf("dt3 header: %v", err)
	}
	n := binary.LittleEndian.Uint64(head)
	body := make([]byte, n)
	if _, err := ioReadFull(c, body); err != nil {
		t.Fatalf("dt3 body: %v", err)
	}
	if string(body) != "download-me" {
		t.Fatalf("dt3 content mismatch: %q", body)
	}
}

// dt3 gzip=true：内容 gzip 压缩返回
func TestDT3DownloadGzip(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	src := filepath.Join(t.TempDir(), "dl2.bin")
	os.WriteFile(src, []byte("compress-me"), 0o644)

	req, _ := json.Marshal(map[string]any{"filepath": src, "gzip": true})
	c.Write(frame.Encode(21, req))
	waitAck(t, c, "21 ok")

	c.Write(frame.Encode(3, []byte(`{"gzip":true}`)))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	head := make([]byte, 8)
	ioReadFull(c, head)
	n := binary.LittleEndian.Uint64(head)
	body := make([]byte, n)
	ioReadFull(c, body)
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("dt3 gzip body: %v", err)
	}
	out, _ := ioReadAll(zr)
	if string(out) != "compress-me" {
		t.Fatalf("decompressed mismatch: %q", out)
	}
}

func ioReadFull(c net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := c.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

func ioReadAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out, err
		}
	}
}
