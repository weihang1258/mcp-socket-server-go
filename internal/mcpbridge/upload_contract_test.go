package mcpbridge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A1 回归：httpUpload 必须带 Content-Length（agent 侧 length<=0 判 empty body 回 400）。
func TestHttpUploadSendsContentLength(t *testing.T) {
	var gotLen int64 = -1
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLen = r.ContentLength
		b, _ := io.ReadAll(r.Body)
		gotBody = b
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	// httptest URL: http://127.0.0.1:port
	port := 0
	for _, c := range ts.URL[strings.LastIndex(ts.URL, ":")+1:] {
		port = port*10 + int(c-'0')
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	content := make([]byte, 100000)
	for i := range content {
		content[i] = byte(i % 251)
	}
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	n, _, err := httpUpload("127.0.0.1", port, p, "/home/tmp/f.bin", 10)
	if err != nil {
		t.Fatalf("上传失败: %v", err)
	}
	if n != int64(len(content)) {
		t.Fatalf("返回大小 %d != %d", n, len(content))
	}
	if gotLen <= 0 {
		t.Fatalf("请求 Content-Length = %d，仍走 chunked（A1 回归）", gotLen)
	}
	if int64(len(gotBody)) != gotLen {
		t.Fatalf("实际收到 %d 字节，与声明 %d 不符", len(gotBody), gotLen)
	}
	// 尾段完整性：multipart 收尾必须落在 body 末尾
	tail := "\r\n--socketstackput--\r\n"
	if string(gotBody[len(gotBody)-len(tail):]) != tail {
		t.Fatalf("multipart 尾段缺失/错位: %q", gotBody[max(0, len(gotBody)-40):])
	}
}
