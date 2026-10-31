package mcpbridge

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setFetchBase(t *testing.T, _, relBase string) {
	t.Helper()
	prevRel := releaseBase
	releaseBase = relBase
	t.Cleanup(func() { releaseBase = prevRel })
}

// fetch_latest_version：读 releases/latest 的 302 Location 取 tag。
// 旧实现读 raw version.py，但 Go 仓库没有该文件（1.9.x 发在 mcp-socket-server-go）。
// 覆盖：正常 302、404、以及 200 但无 Location（反代吞重定向）三种。
func TestFetchLatestVersion(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/latest" {
			http.Redirect(w, r, srvURL+"/releases/tag/v1.9.3", http.StatusFound)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	srvURL = srv.URL
	prev := latestReleaseBaseFor
	latestReleaseBaseFor = func(repo string) string { return srv.URL }
	t.Cleanup(func() { latestReleaseBaseFor = prev })

	if v := FetchLatestVersion(""); v != "1.9.3" {
		t.Fatalf("want 1.9.3 got %q", v)
	}

	// 失败 → ""
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv2.Close()
	latestReleaseBaseFor = func(repo string) string { return srv2.URL }
	if v := FetchLatestVersion(""); v != "" {
		t.Fatalf("fail want empty, got %q", v)
	}
}

// ensure_release_binary：下载 + sha 校验 → 原子落盘；已存在复用
func TestEnsureReleaseBinary(t *testing.T) {
	content := []byte("RELEASE-BINARY")
	sum := fmt.Sprintf("%x", sha256.Sum256(content))
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.8.4/socket_server", func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	})
	mux.HandleFunc("/v1.8.4/socket_server.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sum+"  socket_server\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setFetchBase(t, srv.URL, srv.URL)

	dir := t.TempDir()
	path, gotSHA, err := EnsureReleaseBinary("1.8.4", dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if gotSHA != sum {
		t.Fatalf("sha: %s", gotSHA)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "RELEASE-BINARY" {
		t.Fatalf("content: %q", data)
	}
	// 二次：复用（服务器已关也应成功）
	srv.Close()
	path2, _, err := EnsureReleaseBinary("1.8.4", dir, "")
	if err != nil || path2 != path {
		t.Fatalf("reuse: %v %q", err, path2)
	}
	// sha 不符 → 错误 + 无半截文件
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/v1.8.5/socket_server", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("TAMPERED"))
	})
	mux2.HandleFunc("/v1.8.5/socket_server.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("0", 64))
	})
	srv3 := httptest.NewServer(mux2)
	defer srv3.Close()
	setFetchBase(t, srv3.URL, srv3.URL)
	if _, _, err := EnsureReleaseBinary("1.8.5", dir, ""); err == nil {
		t.Fatal("sha mismatch must fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "socket_server", "v1.8.5", "socket_server")); !os.IsNotExist(err) {
		t.Fatal("no half-written file")
	}
	// 版本非法
	if _, _, err := EnsureReleaseBinary("../evil", dir, ""); err == nil {
		t.Fatal("bad version")
	}
}

// 下载失败不留空壳目录（v1.9.9）：真机中央缓存 8 个版本目录里 4 个是下载失败
// 留下的空目录，`ls` 核对缓存完整性会被目录存在误导（二轮验收发现）。失败即清，
// 缓存目录内存在 = 完整包。os.Remove 只删空目录，非空（理论不可能）不动。
func TestEnsureReleaseBinaryCleanupEmptyDirOnFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.9.3/socket_server", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setFetchBase(t, srv.URL, srv.URL)

	dir := t.TempDir()
	_, _, err := EnsureReleaseBinary("1.9.3", dir, "")
	if err == nil {
		t.Fatal("404 must fail")
	}
	// 错误必须带下载源上下文：五轮验收发现 mirror 未生效时错误里看不出来
	// （请求地址无前缀这一铁证四轮没人看）。显式打 mirror=/proxy= 当场分清
	// 「没拼前缀」还是「拼了打不通」。
	for _, want := range []string{"mirror=", "proxy="} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("错误信息应含 %q（实际: %v）", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "socket_server", "v1.9.3")); !os.IsNotExist(err) {
		t.Fatal("失败后不应留下空壳目录")
	}
}

// push_binary：POST multipart 到 :9001，path=staging；IPv6 加方括号
func TestPushBinary(t *testing.T) {
	var gotPath, gotFile string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(1 << 20)
		gotPath = r.FormValue("path")
		f, _, _ := r.FormFile("file")
		if f != nil {
			buf := make([]byte, 64)
			n, _ := f.Read(buf)
			gotFile = string(buf[:n])
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()
	// 提取 host:port
	addr := strings.Trim(strings.TrimPrefix(srv.URL, "http://"), "/")
	idx := strings.LastIndex(addr, ":")
	base := addr[:idx]
	port := addr[idx+1:]
	portN := 0
	fmt.Sscanf(port, "%d", &portN)

	bin := filepath.Join(t.TempDir(), "b")
	os.WriteFile(bin, []byte("PB"), 0o755)
	ok, _, err := PushBinary(base, bin, "1.9.1", portN, 10)
	if !ok || err != nil {
		t.Fatalf("push: %v %v", ok, err)
	}
	if !strings.Contains(gotPath, "/opt/socket/versions/1.9.1/.staging/socket_server") {
		t.Fatalf("staging path: %q", gotPath)
	}
	if gotFile != "PB" {
		t.Fatalf("file content: %q", gotFile)
	}
	// 服务器返回非 ok → 失败
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":false,"error":"bad"}`)
	}))
	defer srv2.Close()
	addr2 := strings.TrimPrefix(srv2.URL, "http://")
	idx2 := strings.LastIndex(addr2, ":")
	port2 := 0
	fmt.Sscanf(addr2[idx2+1:], "%d", &port2)
	if ok, _, err := PushBinary(addr2[:idx2], bin, "1.9.1", port2, 10); ok || err == nil {
		t.Fatal("non-ok response must fail")
	}
}
