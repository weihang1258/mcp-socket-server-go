package agent

// chromium 自动下载（boce.py:142-187 ensure_chromium 移植）：
// npmmirror 查最新 revision → 下载 chrome-linux.zip 到临时目录 → 解压到
// dirname(CHROME_INSTALL_DIR)（Python zipfile.extractall 语义，含 zip-slip 消毒）→
// chmod 755 → 复查。失败一律 false → 上层回 [4B i][{"error":"chromium 自动下载失败..."}]。

import (
	"archive/zip"
	"context"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestEnsureChromiumDownloadE2E(t *testing.T) {
	root := t.TempDir()
	restore := overrideChromiumPaths(t, filepath.Join(root, "opt", "socket", "chrome-linux"))
	defer restore()

	var requested []string
	srv := newNPMMirrorServer(t, func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		// 目录列表混入非数字项 → 须取数值最大者 123（max(key=int)）
		w.Write([]byte(`[{"name":"120/"},{"name":"abc/"},{"name":"123/"}]`))
	}, func(w http.ResponseWriter, revision string) {
		writeZip(t, w, map[string]string{"chrome-linux/chrome": "#!/bin/sh\nexit 0\n"})
	})
	defer srv.Close()
	npmmirrorBase = "http://" + srv.Addr

	target := chromeInstallDir + "/chrome"
	if !ensureChromiumDownload(target) {
		t.Fatal("下载链路应成功")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("chrome 未落盘: %v", err)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o755 {
		t.Fatalf("chmod 755 未生效: %v", fi.Mode().Perm())
	}
	if !chromiumUsable(target) {
		t.Fatal("落盘后 chromiumUsable 须为 true")
	}
}

// Python zipfile.extractall 消毒语义：绝对路径去首斜杠、任何 ".." 段直接丢弃。
func TestEnsureChromiumZipSlipBlocked(t *testing.T) {
	root := t.TempDir()
	installRoot := filepath.Join(root, "opt", "socket", "chrome-linux")
	restore := overrideChromiumPaths(t, installRoot)
	defer restore()

	srv := newNPMMirrorServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name":"1/"}]`))
	}, func(w http.ResponseWriter, revision string) {
		writeZip(t, w, map[string]string{
			"../../escaped.txt":     "x",
			"a/../../mid.txt":       "m", // 中间 .. 段：Python 过滤后为 a/mid.txt
			"/abs/absolute.txt":     "y",
			"chrome-linux/chrome":   "#!/bin/sh\n",
			"chrome-linux/sub/a.js": "z",
		})
	})
	defer srv.Close()
	npmmirrorBase = "http://" + srv.Addr

	if !ensureChromiumDownload(installRoot + "/chrome") {
		t.Fatal("含恶意路径的 zip 仍应解压成功（Python 丢弃 .. 段）")
	}
	parent := filepath.Dir(installRoot)
	if _, err := os.Stat(filepath.Join(parent, "escaped.txt")); err != nil {
		t.Fatalf("../../ 须被丢弃后落在父目录: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "escaped.txt")); err == nil {
		t.Fatal("zip-slip 逃逸到父目录之外")
	}
	if _, err := os.Stat(filepath.Join(parent, "abs", "absolute.txt")); err != nil {
		t.Fatalf("绝对路径须去首斜杠后落在父目录下: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "a", "mid.txt")); err != nil {
		t.Fatalf("中间 .. 段须被丢弃（a/mid.txt）: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installRoot, "sub", "a.js")); err != nil {
		t.Fatalf("嵌套目录未解压: %v", err)
	}
	// CPython extractall 不复刻 external_attr：普通文件恒 0666&~umask（0o644），目录 0o755
	if fi, err := os.Stat(filepath.Join(installRoot, "sub", "a.js")); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("文件权限须 0o644（忽略 zip external_attr）: %v %v", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(filepath.Join(installRoot, "sub")); err != nil || !fi.IsDir() {
		t.Fatalf("子目录缺失: %v", err)
	}
}

func TestEnsureChromiumRevisionFetchFailure(t *testing.T) {
	root := t.TempDir()
	defer overrideChromiumPaths(t, filepath.Join(root, "opt", "socket", "chrome-linux"))()

	srv := newNPMMirrorServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	}, nil)
	defer srv.Close()
	npmmirrorBase = "http://" + srv.Addr

	if ensureChromiumDownload(chromeInstallDir + "/chrome") {
		t.Fatal("查询失败须返回 false")
	}
}

func TestEnsureChromiumNoNumericRevision(t *testing.T) {
	root := t.TempDir()
	defer overrideChromiumPaths(t, filepath.Join(root, "opt", "socket", "chrome-linux"))()

	srv := newNPMMirrorServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name":"abc/"}]`))
	}, nil)
	defer srv.Close()
	npmmirrorBase = "http://" + srv.Addr

	if ensureChromiumDownload(chromeInstallDir + "/chrome") {
		t.Fatal("无数字 revision 须返回 false")
	}
}

// proxy= 从 /opt/socket/config 读取（Python _read_config_proxy；生产中即 upgradeRoot/config）。
func TestReadSocketConfigProxy(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	prev := upgradeRoot
	defer func() { upgradeRoot = prev }()
	upgradeRoot = dir

	os.WriteFile(p, []byte("http_port=9001\nproxy=http://127.0.0.1:7897\n"), 0o644)
	if got := readSocketConfigProxy(); got != "http://127.0.0.1:7897" {
		t.Fatalf("proxy 解析错误: %q", got)
	}
	os.WriteFile(p, []byte("proxy=\n"), 0o644)
	if got := readSocketConfigProxy(); got != "" {
		t.Fatalf("空 proxy 须返回空: %q", got)
	}
	os.Remove(p)
	if got := readSocketConfigProxy(); got != "" {
		t.Fatalf("配置缺失须返回空: %q", got)
	}
}

// 下载中途断流（连接被掐）→ io.Copy 报错 → false，且不留可用 chrome。
func TestEnsureChromiumTruncatedDownload(t *testing.T) {
	root := t.TempDir()
	defer overrideChromiumPaths(t, filepath.Join(root, "opt", "socket", "chrome-linux"))()

	srv := newNPMMirrorServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name":"7/"}]`))
	}, func(w http.ResponseWriter, revision string) {
		// 声明 1MB，只写 1KB 就掐断连接 → 客户端读到 EOF/错误
		w.Header().Set("Content-Length", "1048576")
		w.Write(make([]byte, 1024))
		hj, _ := w.(http.Hijacker)
		if hj != nil {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
			}
		}
	})
	defer srv.Close()
	npmmirrorBase = "http://" + srv.Addr

	if ensureChromiumDownload(chromeInstallDir + "/chrome") {
		t.Fatal("断流下载须返回 false")
	}
	if chromiumUsable(chromeInstallDir + "/chrome") {
		t.Fatal("断流不得留下可用 chrome")
	}
}

// 下载后解压出来是目录不是可执行文件 → chmod 成功但 isfile/X_OK 复查失败 → false。
func TestEnsureChromiumZipWithoutExecutable(t *testing.T) {
	root := t.TempDir()
	defer overrideChromiumPaths(t, filepath.Join(root, "opt", "socket", "chrome-linux"))()

	srv := newNPMMirrorServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name":"1/"}]`))
	}, func(w http.ResponseWriter, revision string) {
		writeZip(t, w, map[string]string{"chrome-linux/README": "no binary here"})
	})
	defer srv.Close()
	npmmirrorBase = "http://" + srv.Addr

	if ensureChromiumDownload(chromeInstallDir + "/chrome") {
		t.Fatal("zip 内无可执行文件须返回 false")
	}
}

// 解压不沿用 zip 内的 external_attr 权限（CPython extractall 用 open(wb)，恒 0666&~umask）。
// 真机实证：python3.9 extractall 后 exec.sh(0755) 与 ro.txt(0400) 均落为 0o644。
func TestEnsureChromiumIgnoresZipFileModes(t *testing.T) {
	root := t.TempDir()
	installRoot := filepath.Join(root, "opt", "socket", "chrome-linux")
	defer overrideChromiumPaths(t, installRoot)()

	srv := newNPMMirrorServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name":"1/"}]`))
	}, func(w http.ResponseWriter, revision string) {
		writeUnixZip(t, w, map[string]struct {
			Body string
			Mode fs.FileMode
		}{
			"chrome-linux/chrome":   {"#!/bin/sh\n", 0o755},
			"chrome-linux/libro.so": {"ro", 0o400},
			"chrome-linux/tool":     {"tool", 0o700},
		})
	})
	defer srv.Close()
	npmmirrorBase = "http://" + srv.Addr

	if !ensureChromiumDownload(installRoot + "/chrome") {
		t.Fatal("下载应成功")
	}
	for name, want := range map[string]fs.FileMode{
		"chrome":   0o755,                // 主目标被显式 chmod 755
		"libro.so": 0o644, "tool": 0o644, // 其余按 CPython 语义 0666&~umask
	} {
		fi, err := os.Stat(filepath.Join(installRoot, name))
		if err != nil {
			t.Fatalf("%s 缺失: %v", name, err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s 权限 %v，want %v", name, fi.Mode().Perm(), want)
		}
	}
}

// ---- 测试辅助 ----

func overrideChromiumPaths(t *testing.T, installDir string) func() {
	t.Helper()
	prevDir, prevBase, prevRoot := chromeInstallDir, npmmirrorBase, upgradeRoot
	chromeInstallDir = installDir
	npmmirrorBase = "http://127.0.0.1:1" // 未覆盖必然失败，防误联网
	upgradeRoot = t.TempDir()
	return func() { chromeInstallDir, npmmirrorBase, upgradeRoot = prevDir, prevBase, prevRoot }
}

// newNPMMirrorServer 假 npmmirror："/" 至列表，"/<rev>/chrome-linux.zip" 回 zip。
func newNPMMirrorServer(t *testing.T, list http.HandlerFunc, zipFor func(http.ResponseWriter, string)) *http.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			list(w, r)
			return
		}
		if zipFor == nil {
			http.NotFound(w, r)
			return
		}
		rev := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/chrome-linux.zip")
		zipFor(w, rev)
	})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Addr: ln.Addr().String(), Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return srv
}

func writeZip(t *testing.T, w http.ResponseWriter, files map[string]string) {
	t.Helper()
	zw := zip.NewWriter(w)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(f, files[n])
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

// writeUnixZip 生成 Unix 创建者标记的 zip（external_attr 带真实权限），
// 用于验证解压不沿用 external_attr（CPython extractall 行为）。
func writeUnixZip(t *testing.T, w http.ResponseWriter, entries map[string]struct {
	Body string
	Mode fs.FileMode
}) {
	t.Helper()
	zw := zip.NewWriter(w)
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h := &zip.FileHeader{Name: n, Method: zip.Deflate, CreatorVersion: 3 << 8} // 3 = Unix
		h.SetMode(entries[n].Mode)
		fw, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(fw, entries[n].Body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}
