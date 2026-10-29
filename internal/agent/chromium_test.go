package agent

// chromium 自动下载（boce.py:142-187 ensure_chromium 移植）：
// npmmirror 查最新 revision → 下载 chrome-linux.zip 到临时目录 → 解压到
// dirname(CHROME_INSTALL_DIR)（Python zipfile.extractall 语义，含 zip-slip 消毒）→
// chmod 755 → 复查。失败一律 false → 上层回 [4B i][{"error":"chromium 自动下载失败..."}]。

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
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
		if revision != "123" {
			t.Errorf("须下载数值最大的 revision 123，实际 %q", revision)
		}
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
	if len(requested) != 1 {
		t.Fatalf("目录列表须只查一次（锁内 double-check），实际 %d 次: %v", len(requested), requested)
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
	// CPython extractall 不复刻 external_attr：普通文件恒 0666&~umask
	if fi, err := os.Stat(filepath.Join(installRoot, "sub", "a.js")); err != nil || fi.Mode().Perm() != wantFileMode() {
		t.Fatalf("文件权限须 %v（忽略 zip external_attr）: %v %v", wantFileMode(), fi.Mode().Perm(), err)
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
		"chrome":   0o755,                                  // 主目标被显式 chmod 755（chmod 不受 umask 影响）
		"libro.so": wantFileMode(), "tool": wantFileMode(), // 其余按 CPython 语义 0666&~umask
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

// 慢链路语义（对齐 requests(timeout=N) 的逐操作超时）：整体传输远超 timeout 仍须成功。
// 目录列表真机 36MB/5.8s——若用 Client.Timeout 总时限则慢机必败。
func TestEnsureChromiumSlowBodyNoTotalDeadline(t *testing.T) {
	root := t.TempDir()
	defer overrideChromiumPaths(t, filepath.Join(root, "opt", "socket", "chrome-linux"))()

	srv := newNPMMirrorServer(t, func(w http.ResponseWriter, r *http.Request) {
		// 分 5 段写、每段间隔 500ms：总耗时 ~2.5s，明显超过下面传入的 1s。
		// per-op 超时（connect/握手/首字节）不受影响；总时限（Client.Timeout）必失败。
		f := w.(http.Flusher)
		w.Write([]byte(`[{"name":"1/"},`))
		f.Flush()
		for i := 0; i < 3; i++ {
			time.Sleep(500 * time.Millisecond)
			w.Write([]byte(`{"name":"x"},`))
			f.Flush()
		}
		time.Sleep(500 * time.Millisecond)
		w.Write([]byte(`{"name":"2/"}]`))
	}, func(w http.ResponseWriter, revision string) {
		if revision != "2" {
			t.Errorf("revision 应为 2（列表最大数字）: %q", revision)
		}
		writeZip(t, w, map[string]string{"chrome-linux/chrome": "#!/bin/sh\n"})
	})
	defer srv.Close()
	npmmirrorBase = "http://" + srv.Addr

	if !fetcherHTTP(1) {
		t.Fatal("慢速响应超过 timeout 不应整体失败（仅逐操作超时）")
	}
	if !ensureChromiumDownload(chromeInstallDir + "/chrome") {
		t.Fatal("慢链路下载应成功")
	}
}

// 直取目录列表校验 transport 超时语义（1s per-op 上限，1.2s 总长须通过）。
func fetcherHTTP(timeoutSeconds int) bool {
	resp, err := fetcher(timeoutSeconds).Get(npmmirrorBase + "/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	return err == nil
}

// config 无 proxy= 时须继承环境变量代理（Python trust_env）。
func TestChromiumTransportUsesEnvProxyWhenNoConfig(t *testing.T) {
	dir := t.TempDir()
	prev := upgradeRoot
	defer func() { upgradeRoot = prev }()
	upgradeRoot = dir // 无 config 文件

	t.Setenv("HTTP_PROXY", "http://127.0.0.1:7897")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:7897")
	tr := chromiumTransport(10)
	req, _ := http.NewRequest("GET", "http://example.invalid/", nil)
	if tr.Proxy == nil {
		t.Fatal("无 config 时 Proxy 不得为 nil（须继承环境变量）")
	}
	u, err := tr.Proxy(req)
	if err != nil || u == nil || u.Port() != "7897" {
		t.Fatalf("环境变量代理未生效: u=%v err=%v", u, err)
	}
	// config 里的 proxy= 优先于环境变量
	os.WriteFile(filepath.Join(dir, "config"), []byte("proxy=http://127.0.0.1:9999\n"), 0o644)
	u2, err := chromiumTransport(10).Proxy(req)
	if err != nil || u2 == nil || u2.Port() != "9999" {
		t.Fatalf("config proxy 须优先: u=%v err=%v", u2, err)
	}
}

// body 中途停摆必须有 read 超时（requests(timeout=N) 的 N 就是 read timeout）：
// 服务器发完响应头 + 半截 body 后停住 → 客户端须在 ~N 秒内失败，不得永久挂住
// （挂住会一直持有 chromiumDownloadMu，之后该 agent 上所有 boce 都排死）。
// body 中途停摆必须有 read 超时（requests(timeout=N) 的 N 就是 read timeout）：
// 服务器发完响应头 + 半截 body 后停住 → 客户端须在 ~N 秒内失败，不得永久挂住
// （挂住会一直持有 chromiumDownloadMu，之后该 agent 上所有 boce 都排死）。
func TestFetcherBodyStallTimesOut(t *testing.T) {
	prevRoot := upgradeRoot
	defer func() { upgradeRoot = prevRoot }()
	upgradeRoot = t.TempDir() // 隔离本机 /opt/socket/config 的 proxy=

	stall := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		f := w.(http.Flusher)
		w.Write(make([]byte, 100))
		f.Flush()
		<-stall // 停摆：剩下的字节永远不来（测试结束即释放，避免 Close 卡等 handler）
	}))
	defer srv.Close()
	defer close(stall)

	type outcome struct {
		headersOK bool
		err       error
	}
	done := make(chan outcome, 1)
	start := time.Now()
	go func() {
		resp, err := fetcher(1).Get(srv.URL)
		if err != nil {
			done <- outcome{false, err}
			return
		}
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		done <- outcome{true, err} // 走到这里说明响应头已到位，失败只能来自 body 读
	}()
	select {
	case o := <-done:
		// 必须先拿到响应头——否则本测测的是 header 超时，不是 body 读超时，
		// 被测语义就漂移了（ResponseHeaderTimeout 调短也能让弱断言通过）。
		if !o.headersOK {
			t.Fatalf("响应头阶段就失败了，未覆盖 body 停摆场景: %v", o.err)
		}
		if o.err == nil {
			t.Fatal("停摆的 body 须报错")
		}
		var ne net.Error
		if !errors.As(o.err, &ne) || !ne.Timeout() {
			t.Fatalf("须为 net.Error 超时，实际 %T: %v", o.err, o.err)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("read 超时过晚（%v），timeout=1 应在 ~1s 内失败", el)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("body 停摆时请求永久挂起——缺 read deadline")
	}
}

// requests 语义细节（复核实测对齐）：
//   - config proxy= 无 scheme 自动补 http://（adapters.py prepend_scheme_if_needed）
//   - 大小写同时设置时**小写优先**（utils: os.environ.get(k) or get(k.upper())）
//   - 只设大写也能用；只设 https 的不影响 http 请求
func TestChromiumProxySemantics(t *testing.T) {
	dir := t.TempDir()
	prev := upgradeRoot
	defer func() { upgradeRoot = prev }()
	upgradeRoot = dir

	reqHTTP, _ := http.NewRequest("GET", "http://example.invalid/", nil)
	reqHTTPS, _ := http.NewRequest("GET", "https://example.invalid/", nil)

	t.Run("config 无 scheme 自动补 http://", func(t *testing.T) {
		os.WriteFile(filepath.Join(dir, "config"), []byte("proxy=10.0.0.1:7897\n"), 0o644)
		u, err := chromiumProxyFunc()(reqHTTP)
		if err != nil || u == nil || u.Scheme != "http" || u.Host != "10.0.0.1:7897" {
			t.Fatalf("无 scheme 须补 http://: u=%v err=%v", u, err)
		}
		os.Remove(filepath.Join(dir, "config"))
	})
	t.Run("小写优先于大写", func(t *testing.T) {
		t.Setenv("http_proxy", "http://lower:1")
		t.Setenv("HTTP_PROXY", "http://upper:2")
		u, _ := chromiumProxyFunc()(reqHTTP)
		if u == nil || u.Host != "lower:1" {
			t.Fatalf("小写须优先: u=%v", u)
		}
	})
	t.Run("只设小写", func(t *testing.T) {
		t.Setenv("http_proxy", "http://lower:1")
		os.Unsetenv("HTTP_PROXY")
		u, _ := chromiumProxyFunc()(reqHTTP)
		if u == nil || u.Host != "lower:1" {
			t.Fatalf("小写单独生效: u=%v", u)
		}
	})
	t.Run("HTTPS_PROXY 不影响 http 请求", func(t *testing.T) {
		os.Unsetenv("http_proxy")
		os.Unsetenv("HTTP_PROXY")
		t.Setenv("HTTPS_PROXY", "http://sec:3")
		if u, _ := chromiumProxyFunc()(reqHTTP); u != nil {
			t.Fatalf("http 请求不得用 HTTPS_PROXY: %v", u)
		}
		if u, _ := chromiumProxyFunc()(reqHTTPS); u == nil || u.Host != "sec:3" {
			t.Fatalf("https 请求须用 HTTPS_PROXY: %v", u)
		}
	})
}

// no_proxy 命中即直连（requests should_bypass_proxies 语义）
func TestChromiumProxyNoProxyBypass(t *testing.T) {
	prev := upgradeRoot
	defer func() { upgradeRoot = prev }()
	upgradeRoot = t.TempDir() // 无 config proxy=

	t.Setenv("http_proxy", "http://p:1")
	req := func(rawurl string) *http.Request {
		r, _ := http.NewRequest("GET", rawurl, nil)
		return r
	}

	t.Run("精确 host 命中", func(t *testing.T) {
		t.Setenv("no_proxy", "registry.npmmirror.com")
		if u, _ := chromiumProxyFunc()(req("http://registry.npmmirror.com/x")); u != nil {
			t.Fatalf("命中 no_proxy 须直连: %v", u)
		}
		if u, _ := chromiumProxyFunc()(req("http://other.com/x")); u == nil {
			t.Fatal("未命中须走代理")
		}
	})
	t.Run("后缀命中", func(t *testing.T) {
		t.Setenv("no_proxy", ".npmmirror.com")
		if u, _ := chromiumProxyFunc()(req("http://a.b.npmmirror.com/x")); u != nil {
			t.Fatalf("后缀须命中: %v", u)
		}
	})
	t.Run("星号全部绕过", func(t *testing.T) {
		t.Setenv("no_proxy", "*")
		if u, _ := chromiumProxyFunc()(req("http://anything.com/x")); u != nil {
			t.Fatalf("* 须全部直连: %v", u)
		}
	})
	// 带端口条目必须端口精确匹配（requests：entry 原样与 host / host:port 比 endswith）
	t.Run("带端口条目", func(t *testing.T) {
		t.Setenv("no_proxy", "h.com:8080")
		cases := []struct {
			url       string
			wantBypss bool
		}{
			{"http://h.com:8080/x", true},
			{"http://h.com/x", false},      // 无端口 ≠ 带端口条目
			{"http://h.com:9090/x", false}, // 端口不同不得绕过（曾有 bug）
		}
		for _, c := range cases {
			u, _ := chromiumProxyFunc()(req(c.url))
			if got := u == nil; got != c.wantBypss {
				t.Errorf("%s: bypass=%v want %v (proxy=%v)", c.url, got, c.wantBypss, u)
			}
		}
	})
	t.Run("不带端口的条目可匹配任意端口", func(t *testing.T) {
		t.Setenv("no_proxy", "h.com")
		if u, _ := chromiumProxyFunc()(req("http://h.com:8080/x")); u != nil {
			t.Fatalf("无端口条目须命中带端口 URL: %v", u)
		}
	})
	t.Run("大写 NO_PROXY 也生效", func(t *testing.T) {
		os.Unsetenv("no_proxy")
		t.Setenv("NO_PROXY", "registry.npmmirror.com")
		if u, _ := chromiumProxyFunc()(req("http://registry.npmmirror.com/x")); u != nil {
			t.Fatalf("NO_PROXY 须生效: %v", u)
		}
	})
	t.Run("IPv4 CIDR", func(t *testing.T) {
		t.Setenv("no_proxy", "10.0.0.0/8,192.168.1.5")
		if u, _ := chromiumProxyFunc()(req("http://10.12.34.56/x")); u != nil {
			t.Fatalf("CIDR 须命中: %v", u)
		}
		if u, _ := chromiumProxyFunc()(req("http://192.168.1.5/x")); u != nil {
			t.Fatalf("裸 IP 须精确命中: %v", u)
		}
		if u, _ := chromiumProxyFunc()(req("http://11.0.0.1/x")); u == nil {
			t.Fatal("CIDR 外须走代理")
		}
		if u, _ := chromiumProxyFunc()(req("http://192.168.1.6/x")); u == nil {
			t.Fatal("非该 IP 须走代理")
		}
	})
	t.Run("config 显式 proxy 不被 no_proxy 绕开", func(t *testing.T) {
		dir := t.TempDir()
		upgradeRoot = dir
		os.WriteFile(filepath.Join(dir, "config"), []byte("proxy=http://cfg:9\n"), 0o644)
		t.Setenv("no_proxy", "registry.npmmirror.com")
		u, _ := chromiumProxyFunc()(req("http://registry.npmmirror.com/x"))
		if u == nil || u.Host != "cfg:9" {
			t.Fatalf("显式配置须优先于 no_proxy: %v", u)
		}
	})
}

// ---- 测试辅助 ----

// wantFileMode 解压出的普通文件权限：CPython extractall 用 open(wb) → 0666 & ~umask。
// 按当前进程 umask 推算，避免在 umask 077 的机器上误报（windows 无 Umask，见下）。
func wantFileMode() fs.FileMode { return fs.FileMode(0o666 &^ currentUmask()) }

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
