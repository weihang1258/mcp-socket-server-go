package mcpbridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Go 版二进制发在 mcp-socket-server-go 仓库，1.9.x 在 Python 仓库（socket_server）
// 里根本不存在。基址写死成 Python 仓库时 upgrade_run 必然 404——真机实测
// `upgrade_run(version="1.9.3")` → {"reason":"下载 v1.9.3 失败: HTTP 404"}。
func TestUpgradeRepoDefaultsToGoRepo(t *testing.T) {
	if !strings.Contains(defaultUpgradeRepo, "mcp-socket-server-go") {
		t.Fatalf("默认下载仓库应为 Go 版仓库，实际 %q", defaultUpgradeRepo)
	}
	for _, base := range []string{releaseBaseFor(defaultUpgradeRepo), defaultUpgradeRepo + "/releases/latest"} {
		if !strings.Contains(base, defaultUpgradeRepo) {
			t.Fatalf("基址 %q 未指向 %s", base, defaultUpgradeRepo)
		}
	}
}

// 查最新版不能靠 raw version.py：Go 仓库没有这个文件。用 releases/latest 的
// 302 Location 取 tag（Python 自己的 install.sh 也是这么干的），两仓库通用。
func TestFetchLatestVersionViaRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases/latest" {
			w.WriteHeader(404)
			return
		}
		http.Redirect(w, r, srv2URL+"/releases/tag/v1.9.3", http.StatusFound)
	}))
	defer srv.Close()
	srv2URL = srv.URL

	prev := latestReleaseBaseFor
	latestReleaseBaseFor = func(repo string) string { return srv.URL }
	defer func() { latestReleaseBaseFor = prev }()

	if v := FetchLatestVersion(""); v != "1.9.3" {
		t.Fatalf("want 1.9.3, got %q", v)
	}
}

var srv2URL string

// Go 仓库的 release 只有 socket_server 资产，没有 socket_server.sha256。
// 缺 sha 资产时必须改为本地计算哈希（dt20 推送本来就需要这个哈希），
// 不能像旧实现那样直接判失败。
func TestEnsureReleaseBinaryWithoutRemoteSHA(t *testing.T) {
	content := []byte("GO-BINARY")
	want := fmt.Sprintf("%x", sha256.Sum256(content))
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.9.3/socket_server", func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	})
	// 故意不注册 .sha256 → 404
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setFetchBase(t, srv.URL, srv.URL)

	dir := t.TempDir()
	path, gotSHA, err := EnsureReleaseBinary("1.9.3", dir, "")
	if err != nil {
		t.Fatalf("无远端 sha 时应本地计算而不是失败: %v", err)
	}
	if gotSHA != want {
		t.Fatalf("sha 应为本地计算结果 %s，实际 %s", want, gotSHA)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "GO-BINARY" {
		t.Fatalf("content: %q", data)
	}
}

// 远端 sha 资产存在且一致时仍要校验（保留对 Python 仓库的兼容）。
func TestEnsureReleaseBinaryUsesRemoteSHAWhenPresent(t *testing.T) {
	content := []byte("OK")
	sum := fmt.Sprintf("%x", sha256.Sum256(content))
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.9.4/socket_server", func(w http.ResponseWriter, r *http.Request) { w.Write(content) })
	mux.HandleFunc("/v1.9.4/socket_server.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  socket_server\n", sum)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setFetchBase(t, srv.URL, srv.URL)

	if _, got, err := EnsureReleaseBinary("1.9.4", t.TempDir(), ""); err != nil || got != sum {
		t.Fatalf("远端 sha 一致时应通过: shav=%s err=%v", got, err)
	}

	// 远端 sha 不一致 → 仍必须拒绝（防篡改能力不能因为放宽而丢掉）
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/v1.9.5/socket_server", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("TAMPERED")) })
	mux2.HandleFunc("/v1.9.5/socket_server.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("0", 64))
	})
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	setFetchBase(t, srv2.URL, srv2.URL)
	if _, _, err := EnsureReleaseBinary("1.9.5", t.TempDir(), ""); err == nil {
		t.Fatal("远端 sha 不一致必须拒绝")
	}
}

// 404 时必须能看出请求打到了哪个仓库——真机报告里只有 "下载 v1.9.3 失败: HTTP 404"，
// 完全看不出基址是 Python 仓库。
func TestDownloadErrorIncludesURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	setFetchBase(t, srv.URL, srv.URL)

	_, _, err := EnsureReleaseBinary("1.9.3", t.TempDir(), "")
	if err == nil {
		t.Fatal("404 必须失败")
	}
	if !strings.Contains(err.Error(), srv.URL) || !strings.Contains(err.Error(), "1.9.3") {
		t.Fatalf("错误信息须含实际请求 URL 和版本，实际: %v", err)
	}
}

// 代理：mcp.proxy 为空时回退读 /opt/socket/config 的 proxy=（Python 版语义）。
// 试点机 yaml 不存在 → 以前裸连；旧键里配了代理却用不上。
func TestParseLegacyProxy(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte("version=1.2\nport=9000\nproxy=http://10.12.186.204:7897\nautoupgrade=on\n"), 0o644)
	if got := legacyProxyFrom(cfg); got != "http://10.12.186.204:7897" {
		t.Fatalf("want proxy, got %q", got)
	}
	// 无 proxy 键 → 空
	os.WriteFile(cfg, []byte("autoupgrade=on\n"), 0o644)
	if got := legacyProxyFrom(cfg); got != "" {
		t.Fatalf("无 proxy 键应为空，got %q", got)
	}
	// 文件不存在 → 空
	if got := legacyProxyFrom(filepath.Join(dir, "nope")); got != "" {
		t.Fatalf("文件不存在应为空，got %q", got)
	}
	// 空值 → 空
	os.WriteFile(cfg, []byte("proxy=\n"), 0o644)
	if got := legacyProxyFrom(cfg); got != "" {
		t.Fatalf("空值应为空，got %q", got)
	}
}

var _ = hex.EncodeToString

// withMirror 不能修改包级 upgradeMirror：并发下载时两次调用会各补一个斜杠，
// 拼出 "https://gh-proxy.com//https://..."。
func TestWithMirrorDoesNotMutate(t *testing.T) {
	prevRepo, prevMirror := upgradeRepo, upgradeMirror
	defer func() { upgradeRepo, upgradeMirror = prevRepo, prevMirror }()

	ConfigureUpgradeSource("", "https://gh-proxy.com") // 无尾斜杠
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); withMirror("https://github.com/x") }()
	}
	wg.Wait()
	if upgradeMirror != "https://gh-proxy.com" {
		t.Fatalf("withMirror 不得修改配置，实际 %q", upgradeMirror)
	}
	if got := withMirror("U"); got != "https://gh-proxy.com/U" {
		t.Fatalf("拼接结果不对: %q", got)
	}
}

// 显式"直连"必须可表达：旧键里配了 proxy= 时，若用户在网络更好的机器上
// 不想走代理，仅写 proxy: "" 无效（YAML 空串与未配置无法区分），会被回退到
// 旧键的代理。因此支持 proxy: "none" 强制直连。
func TestResolveProxyExplicitDirect(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte("proxy=http://10.12.186.204:7897\n"), 0o644)
	prev := legacyProxyPath
	legacyProxyPath = cfg
	defer func() { legacyProxyPath = prev }()

	if got := ResolveProxy(""); got != "http://10.12.186.204:7897" {
		t.Fatalf("空配置应回退旧键，实际 %q", got)
	}
	for _, v := range []string{"none", "NONE", "-"} {
		if got := ResolveProxy(v); got != "" {
			t.Fatalf("%q 应表示强制直连，实际 %q", v, got)
		}
	}
	if got := ResolveProxy("http://p:1"); got != "http://p:1" {
		t.Fatalf("显式代理应生效，实际 %q", got)
	}
}

// 代理串写错（缺 scheme）时 url.Parse 直接报错，旧实现静默把 Proxy 留成 nil
// → 请求变成直连，日志里一个字都没有，排查时完全看不出来。修完后必须留告警。
func TestHTTPClientBadProxyWarns(t *testing.T) {
	var buf bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevOut)

	c := httpClient(5, "10.12.186.204:7897") // 缺 scheme
	if tr, ok := c.Transport.(*http.Transport); !ok || tr.Proxy != nil {
		t.Fatal("坏代理不得设成有效 Proxy")
	}
	if !strings.Contains(buf.String(), "代理配置无法解析") {
		t.Fatalf("坏代理必须留告警日志，实际日志: %q", buf.String())
	}

	// 正常代理照旧生效
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	c2 := httpClient(5, "http://10.12.186.204:7897")
	u2, _ := c2.Transport.(*http.Transport).Proxy(req)
	if u2 == nil || u2.Host != "10.12.186.204:7897" {
		t.Fatalf("正常代理应生效，实际 %v", u2)
	}
}
