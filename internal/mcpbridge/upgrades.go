// 中央升级编排（upgrades.py 移植，设计 §4 工具15 + upgrades 段）：
// 查版 = releases/latest 的 302 Location（非 API、非 raw version.py，见 §12#37）；
// 退避 1h→2h→4h 日志策略；ensure_release_binary 幂等复用 + sha 校验原子落盘
// （远端 .sha256 可选，§12#38）；push_binary 经 :9001；每日兜底先睡 24h 绝不自动升级。
package mcpbridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 基址可注入（测试 httptest；生产按仓库/镜像拼）。
//
// **不能写死 Python 仓库**：Go 版二进制发在 mcp-socket-server-go，Python 仓库
// （socket_server）最新只到 1.8.3。原实现逐字复刻 Python 版的 REPO 常量，导致
// upgrade_run(version="1.9.3") 必然 404。
var (
	defaultUpgradeRepo = "weihang1258/mcp-socket-server-go"

	// upgradeRepo/upgradeMirror 运行时配置（Init 时从 config 写入）。
	upgradeRepo   = defaultUpgradeRepo
	upgradeMirror = ""

	// githubBase GitHub 站点基址（测试替换为 httptest URL）。
	githubBase = "https://github.com"
	// releaseBase 测试注入点：非空时覆盖按仓库拼出来的值。
	releaseBase = ""

	// latestReleaseBaseFor 查最新版用的基址（测试注入）。
	latestReleaseBaseFor = func(repo string) string { return githubBase + "/" + repo }

	// pushHTTPPort 推包端口（Python 硬编码 9001；var 仅为单测接缝——本机 :9001 可能被
	// 真实 agent 占用，不可达分支需确定性端口；生产路径恒默认值）
	pushHTTPPort = 9001
)

// releaseBaseFor 某仓库的 release 下载基址。
func releaseBaseFor(repo string) string {
	if releaseBase != "" {
		return releaseBase
	}
	return githubBase + "/" + repo + "/releases/download"
}

// legacyProxyPath 旧键配置（/opt/socket/config，Python 版格式）。
// var 仅为单测注入。
var legacyProxyPath = "/opt/socket/config"

// legacyProxyFrom 从旧键配置读 proxy=（Python 版 mcp 只读这一处）。
//
// 为什么要有：试点机只配了 /opt/socket/config 的 proxy=，没有
// /etc/socketstack/config.yaml，于是 mcp.proxy 为空 → 走 ProxyFromEnvironment
// → unit 里没有 Environment= → 裸连 GitHub（实测 570 B/s，等于不可用）。
func legacyProxyFrom(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "proxy=") {
			return strings.TrimSpace(line[len("proxy="):])
		}
	}
	return ""
}

// ResolveProxy 生效代理：显式配置优先，空则回退旧键 proxy=。
//
// 注意：`proxy: ""` 与「不写这个键」解析后无法区分，都是空串，所以没配代理时
// 一定会回退旧键。想**强制直连**（旧键里配了代理但你不想用）用
// `proxy: "none"`（或 config 的 mcp.no_proxy: true）显式关闭。
func ResolveProxy(explicit string) string {
	p := strings.TrimSpace(explicit)
	if p == "none" || p == "NONE" || p == "-" {
		return "" // 显式直连
	}
	if p != "" {
		return p
	}
	return legacyProxyFrom(legacyProxyPath)
}

// ConfigureUpgradeSource 写入运行时下载源配置（Init 时调用）。
func ConfigureUpgradeSource(repo, mirror string) {
	if repo != "" {
		upgradeRepo = repo
	}
	upgradeMirror = strings.TrimSpace(mirror)
}

// withMirror 给 GitHub URL 套镜像前缀（gh-proxy 等用法：MIRROR + 完整 URL）。
// 只读 upgradeMirror，不改它——之前就地补斜杠会在并发调用间叠加出 "//"。
func withMirror(u string) string {
	m := upgradeMirror
	if m == "" {
		return u
	}
	if !strings.HasSuffix(m, "/") {
		m += "/"
	}
	return m + u
}

var versionRe = regexp.MustCompile(`^\d+(\.\d+){1,3}$`)

var (
	failStreakMu sync.Mutex
	failStreak   int
	announced    string
	announceMu   sync.Mutex
)

// VersionOK 版本号格式校验（防路径穿越）。
func VersionOK(v string) bool { return versionRe.MatchString(v) }

// httpClient proxy 非空时显式使用（对齐 httpx proxy=；空=环境变量/直连）。
//
// 代理串解析失败时**必须告警**：`url.Parse` 对 "10.12.186.204:7897"（缺
// scheme）会成功但 Host 为空，对某些畸形串直接报错。静默忽略的结果是
// "配了代理却裸连"，排查时完全看不出来。
func httpClient(timeout int, proxy string) *http.Client {
	t := &http.Transport{}
	if proxy != "" {
		if u, err := url.Parse(proxy); err != nil || u.Host == "" {
			log.Printf("代理配置无法解析，本次按直连处理: %q（应为 http://host:port）", proxy)
			t.Proxy = nil
		} else {
			t.Proxy = http.ProxyURL(u)
		}
	} else {
		t.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{Timeout: time.Duration(timeout) * time.Second, Transport: t}
}

// FetchLatestVersion 查最新版本；失败 ""（退避日志策略：首败 warning、后续 debug、恢复 info）。
//
// 走 releases/latest 的 302 Location 取 tag，而不是 raw version.py：
// Go 仓库没有 socket_server/version.py，raw 方式在新仓库上恒失败。302 方案
// 两仓库通用，Python 版 install.sh 的 latest_tag() 也是这么做的。
func FetchLatestVersion(proxy string) string {
	failStreakMu.Lock()
	streak := failStreak
	failStreakMu.Unlock()

	v, err := fetchLatestViaRedirect(proxy)
	if err != "" {
		logFetchFail(fmt.Errorf("%s", err), streak+1)
		return ""
	}
	failStreakMu.Lock()
	if failStreak > 0 {
		log.Printf("版本查询已恢复（此前连续失败 %d 次）", failStreak)
	}
	failStreak = 0
	failStreakMu.Unlock()
	return v
}

var latestTagRe = regexp.MustCompile(`/releases/tag/v?([0-9][0-9.]*)$`)

// fetchLatestViaRedirect 读 /releases/{latest} 的 302 Location 尾段取版本号。
// 只读 302，不跟随（跟随重定向后拿不到 Location）。返回 (版本, 错误说明)。
func fetchLatestViaRedirect(proxy string) (string, string) {
	base := latestReleaseBaseFor(upgradeRepo)
	url := withMirror(base + "/releases/latest")
	c := httpClient(10, proxy)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(url)
	if err != nil {
		return "", err.Error()
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
		if m := latestTagRe.FindStringSubmatch(loc); m != nil {
			return m[1], ""
		}
		return "", fmt.Sprintf("无法从 Location 解析版本: %s", loc)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Sprintf("HTTP %d（%s）", resp.StatusCode, url)
	}
	// 200：不跟随重定向的服务端直接返回页面，Location 里没有 tag。
	return "", fmt.Sprintf("未返回重定向（%s）", url)
}

func logFetchFail(err error, streak int) {
	steps := []int{3600, 7200, 14400}
	idx := streak - 1
	if idx > len(steps)-1 {
		idx = len(steps) - 1
	}
	if idx < 0 {
		idx = 0
	}
	if streak == 1 {
		log.Printf("版本查询失败: %v；后续按退避重试，期间不再刷失败日志", err)
	} // streak≥2 静默（Python debug 级不刷屏）
	failStreakMu.Lock()
	failStreak = streak
	failStreakMu.Unlock()
}

// sha256File 文件哈希。
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// EnsureReleaseBinary 确保 <download_dir>/socket_server/v<版本>/socket_server 存在。
// 已存在复用（幂等）；否则下载 + .sha256 校验 → tmp 原子落盘。失败返回原因。
func EnsureReleaseBinary(version, downloadDir, proxy string) (string, string, error) {
	version = strings.TrimLeft(strings.TrimSpace(version), "v")
	if !VersionOK(version) {
		return "", "", fmt.Errorf("版本号非法: %q", version)
	}
	vdir := filepath.Join(downloadDir, "socket_server", "v"+version)
	binary := filepath.Join(vdir, "socket_server")
	if fi, err := os.Stat(binary); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
		sha, err := sha256File(binary)
		return binary, sha, err
	}
	base := withMirror(fmt.Sprintf("%s/v%s", releaseBaseFor(upgradeRepo), version))
	os.MkdirAll(vdir, 0o755)
	binURL := base + "/socket_server"
	content, status, err := httpGetStatus(binURL, proxy, 300)
	if err != nil {
		return "", "", fmt.Errorf("下载 v%s 失败: %v（请求地址 %s）", version, err, binURL)
	}
	if status != 200 {
		return "", "", fmt.Errorf("下载 v%s 失败: HTTP %d（请求地址 %s）", version, status, binURL)
	}
	actual := sha256.Sum256(content)
	actualHex := hex.EncodeToString(actual[:])
	// 远端 sha 资产**可选**：Go 仓库的 release 只有 socket_server 一个资产。
	// 有就校验（保留对 Python 仓库的防篡改能力），没有就用本地计算结果——
	// dt20 推送本来就需要这个哈希，靶机侧仍会按它校验，链路完整性不受影响。
	shaURL := base + "/socket_server.sha256"
	expectedRaw, status2, err2 := httpGetStatus(shaURL, proxy, 30)
	switch {
	case err2 != nil || status2 != 200:
		log.Printf("v%s 无远端 sha256 资产（%s，HTTP %d），改用本地计算 %s", version, shaURL, status2, actualHex[:16])
	case len(strings.Fields(string(expectedRaw))) == 0:
		log.Printf("v%s 远端 sha256 为空，改用本地计算", version)
	default:
		expected := strings.Fields(string(expectedRaw))[0]
		if actualHex != expected {
			return "", "", fmt.Errorf("下载校验失败: 期望 %s, 实际 %s（%s）", expected, actualHex, binURL)
		}
	}
	tmp := binary + ".tmp"
	if err := os.WriteFile(tmp, content, 0o755); err != nil {
		return "", "", err
	}
	if err := os.Rename(tmp, binary); err != nil {
		return "", "", err
	}
	log.Printf("已下载 v%s -> %s (%dB)", version, binary, len(content))
	return binary, actualHex, nil
}

// httpGet 全量 GET。
func httpGet(url, proxy string, timeout int) ([]byte, error) {
	body, status, err := httpGetStatus(url, proxy, timeout)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	return body, nil
}

// httpGetStatus 全量 GET，返回 (body, HTTP 状态码, 传输错误)。
// 状态码单独返回，供调用方在 404 时把实际 URL 一并写进错误信息。
func httpGetStatus(url, proxy string, timeout int) ([]byte, int, error) {
	resp, err := httpClient(timeout, proxy).Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// PushBinary 经 :9001 推二进制到 versions/<版本>/.staging/socket_server（IPv6 加方括号）。
func PushBinary(host, binaryPath, version string, httpPort, timeout int) (bool, string, error) {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	url := fmt.Sprintf("http://%s:%d/files", host, httpPort)
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return false, "", fmt.Errorf("推送失败: %v", err)
	}
	staging := fmt.Sprintf("/opt/socket/versions/%s/.staging/socket_server", version)
	// multipart：path 字段 + file 字段（与 http_file.py 解析同构）
	var buf strings.Builder
	boundary := "socketstackpush"
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	fmt.Fprintf(&buf, "Content-Disposition: form-data; name=\"path\"\r\n\r\n")
	fmt.Fprintf(&buf, "%s\r\n", staging)
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	fmt.Fprintf(&buf, "Content-Disposition: form-data; name=\"file\"; filename=\"socket_server\"\r\n\r\n")
	buf.Write(content)
	fmt.Fprintf(&buf, "\r\n--%s--\r\n", boundary)

	req, err := http.NewRequest("POST", url, strings.NewReader(buf.String()))
	if err != nil {
		return false, "", fmt.Errorf("推送失败（需靶机 1.7.0+ 开启 :9001）: %v", err)
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	resp, err := httpClient(timeout, "").Do(req)
	if err != nil {
		return false, "", fmt.Errorf("推送失败（需靶机 1.7.0+ 开启 :9001）: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return false, "", fmt.Errorf("推送失败: HTTP %d %s", resp.StatusCode, string(body))
	}
	// Python resp.json().get("ok") 语义（容忍任意 JSON 排版）
	var ack struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(body, &ack); err != nil || !ack.OK {
		return false, "", fmt.Errorf("推送失败: %s", string(body))
	}
	return true, staging, nil
}

var dailyOnce sync.Once

// StartDailyCheck 每日兜底（先睡 24h；有新版记 1 条 info，绝不自动升级；防重）。
func StartDailyCheck(proxy string, getBridgeVersion func() string) {
	dailyOnce.Do(func() { go dailyLoop(proxy, getBridgeVersion) })
}

func dailyLoop(proxy string, getBridgeVersion func() string) {
	{
		for {
			time.Sleep(24 * time.Hour)
			v := FetchLatestVersion(proxy)
			announceMu.Lock()
			if v != "" && v != announced {
				log.Printf("socket_server 最新版 v%s（本桥 %s；仅提示，不会自动升级，需要时调 upgrade_run）", v, getBridgeVersion())
				announced = v
			}
			announceMu.Unlock()
		}
	}
}

var _ = strconv.Itoa
