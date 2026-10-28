// 中央升级编排（upgrades.py 移植，设计 §4 工具15 + upgrades 段）：
// 查版 = raw version.py（非 API）；退避 1h→2h→4h 日志策略；
// ensure_release_binary 幂等复用 + sha 校验原子落盘；push_binary 经 :9001；
// 每日兜底先睡 24h 绝不自动升级。
package mcpbridge

import (
	"crypto/sha256"
	"encoding/hex"
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

// 基址可注入（测试 httptest；生产 GitHub）。
var (
	rawVersionBase = "https://raw.githubusercontent.com/weihang1258/socket_server/main/socket_server/version.py"
	releaseBase    = "https://github.com/weihang1258/socket_server/releases/download"
)

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
func httpClient(timeout int, proxy string) *http.Client {
	t := &http.Transport{}
	if proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			t.Proxy = http.ProxyURL(u)
		}
	} else {
		t.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{Timeout: time.Duration(timeout) * time.Second, Transport: t}
}

// FetchLatestVersion 查最新版本；失败 ""（退避日志策略：首败 warning、后续 debug、恢复 info）。
func FetchLatestVersion(proxy string) string {
	failStreakMu.Lock()
	streak := failStreak
	failStreakMu.Unlock()
	resp, err := httpClient(10, proxy).Get(rawVersionBase)
	if err != nil {
		logFetchFail(err, streak+1)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logFetchFail(fmt.Errorf("HTTP %d", resp.StatusCode), streak+1)
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	m := regexp.MustCompile(`VERSION\s*=\s*"([^"]+)"`).FindSubmatch(body)
	if m == nil {
		log.Printf("raw version.py 未解析到 VERSION")
		return ""
	}
	failStreakMu.Lock()
	if failStreak > 0 {
		log.Printf("版本查询已恢复（此前连续失败 %d 次）", failStreak)
	}
	failStreak = 0
	failStreakMu.Unlock()
	return string(m[1])
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
	base := fmt.Sprintf("%s/v%s", releaseBase, version)
	os.MkdirAll(vdir, 0o755)
	content, err := httpGet(base+"/socket_server", proxy, 300)
	if err != nil {
		return "", "", fmt.Errorf("下载 v%s 失败: %v", version, err)
	}
	expectedRaw, err := httpGet(base+"/socket_server.sha256", proxy, 30)
	if err != nil {
		return "", "", fmt.Errorf("下载 v%s 失败: %v", version, err)
	}
	expected := strings.Fields(string(expectedRaw))
	if len(expected) == 0 {
		return "", "", fmt.Errorf("下载 v%s 失败: 空 sha256 文件", version)
	}
	actual := sha256.Sum256(content)
	actualHex := hex.EncodeToString(actual[:])
	if actualHex != expected[0] {
		return "", "", fmt.Errorf("下载校验失败: 期望 %s, 实际 %s", expected[0], actualHex)
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
	resp, err := httpClient(timeout, proxy).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
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
	if !strings.Contains(string(body), `"ok":true`) {
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
