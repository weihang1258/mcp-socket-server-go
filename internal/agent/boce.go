package agent

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dt131 拨测（boce.py 移植，设计 §3）。
// 预检链：chromium 缺失 → ensure_chromium（npmmirror 自动下载，失败回错误 JSON）→
// 自检 dump-dom → stderr 含 cannot open shared object file 才装依赖（yum/apt）→
// 无包管理器仅 log 继续 → 装后复测失败回错误 JSON。
// boce() 运行时异常冒泡断连（回退后契约）。封堵=纯 HTTP；重定向/弹窗=chromedp（boce_browser）。

// 可注入路径（测试改到临时目录；生产值对齐 boce.py:80-81）。
// defaultChromiumPath 由 chromeInstallDir 派生，避免两处路径漂移。
var (
	chromeInstallDir = "/opt/socket/chrome-linux"
	npmmirrorBase    = "https://registry.npmmirror.com/-/binary/chromium-browser-snapshots/Linux_x64"
)

func defaultChromiumPath() string { return chromeInstallDir + "/chrome" }

// ensureChromiumFn 可注入（测试/后续实现替换）；签名（有效路径）→ 是否可用。
var ensureChromiumFn func(chromiumPath string) bool

func setEnsureChromium(f func(string) bool) { ensureChromiumFn = f }

// PrefetchChromium 非阻塞后台预取 chromium（**默认关闭**，见 config.Agent.ChromiumPrefetch）。
// 目的是消掉「首次 boce_run 现场下载 223s，把那条连接的超时（timeout+10）撑爆」。
// 默认关：内网靶机连不上 npmmirror，无条件预取会让每次重启白跑一次 536MB 下载，
// 而 Python 是「用到才触发」（handlers.py:263）。能上外网的部署才开。
//
// 与现场下载共用 chromiumDownloadMu，故两者并发时不会重复下载：后到者阻塞等锁，
// 等锁期间前者已装好 → double-check 直接返回。
// 不返回错误：下载失败只记日志，运行时仍走原来那条「现场下载 + 手动提示」路径。
// prefetchDownload 预取下载实现（注入点，测试用）。
var prefetchDownload = ensureChromiumDownload

func PrefetchChromium() {
	// SOCKETSTACK_TEST_CHROMIUM 只服务测试/验收。它非空时 ensureChromiumDownload
	// 解压/chmod 的目标仍是默认安装路径，于是「钩子指向不存在的文件」会变成
	// 「绕过钩子往默认路径下一份」——验收机残留该变量时就多下一次。直接不预取。
	if os.Getenv("SOCKETSTACK_TEST_CHROMIUM") != "" {
		return
	}
	path := defaultChromiumPath()
	if chromiumUsable(path) {
		return // 已装好，零开销
	}
	go func() {
		// 长驻 goroutine 强制 recover（§11/§12#2 约定，capture.go 同款）：
		// goroutine 里 panic 会带走整个 agent 进程。
		defer func() {
			if r := recover(); r != nil {
				log.Printf("后台预取 chromium panic: %v", r)
			}
		}()
		log.Printf("后台预取 chromium: %s", path)
		if !prefetchDownload(path) {
			log.Printf("后台预取失败，首次 boce 时仍会尝试现场下载")
		}
	}()
}

// effectiveChromium 测试环境变量优先，其次 payload，再默认。
// payloadPath 显式空串按 Python data.get 语义保留（isfile("") 假 → 下载失败），不走默认。
func effectiveChromium(payloadPath string) string {
	if p := os.Getenv("SOCKETSTACK_TEST_CHROMIUM"); p != "" {
		return p
	}
	if payloadPath != "" {
		return payloadPath
	}
	return defaultChromiumPath()
}

// doBoce dt131 入口。
func doBoce(payload []byte) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}
	// 严格键（Python boce(**data) 未知键/缺 url → TypeError → 冒泡断连）
	allowed := map[string]bool{"url": true, "count": true, "interval": true,
		"thread_count": true, "timeout": true, "mode": true, "chromium_path": true}
	for k := range raw {
		if !allowed[k] {
			return nil, fmt.Errorf("boce() got unexpected keyword argument %q", k)
		}
	}
	if _, ok := raw["url"]; !ok {
		return nil, errors.New("boce() missing required argument: url")
	}
	var req struct {
		Url         string `json:"url"`
		Count       int    `json:"count"`
		Interval    int    `json:"interval"`
		ThreadCount int    `json:"thread_count"`
		Timeout     int    `json:"timeout"`
		Mode        string `json:"mode"`
		Chromium    string `json:"chromium_path"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	// 缺省键对齐 Python boce() 签名（boce.py:460）：count=1 / timeout=3 / mode="封堵"。
	// 显式 count<=0 → range(count) 空 → total=0（Python run_multiple 空结果集）。
	count := 1
	if _, ok := raw["count"]; ok {
		count = req.Count
		if count < 0 {
			count = 0
		}
	}
	timeout := 3
	if _, ok := raw["timeout"]; ok {
		timeout = req.Timeout
	}
	mode := "封堵"
	if _, ok := raw["mode"]; ok {
		mode = req.Mode
	}

	// chromium 预检链（全模式执行，对齐 handlers.py 顺序）；chromium_path 键缺失才走默认，
	// 显式空串保留（Python data.get 原样返回 "" → isfile 假 → 下载失败）
	chromium := defaultChromiumPath()
	if _, ok := raw["chromium_path"]; !ok {
		chromium = effectiveChromium("")
	} else if string(raw["chromium_path"]) != "null" {
		chromium = req.Chromium
	}
	if v, ok := raw["chromium_path"]; ok && strings.TrimSpace(string(v)) == "null" {
		return nil, errors.New("os.path.isfile(None) TypeError") // 冒泡断连
	}
	if !chromiumUsable(chromium) {
		log.Printf("chromium 不存在: %s，尝试自动下载...", chromium)
		fn := ensureChromiumFn
		if fn == nil {
			fn = ensureChromiumDownload
		}
		if !fn(chromium) {
			return dt131Frame(map[string]string{"error": "chromium 自动下载失败，请查看日志中的手动下载方法"}), nil
		}
	}
	if code, _, stderr := execCmdArgs(chromium, "--headless", "--no-sandbox", "--disable-gpu", "--dump-dom", "about:blank"); code != 0 &&
		strings.Contains(stderr, "cannot open shared object file") {
		log.Printf("chromium 缺少依赖库，尝试自动安装...\nstderr: %s", stderr)
		var install string
		if _, err := exec.LookPath("yum"); err == nil {
			install = "yum install -y libX11 libXcomposite libXcursor libXdamage libXext libXi libXtst cups-libs libXScrnSaver libXrandr GConf2 atk gtk3 pango at-spi2-atk libwayland-client libwayland-cursor libwayland-egl alsa-lib nss nspr"
		} else if _, err := exec.LookPath("apt-get"); err == nil {
			install = "apt-get install -y libx11-6 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxi6 libxtst6 libcups2 libxss1 libxrandr2 libgconf-2-4 libatk1.0-0 libgtk-3-0 libpango-1.0-0 libpangocairo-1.0-0 libwayland-client0 libwayland-cursor0 libasound2 libnss3 libnspr4 libgbm1 libxshmfence1"
		} else {
			log.Printf("未找到 yum 或 apt-get，无法自动安装依赖") // 仅 log 继续（quirk）
		}
		if install != "" {
			code2, _, _ := execCmd(install)
			_ = code2
			if code3, _, stderr3 := execCmdArgs(chromium, "--headless", "--no-sandbox", "--disable-gpu", "--dump-dom", "about:blank"); code3 != 0 {
				// 真机反馈：原来只回 ".so: cannot open shared object file"，
				// 装包还得人工反查包名。这里补三样：缺哪些 .so、要装哪些包、
				// 以及可直接复制的命令。
				return dt131Frame(map[string]string{"error": fmt.Sprintf(
					"chromium依赖库安装失败: %s；缺失库: %s；可手动执行: sudo %s",
					truncBytes(stderr3, 200), strings.Join(missingSharedLibs(stderr3), ", "), install)}), nil
			}
			log.Printf("chromium 依赖库安装成功，继续执行拨测")
		}
	}

	// 拨测分派（Python boce.py:466-476）：缺省/封堵 → RequestChecker（requests）；
	// 重定向/弹窗/未知 → PyppeteerChecker。thread_count 校验仅封堵分支生效
	//（max_workers ValueError 只在 RequestChecker.run_multiple 抛）
	switch mode {
	case "封堵": // 显式 mode:"" 不是缺省——Python ""≠"封堵" → pyppeteer 未知模式恒败
		tc := 1
		if _, ok := raw["thread_count"]; ok {
			tc = req.ThreadCount
			if tc <= 0 {
				return nil, errors.New("max_workers must be greater than 0") // ValueError 冒泡
			}
		}
		out := boceBlock(req.Url, count, req.Interval, tc, timeout)
		return dt131Frame(out), nil
	default:
		// Python boce.py:475-476：浏览器模式显式空 chromium_path → ValueError 冒泡断连
		//（预检阶段 isfile("") 为假会先走下载失败分支；下载成功或预检被绕过时才会到这里）
		if chromium == "" {
			return nil, errors.New("必须指定 Chromium 可执行文件路径参数 chromium_path")
		}
		return boceBrowser(payload, mode, count, timeout) // chromedp 实现（boce_browser.go）
	}
}

// dt131Frame [4B i][JSON body]。
func dt131Frame(v any) []byte {
	body, _ := json.Marshal(v)
	out := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out
}

func truncBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func chromiumUsable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}

// ensureChromiumDownload npmmirror 自动下载（boce.py:142 ensure_chromium）：
// 查最新 revision → 下载 zip → 解压到 dirname(install) → chmod 755 → 复查。
// 失败一律 false（上层回错误 JSON 帧），不 panic。
func ensureChromiumDownload(chromiumPath string) bool {
	if chromiumUsable(chromiumPath) {
		return true
	}
	// Python `with _browser_lock:` 阻塞串行化 + 等锁后 double-check（并发拨测不重复下载，
	// 且后到者能拿到前者下载好的结果）
	chromiumDownloadMu.Lock()
	defer chromiumDownloadMu.Unlock()
	if chromiumUsable(chromiumPath) { // double-check
		return true
	}
	revision, err := fetchLatestChromiumRevision()
	if err != nil {
		log.Printf("查询 chromium 最新版本失败: %v", err)
		printManualDownloadHint("latest")
		return false
	}
	log.Printf("npmmirror 最新 chromium revision: %s", revision)

	staging, err := os.MkdirTemp("", "chrome_dl_")
	if err != nil {
		log.Printf("chromium 自动下载失败: %v", err)
		printManualDownloadHint(revision)
		return false
	}
	defer os.RemoveAll(staging) // Python shutil.rmtree(staging, ignore_errors=True)

	destZip := filepath.Join(staging, "chrome-linux.zip")
	installRoot := filepath.Dir(chromeInstallDir)
	if err := downloadChromiumZip(revision, destZip); err != nil {
		log.Printf("chromium 自动下载失败: %v", err)
		printManualDownloadHint(revision)
		return false
	}
	log.Printf("chromium 下载完成，开始解压到 %s...", installRoot)
	if err := unzipInto(destZip, installRoot); err != nil {
		log.Printf("chromium 自动下载失败: %v", err)
		printManualDownloadHint(revision)
		return false
	}
	if err := os.Chmod(chromiumPath, 0o755); err != nil {
		log.Printf("chromium 自动下载失败: %v", err)
		printManualDownloadHint(revision)
		return false
	}
	if chromiumUsable(chromiumPath) {
		log.Printf("chromium 安装成功: %s", chromiumPath)
		return true
	}
	log.Printf("解压后未找到可执行的 chrome: %s", chromiumPath)
	printManualDownloadHint(revision)
	return false
}

var chromiumDownloadMu sync.Mutex

// readSocketConfigProxy /opt/socket/config 的 proxy= 键（boce.py:84 _read_config_proxy）。
// 与 readAutoupgrade 同源文件（agent 侧实时读 /opt/socket/config）。
func readSocketConfigProxy() string {
	b, err := os.ReadFile(filepath.Join(upgradeRoot, "config"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "proxy=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "proxy="))
		}
	}
	return ""
}

// chromiumTransport 超时语义对齐 requests(timeout=N)：
//   - N 是**逐次 socket 操作**的超时——连接、握手、等首字节、以及**每次 read 等待**，
//     都不是整个传输的总时限（36MB 目录列表真机 5.8s，慢链路 36s，总时限必败）。
//   - Go 的 ResponseHeaderTimeout 只管到响应头；头一到位，body 就再无 deadline，
//     故 dial 时给 conn 包一层 readDeadlineConn，每次 Read 前重设 deadline。
//
// 基线用 DefaultTransport 克隆：config 无 proxy= 时仍走 HTTP_PROXY/HTTPS_PROXY。
func chromiumTransport(timeout int) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	d := time.Duration(timeout) * time.Second
	dialer := &net.Dialer{Timeout: min(d, 20*time.Second)}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &readDeadlineConn{Conn: c, timeout: d}, nil
	}
	tr.TLSHandshakeTimeout = d
	tr.ResponseHeaderTimeout = d
	tr.IdleConnTimeout = 90 * time.Second
	tr.Proxy = chromiumProxyFunc()
	return tr
}

// readDeadlineConn 每次 Read 前重设 deadline（requests 的 read timeout 语义：
// 计时从"开始等下一批字节"算起，数据持续到达就持续续期）。
// 注意：仅适用于**一次性请求**的 Transport（当前 fetcher 每次新建）。若将来把 Transport
// 提成包级复用，HTTP/2 的空闲读循环会被这里的 deadline 判定为连接故障而拆连接。
type readDeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *readDeadlineConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

// chromiumProxyFunc config 的 proxy= 显式则用（无 scheme 自动补 http://，对齐
// requests adapters.py prepend_scheme_if_needed）；否则取环境变量并遵守 no_proxy
// （requests Session.merge_environment_settings → get_environ_proxies → should_bypass_proxies：
// 命中 no_proxy 即返回 {} = 直连）。大小写冲突时**小写优先**（utils: get(k) or get(k.upper())）。
func chromiumProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if p := readSocketConfigProxy(); p != "" {
			u := parseProxyURL(p)
			if u == nil {
				// 配了代理但不可解析：直接失败（走 ensureChromiumDownload 的日志+手动下载
				// 提示路径），不静默改用 env——否则"代理配错了"会表现为"下载很慢/超时"。
				return nil, fmt.Errorf("proxy= 配置不可用: %q", p)
			}
			return u, nil // 显式配置不参与 no_proxy 绕过（与 requests proxies= 一致）
		}
		if noProxyBypass(req.URL) {
			return nil, nil
		}
		lower, upper := "http_proxy", "HTTP_PROXY"
		if req.URL.Scheme == "https" {
			lower, upper = "https_proxy", "HTTPS_PROXY"
		}
		for _, k := range []string{lower, upper} {
			if v := os.Getenv(k); v != "" {
				if u := parseProxyURL(v); u != nil {
					return u, nil
				}
			}
		}
		return nil, nil
	}
}

// noProxyBypass requests should_bypass_proxies 的等价实现：
//   - no_proxy（小写优先）、逗号分隔、去空格
//   - "*" 全部绕过
//   - 目标是 IPv4 字面量时支持 CIDR（requests 的 is_valid_cidr/address_in_network），
//     否则按裸 IP 精确匹配
//   - 其余按 host 或 host:port 后缀匹配（见后缀边界说明）
func noProxyBypass(u *url.URL) bool {
	raw := os.Getenv("no_proxy")
	if raw == "" {
		raw = os.Getenv("NO_PROXY")
	}
	if raw == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return true // requests：hostname 为 None（如 file://）直接绕过
	}
	if strings.TrimSpace(raw) == "*" {
		return true
	}
	hostWithPort := host
	if p := u.Port(); p != "" {
		hostWithPort += ":" + p
	}
	ip := net.ParseIP(host)
	isV4 := ip != nil && ip.To4() != nil

	for _, entry := range strings.Split(strings.ReplaceAll(raw, " ", ""), ",") {
		entry = strings.ToLower(entry)
		if entry == "" {
			continue
		}
		if isV4 {
			if _, cidr, err := net.ParseCIDR(entry); err == nil {
				if cidr.Contains(ip) {
					return true
				}
				continue
			}
			if entry == host { // 裸 IP 精确匹配（requests 同一分支）
				return true
			}
			continue // IPv4 目标不再走后缀匹配
		}
		// 后缀匹配：Python 用裸 endswith（无标签边界，故 no_proxy=mirror.com 会命中
		// notmirror.com）；Go 侧保留标签边界语义（§12#30），更接近 curl/wget。
		// **不得剥离 entry 的端口**：requests 是拿 entry 原样与 host / host:port 两个
		// 形态比 endswith，端口不匹配就不命中（否则 no_proxy=h.com:8080 会误绕 h.com:9090）。
		e := strings.TrimPrefix(entry, ".")
		if host == e || strings.HasSuffix(host, "."+e) ||
			hostWithPort == entry || strings.HasSuffix(hostWithPort, "."+entry) {
			return true
		}
	}
	return false
}

// parseProxyURL 无 scheme 时补 http://（"10.0.0.1:7897" → http://10.0.0.1:7897）。
// 已有 scheme 时**不再二次补 scheme**：否则 "http://" 会被补成 "http://http://"，
// url.Parse 给出 host="http:" 这种坏代理（比回落 env 更糟，流量指向解析不出的 host）。
func parseProxyURL(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && usableProxyURL(u) {
			return u
		}
		return nil
	}
	if u, err := url.Parse("http://" + raw); err == nil && usableProxyURL(u) {
		return u
	}
	return nil
}

// usableProxyURL host 必须解析出主机名；端口须为 1-65535 的数字；"h.com:" 这类尾冒号
// 与未加方括号的 IPv6（"::1:8080" 会被整个当成 host）都视为坏值——requests 对前者
// 抛 InvalidProxyURL、对越界端口抛 Port out of range，这里对齐成"不可用"。
func usableProxyURL(u *url.URL) bool {
	if u.Hostname() == "" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if strings.Count(u.Host, ":") > 1 && !strings.HasPrefix(u.Host, "[") {
		return false // 裸 IPv6 缺方括号，host/port 无从拆
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

// fetcher 带 proxy 语义的 HTTP client（总时限不限，超时由 transport 逐操作控制）。
func fetcher(timeout int) *http.Client {
	return &http.Client{Transport: chromiumTransport(timeout)}
}

// fetchLatestChromiumRevision 拉目录列表，取 name 为纯数字中最大者（max(key=int)）。
func fetchLatestChromiumRevision() (string, error) {
	resp, err := fetcher(20).Get(npmmirrorBase + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("npmmirror 返回 %d", resp.StatusCode)
	}
	var entries []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return "", err
	}
	latest, latestN := "", -1
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name, "/")
		if name == "" || strings.Trim(name, "0123456789") != "" {
			continue
		}
		n, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		if n > latestN {
			latest, latestN = name, n
		}
	}
	if latestN < 0 {
		return "", errors.New("npmmirror 未返回任何 chromium revision")
	}
	return latest, nil
}

// downloadChromiumZip 流式下载到 dest（Python iter_content 64KB 块）。
func downloadChromiumZip(revision, dest string) error {
	u := fmt.Sprintf("%s/%s/chrome-linux.zip", npmmirrorBase, revision)
	log.Printf("下载 chromium r%s: %s", revision, u)
	resp, err := fetcher(300).Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("下载 chrome-linux.zip 返回 %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// unzipInto 解压 zip 到 destRoot，路径按 Python zipfile.extractall 规则消毒：
// 去首斜杠、丢弃任何 ".." 与 "." 段（Go archive/zip 无内置防护，防 zip-slip）。
func unzipInto(zipPath, destRoot string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		parts := strings.Split(strings.TrimPrefix(filepath.ToSlash(f.Name), "/"), "/")
		clean := make([]string, 0, len(parts))
		for _, p := range parts {
			if p == "" || p == "." || p == ".." {
				continue // Python 语义：.. 段直接丢弃，绝不向上逃逸
			}
			clean = append(clean, p)
		}
		if len(clean) == 0 {
			continue
		}
		target := filepath.Join(append([]string{destRoot}, clean...)...)
		if f.FileInfo().IsDir() {
			if err := mkdirAllPythonMode(target); err != nil {
				return err
			}
			continue
		}
		if err := mkdirAllPythonMode(filepath.Dir(target)); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		// CPython extractall 用 open(wb)（0666&~umask）且忽略 external_attr——保持一致
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o666)
		if err != nil {
			rc.Close()
			return err
		}
		_, cerr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if cerr != nil {
			return cerr
		}
	}
	return nil
}

// mkdirAllPythonMode 目录创建对齐 CPython extractall 的 os.makedirs（默认 0o777 & ~umask）。
func mkdirAllPythonMode(dir string) error { return os.MkdirAll(dir, 0o777) }

// printManualDownloadHint 下载失败的手动步骤（boce.py:127-139 文案逐字保留）。
func printManualDownloadHint(revision string) {
	hint := fmt.Sprintf(`
========== chromium 自动下载失败，请手动下载 ==========
1. 在能联网的机器下载:
   wget %s/%s/chrome-linux.zip
   (或浏览器打开上述 URL)
2. 解压到靶机 %s (最终路径需为 %s/chrome):
   mkdir -p %s && cd %s
   unzip chrome-linux.zip   # 解压出 chrome-linux/ 目录
3. 赋予执行权限:
   chmod +x %s/chrome
4. 验证:
   %s/chrome --headless --no-sandbox --dump-dom about:blank
======================================================`,
		npmmirrorBase, revision, chromeInstallDir, chromeInstallDir,
		filepath.Dir(chromeInstallDir), filepath.Dir(chromeInstallDir),
		chromeInstallDir, chromeInstallDir)
	log.Printf("%s", hint)
	fmt.Println(hint)
}

// boceBlock 封堵模式（RequestChecker.run_multiple 移植）：
// 并发 thread_count、提交间隔 interval、UA Chrome/120、禁跟随、200=成功；
// time = 各请求耗时之和（round 4）；success_ratio "%.2f%%"。
type boceResult struct {
	Total        int     `json:"total"`
	Success      int     `json:"success"`
	Fail         int     `json:"fail"`
	Time         float64 `json:"time"` // round 4（Python round(x,4)）
	SuccessRatio string  `json:"success_ratio"`
}

func boceBlock(url string, count, interval, threadCount, timeout int) boceResult {
	if threadCount < 1 {
		threadCount = 1
	}
	client := &http.Client{
		// Python 每请求新建 Session+close：禁 keep-alive 保持建连成本语义
		Transport: &http.Transport{DisableKeepAlives: true},
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // allow_redirects=False
		},
	}
	sem := make(chan struct{}, threadCount)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var total, success, fail int
	var timeConsumed float64
	for i := 0; i < count; i++ {
		if i > 0 && interval > 0 {
			time.Sleep(time.Duration(interval) * time.Second)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			req, err := http.NewRequest("GET", url, nil)
			var code int
			if err == nil {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
				resp, err := client.Do(req)
				if err == nil {
					code = resp.StatusCode
					resp.Body.Close()
				}
			}
			mu.Lock()
			total++
			timeConsumed += time.Since(start).Seconds()
			if code == 200 {
				success++
			} else {
				fail++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	ratio := 0.0
	if total > 0 {
		ratio = float64(success) / float64(total) * 100
	}
	return boceResult{
		Total: total, Success: success, Fail: fail,
		Time:         round4(timeConsumed),
		SuccessRatio: fmt.Sprintf("%.2f%%", ratio),
	}
}

func round4(f float64) float64 { return float64(int(f*10000+0.5*sign(f))) / 10000 }

// ChromiumPath 当前生效的 chromium 可执行文件路径（含 SOCKETSTACK_TEST_CHROMIUM
// 钩子与默认路径）。供 `socketstack status` 做缺库预检——拨测依赖缺失只会在
// 首次 boce_run 炸，且只报 .so 名。
func ChromiumPath() string { return effectiveChromium("") }

// missingSharedLibs 从 chromium 的 "error while loading shared libraries: X: cannot
// open shared object file" 报错里提取全部 .so 名（真机一次只报第一个，但多行输出
// 可能带多个）。
func missingSharedLibs(stderr string) []string {
	const marker = "cannot open shared object file"
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		if !strings.Contains(line, marker) {
			continue
		}
		// 形如 "... shared libraries: libX11-xcb.so.1: cannot open shared object file"
		idx := strings.Index(line, marker)
		head := strings.TrimSpace(line[:idx])
		head = strings.TrimSuffix(head, ":")
		if i := strings.LastIndex(head, ": "); i >= 0 {
			head = strings.TrimSpace(head[i+1:])
		}
		if head != "" {
			out = append(out, head)
		}
	}
	return out
}
