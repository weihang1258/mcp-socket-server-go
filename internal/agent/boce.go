package agent

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// 可注入路径（测试改到临时目录；生产值对齐 boce.py:83-84）。
// defaultChromiumPath 由 chromeInstallDir 派生，避免两处路径漂移。
var (
	chromeInstallDir = "/opt/socket/chrome-linux"
	npmmirrorBase    = "https://registry.npmmirror.com/-/binary/chromium-browser-snapshots/Linux_x64"
)

func defaultChromiumPath() string { return chromeInstallDir + "/chrome" }

// ensureChromiumFn 可注入（测试/后续实现替换）；签名（有效路径）→ 是否可用。
var ensureChromiumFn func(chromiumPath string) bool

func setEnsureChromium(f func(string) bool) { ensureChromiumFn = f }

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
				return dt131Frame(map[string]string{"error": fmt.Sprintf("chromium依赖库安装失败: %s", truncBytes(stderr3, 200))}), nil
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

// readSocketConfigProxy /opt/socket/config 的 proxy= 键（boce.py:88 _read_config_proxy）。
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

// fetcher 带 proxy= 的 HTTP client（空 proxy → 走环境变量/直连）。
func fetcher(timeout int) *http.Client {
	c := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	if p := readSocketConfigProxy(); p != "" {
		if u, err := url.Parse(p); err == nil {
			c.Transport = &http.Transport{Proxy: http.ProxyURL(u)}
		}
	}
	return c
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
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode().Perm())
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
