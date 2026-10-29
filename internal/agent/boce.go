package agent

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// dt131 拨测（boce.py 移植，设计 §3）。
// 预检链：chromium 缺失 → ensure_chromium（npmmirror 自动下载，失败回错误 JSON）→
// 自检 dump-dom → stderr 含 cannot open shared object file 才装依赖（yum/apt）→
// 无包管理器仅 log 继续 → 装后复测失败回错误 JSON。
// boce() 运行时异常冒泡断连（回退后契约）。封堵=纯 HTTP；重定向/弹窗=chromedp（boce_browser）。

const defaultChromiumPath = "/opt/socket/chrome-linux/chrome"

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
	return defaultChromiumPath
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
	chromium := defaultChromiumPath
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
	case "封堵", "":
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

// ensureChromiumDownload npmmirror 自动下载（网络实现；失败返回 false，日志给手动步骤）。
func ensureChromiumDownload(chromiumPath string) bool {
	// ponytail: 网络下载链（npmmirror revision 查询 + zip + zip-slip 防护）由
	// deploy 验收阶段按目标网络环境补；当前返回失败走错误 JSON 分支（协议行为已对）。
	log.Printf("chromium 自动下载未启用（Go 版待接 npmmirror 链），请手动放置 %s", chromiumPath)
	return false
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
