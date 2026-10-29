package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// 重定向/弹窗拨测（boce.py PyppeteerChecker → chromedp，设计 §12#3）。
// 判定逐条对齐：
//   - goto 成功后固定 sleep(3)
//   - 重定向成功 = framenavigated 跳转 URL 集合非空 或 request 计数>1
//   - "弹窗"与未知模式恒失败（Python 未实现）
//   - 仅异常含 "Connection is closed" 时关 browser 重启重试一次（首尝仅记 exceptions）
//   - ERR_TOO_MANY_REDIRECTS 只是 goto 异常日志，非判定条件
//   - 统计由 run_multiple 语义整体覆写（total=count/fail 计一次/真实耗时）

var (
	browserMu       sync.Mutex
	browserCtx      context.Context
	browserCancel   context.CancelFunc
	browserExecPath string
)

// pythonChromeArgs boce.py:201-213 的 11 个启动参数（headless 由 allocator 另加）。
var pythonChromeArgs = []string{
	"--no-sandbox",
	"--disable-gpu",
	"--disable-software-rasterizer",
	"--disable-dev-shm-usage",
	"--disable-setuid-sandbox",
	"--single-process",
	"--disable-accelerated-2d-canvas",
	"--disable-accelerated-jpeg-decoding",
	"--disable-accelerated-mjpeg-decode",
	"--disable-gpu-compositing",
	"--disable-gpu-sandbox",
}

// getBrowser 懒加载全局 browser（对齐 get_global_loop_and_browser：复用不重建）。
func getBrowser(chromiumPath string) (context.Context, error) {
	browserMu.Lock()
	defer browserMu.Unlock()
	if browserCtx != nil && browserExecPath == chromiumPath {
		return browserCtx, nil
	}
	if browserCtx != nil { // 路径变了：关旧
		browserCancel()
		browserCtx = nil
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromiumPath),
		chromedp.Flag("headless", true),
	)
	for _, a := range pythonChromeArgs {
		opts = append(opts, chromedp.Flag(strings.TrimPrefix(a, "--"), true))
	}
	allocCtx, acancel := chromedp.NewExecAllocator(context.Background(), opts...)
	newBrowserCtx, bcancel := chromedp.NewContext(allocCtx)
	// 启动即拉起（首次 goto 也会拉起，但提前失败更早暴露）；首跑 ctx 不得带超时
	if _, err := chromedp.Run[chromedp.Void](newBrowserCtx, chromedp.Steps()); err != nil {
		acancel()
		browserCancel = nil
		return nil, err
	}
	browserCtx = newBrowserCtx
	browserCancel = func() { acancel(); bcancel() }
	browserExecPath = chromiumPath
	return browserCtx, nil
}

// closeBrowser 关 browser 并置空（Python BrowserManager：close 失败也置 None）。
func closeBrowser() {
	browserMu.Lock()
	defer browserMu.Unlock()
	if browserCancel != nil {
		browserCancel()
		browserCancel = nil
	}
	browserCtx = nil
}

// boceBrowser 重定向/弹窗/未知模式。count/timeout 缺省解析已在 doBoce 完成（boce() 签名默认）。
func boceBrowser(payload []byte, mode string, count, timeout int) ([]byte, error) {
	var req struct {
		Url      string `json:"url"`
		Chromium string `json:"chromium_path"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	chromium := defaultChromiumPath
	if req.Chromium != "" {
		chromium = req.Chromium
	}

	start := time.Now()
	success := 0
	for i := 0; i < count; i++ {
		if runSingleRedirect(chromium, req.Url, timeout, mode) {
			success++
		}
	}
	fail := count - success
	ratio := 0.0
	if count > 0 {
		ratio = float64(success) / float64(count) * 100
	}
	return dt131Frame(boceResult{
		Total: count, Success: success, Fail: fail,
		Time:         round4(time.Since(start).Seconds()),
		SuccessRatio: fmt.Sprintf("%.2f%%", ratio),
	}), nil
}

// runSingleRedirect 单次拨测。Python 仅异常串含 "Connection is closed" 且非 retry 才
// 关 browser 重试一次（boce.py:380-389）；判定失败直接返回不重试。
func runSingleRedirect(chromiumPath, url string, timeout int, mode string) bool {
	ok, err := runSingleOnce(chromiumPath, url, timeout, mode)
	if err == nil {
		return ok
	}
	// chromedp 同源故障的等价错误串（websocket 断开/browser 已关）
	if !strings.Contains(err.Error(), "Connection is closed") &&
		!strings.Contains(err.Error(), "connection closed") &&
		!strings.Contains(err.Error(), "browser has been closed") {
		log.Printf("[pyppeteer拨测] run_single异常: %v", err)
		return false
	}
	log.Printf("[pyppeteer拨测] 检测到browser已关闭，尝试重启browser并重试一次")
	closeBrowser()
	if _, err := getBrowser(chromiumPath); err != nil {
		log.Printf("[pyppeteer拨测] 重启 browser 失败: %v", err)
		return false
	}
	ok, _ = runSingleOnce(chromiumPath, url, timeout, mode)
	return ok
}

// runSingleOnce 单次判定。返回 (判定结果, 运行异常)——判定失败≠异常（后者才触发重试）。
func runSingleOnce(chromiumPath, url string, timeout int, mode string) (bool, error) {
	if mode != "重定向" {
		log.Printf("[拨测] %s 模式未实现，判定为失败", mode)
		return false, nil
	}
	bctx, err := getBrowser(chromiumPath)
	if err != nil {
		log.Printf("[拨测] browser 启动失败: %v", err)
		return false, err
	}
	tabCtx, cancel := chromedp.NewContext(bctx)
	defer cancel()
	ctx, cancel2 := context.WithTimeout(tabCtx, time.Duration(timeout)*time.Second)
	defer cancel2()

	var mu sync.Mutex
	jumped := false
	requests := 0
	sawMain := false

	// 先订阅（SDK 缓冲事件，导航后消费也能看到；对齐 example_test.go:261 注释）
	navigated := chromedp.Events(ctx, page.FrameNavigated)
	requestsEv := chromedp.Events(ctx, network.RequestWillBeSent)
	done := make(chan struct{})
	done2 := make(chan struct{})
	go func() {
		defer close(done)
		for ev, err := range navigated {
			if err != nil {
				return
			}
			frameURL := ""
			if ev.Frame != nil {
				frameURL = ev.Frame.URL
			}
			mu.Lock()
			// Python handler 在 newPage 后挂载——初始 about:blank 事件天然不可见；
			// 主帧到达前的 about:blank 视为该初始事件，之后的一律计入（iframe 跳转 quirk）
			if frameURL == url {
				sawMain = true
			}
			if frameURL == "about:blank" && !sawMain {
				mu.Unlock()
				continue
			}
			if frameURL != "" && frameURL != url {
				jumped = true
			}
			mu.Unlock()
		}
	}()
	go func() {
		defer close(done2)
		for _, err := range requestsEv {
			if err != nil {
				return
			}
			mu.Lock()
			requests++
			mu.Unlock()
		}
	}()

	start := time.Now()
	// 对齐 pyppeteer waitUntil='domcontentloaded'：Navigate 默认等 load 事件；
	// 不用 WaitReady("document")（非 CSS 选择器，会挂到 ctx 超时——真机实测 30s）
	_, err = chromedp.Run[chromedp.Void](ctx, chromedp.Navigate(url))
	if err != nil {
		if strings.Contains(err.Error(), "ERR_TOO_MANY_REDIRECTS") {
			log.Printf("[拨测] 检测到循环重定向") // 仅日志，非判定条件（对齐 Python）
		} else {
			log.Printf("[拨测] goto 异常: %v", err)
		}
	} else {
		time.Sleep(3 * time.Second) // Python goto 成功后固定 sleep(3)
	}
	// 判定先于 cancel：迭代器存活期间缓冲事件持续被消费，select 竞态不丢尾事件
	//（cdproto types.go:113-125 ctx.Done 与事件就绪随机）
	mu.Lock()
	ok := jumped || requests > 1
	mu.Unlock()
	log.Printf("[拨测] 本次 run_single 共发起 %d 次 request, 耗时 %.2fs", requests, time.Since(start).Seconds())
	cancel2()
	<-done
	<-done2
	return ok, nil
}
