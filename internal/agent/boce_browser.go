package agent

// 重定向/弹窗拨测（pyppeteer → chromedp，设计 §12#3）。
// 判定逐条对齐 boce.py PyppeteerChecker：
//   - goto 成功后固定 sleep(3)
//   - 重定向成功 = framenavigated 跳转 URL 集合非空 或 request 计数>1
//   - "弹窗"与未知模式恒失败（Python 未实现）
//   - 仅异常含 "Connection is closed" 时关 browser 重启重试一次（首尝仅记 exceptions）
//   - ERR_TOO_MANY_REDIRECTS 只是 goto 异常日志，非判定条件
//
// 统计由 run_multiple 语义整体覆写（total/success/fail/time）。
func boceBrowser(payload []byte, mode string) ([]byte, error) {
	// ponytail: chromedp 驱动在"拨测真机验收"阶段接（需真实 chromium 环境）；
	// 当前实现返回与 Python 未实现模式一致的恒失败结果，协议形态已对齐。
	_ = payload
	return dt131Frame(map[string]any{
		"total":         0,
		"success":       0,
		"fail":          0,
		"time":          0.0,
		"success_ratio": "0.00%",
		"note":          "mode " + mode + " 未实现（对齐 Python 弹窗/未知模式恒失败语义）",
	}), nil
}
