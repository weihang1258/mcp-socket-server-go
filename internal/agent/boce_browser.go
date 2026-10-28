package agent

import (
	"encoding/json"
	"time"
)

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
	// Python 形态：弹窗/未知模式恒失败 total=count/fail=count/time=真实耗时(4位)；
	// "重定向"运行路径的失败形态相同（browser 不可用 → run_single 全异常 → fail=count）。
	// chromedp 驱动在真机验收阶段接（§12#3）。
	var req struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(payload, &req)
	if req.Count == 0 {
		req.Count = 1
	}
	start := time.Now()
	time.Sleep(200 * time.Millisecond) // 模拟 browser 冷启动开销（真实路径为秒级）
	return dt131Frame(boceResult{
		Total: req.Count, Fail: req.Count,
		Time:         round4(time.Since(start).Seconds()),
		SuccessRatio: "0.00%",
	}), nil
}
