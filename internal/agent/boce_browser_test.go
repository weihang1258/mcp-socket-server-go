package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// 真机验收（设计 §9.4）：chromedp 驱动真实 chromium 走重定向链。
// 需要 /opt/socket/chrome-linux/chrome（或 SOCKETSTACK_TEST_CHROMIUM）。
func TestRealBoceRedirectE2E(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root（真机验收，sudo 运行）")
	}
	chromium := effectiveChromium("")
	if !chromiumUsable(chromium) {
		t.Skip("chromium 不存在: " + chromium)
	}
	// 冒烟先验证 chromium 能起（老版本可能缺依赖）
	if code, _, stderr := execChromiumSmoke(chromium); code != 0 {
		t.Skipf("chromium 冒烟失败(缺依赖库?): %s", stderr)
	}

	// 重定向链: /start → 302 /mid → 302 /final
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/mid", http.StatusFound)
	})
	mux.HandleFunc("/mid", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>final</body></html>"))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	// dt131 全链路（重定向模式）：预检(chromium 存在+dump-dom 自检)→chromedp 判定
	payload, _ := json.Marshal(map[string]any{
		"url": srv.URL + "/start", "count": 1, "timeout": 30, "mode": "重定向",
	})
	resp, err := runDT(t, 131, payload)
	if err != nil {
		t.Fatalf("runtime error must not escape (Python 冒泡语义): %v", err)
	}
	var m map[string]any
	json.Unmarshal(unwrapDT131(t, resp), &m)
	t.Logf("重定向拨测结果: %v", m)
	if m["success"] != float64(1) {
		t.Fatalf("redirect should succeed: %v", m)
	}
}

func execChromiumSmoke(path string) (int, string, string) {
	return execCmdArgs(path, "--headless", "--no-sandbox", "--disable-gpu", "--dump-dom", "about:blank")
}

// 真机：无跳转且仅 1 次 request → 重定向判定失败（Python 同语义）
func TestRealBoceNoRedirectFails(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root（真机验收，sudo 运行）")
	}
	chromium := effectiveChromium("")
	if !chromiumUsable(chromium) {
		t.Skip("chromium 不存在: " + chromium)
	}
	if code, _, stderr := execChromiumSmoke(chromium); code != 0 {
		t.Skipf("chromium 冒烟失败: %s", stderr)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>plain</body></html>"))
	}))
	defer srv.Close()

	// URL 必须带结尾斜杠：chromium 会把 http://host 规范化为 http://host/，
	// frame.url != initial_url 恒成立 → Python 同样误判为跳转成功（见下一个测试）
	payload, _ := json.Marshal(map[string]any{
		"url": srv.URL + "/", "count": 1, "timeout": 30, "mode": "重定向",
	})
	resp, err := runDT(t, 131, payload)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(unwrapDT131(t, resp), &m)
	if m["success"] != float64(0) || m["fail"] != float64(1) {
		t.Fatalf("no-redirect must fail: %v", m)
	}
}

// 真机：URL 规范化即"跳转"——Python `frame.url != initial_url` 的原样复刻。
// 不带斜杠的 URL 被 chromium 规范化后与 initial 不等，无重定向也判成功。
func TestRealBoceURLNormalizationCountsAsJump(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root（真机验收，sudo 运行）")
	}
	chromium := effectiveChromium("")
	if !chromiumUsable(chromium) {
		t.Skip("chromium 不存在")
	}
	if code, _, stderr := execChromiumSmoke(chromium); code != 0 {
		t.Skipf("chromium 冒烟失败: %s", stderr)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>plain</body></html>"))
	}))
	defer srv.Close()

	payload, _ := json.Marshal(map[string]any{
		"url": srv.URL, "count": 1, "timeout": 30, "mode": "重定向",
	})
	resp, err := runDT(t, 131, payload)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(unwrapDT131(t, resp), &m)
	if m["success"] != float64(1) {
		t.Fatalf("bare-host URL 规范化后必须按 Python 语义判成功: %v", m)
	}
}

// 弹窗/未知模式恒失败（Python 未实现）
func TestRealBoceUnimplementedModeFails(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root")
	}
	chromium := effectiveChromium("")
	if !chromiumUsable(chromium) {
		t.Skip("chromium 不存在")
	}
	if code, _, _ := execChromiumSmoke(chromium); code != 0 {
		t.Skip("chromium 冒烟失败")
	}
	payload, _ := json.Marshal(map[string]any{
		"url": "http://127.0.0.1:1", "count": 2, "timeout": 10, "mode": "弹窗",
	})
	resp, _ := runDT(t, 131, payload)
	var m map[string]any
	json.Unmarshal(unwrapDT131(t, resp), &m)
	if m["total"] != float64(2) || m["fail"] != float64(2) || m["success"] != float64(0) {
		t.Fatalf("弹窗 must all fail with total=count: %v", m)
	}
}
