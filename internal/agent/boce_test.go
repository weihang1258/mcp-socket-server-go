package agent

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dt131 响应解包：[4B i][JSON]
func unwrapDT131(t *testing.T, resp []byte) []byte {
	t.Helper()
	if len(resp) < 4 {
		t.Fatalf("missing length prefix: %q", resp)
	}
	n := binary.LittleEndian.Uint32(resp[:4])
	return resp[4 : 4+n]
}

// chromium 预检链注入：fake chromium 可执行 + fake ensure 结果
func setupChromium(t *testing.T, ensureOK bool) string {
	t.Helper()
	fake := t.TempDir()
	chrome := filepath.Join(fake, "chrome")
	os.WriteFile(chrome, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	t.Setenv("SOCKETSTACK_TEST_CHROMIUM", chrome)
	setEnsureChromium(func(string) bool { return ensureOK })
	t.Cleanup(func() { setEnsureChromium(nil) })
	return chrome
}

// 封堵模式：全部 200 → success_ratio 100%
func TestDT131BlockModeAllSuccess(t *testing.T) {
	setupChromium(t, true)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("User-Agent") == "" {
			t.Error("UA must be set")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	payload, _ := json.Marshal(map[string]any{
		"url": srv.URL, "count": 3, "thread_count": 2, "timeout": 3, "mode": "封堵",
	})
	resp, err := runDT(t, 131, payload)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(unwrapDT131(t, resp), &out); err != nil {
		t.Fatal(err)
	}
	if out["total"] != float64(3) || out["success"] != float64(3) || out["fail"] != float64(0) {
		t.Fatalf("stats wrong: %v", out)
	}
	if out["success_ratio"] != "100.00%" {
		t.Fatalf("ratio: %v", out["success_ratio"])
	}
	if _, ok := out["time"]; !ok {
		t.Fatal("time key missing")
	}
	if hits != 3 {
		t.Fatalf("server hits %d", hits)
	}
}

// 封堵：非 200 计失败
func TestDT131BlockModeFailures(t *testing.T) {
	setupChromium(t, true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	payload, _ := json.Marshal(map[string]any{
		"url": srv.URL, "count": 2, "timeout": 3, "mode": "封堵",
	})
	resp, _ := runDT(t, 131, payload)
	var out map[string]any
	json.Unmarshal(unwrapDT131(t, resp), &out)
	if out["success"] != float64(0) || out["fail"] != float64(2) {
		t.Fatalf("fail stats: %v", out)
	}
	if out["success_ratio"] != "0.00%" {
		t.Fatalf("ratio: %v", out["success_ratio"])
	}
}

// 重定向跟随被禁（allow_redirects=false）：302 计失败而非跟随
func TestDT131NoRedirectFollow(t *testing.T) {
	setupChromium(t, true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(302)
	}))
	defer srv.Close()
	payload, _ := json.Marshal(map[string]any{
		"url": srv.URL, "count": 1, "timeout": 3, "mode": "封堵",
	})
	resp, _ := runDT(t, 131, payload)
	var out map[string]any
	json.Unmarshal(unwrapDT131(t, resp), &out)
	if out["fail"] != float64(1) {
		t.Fatalf("302 must count as fail: %v", out)
	}
}

// chromium 缺失且自动下载失败 → [4B i][{"error":...}]（非断连）
func TestDT131ChromiumDownloadFail(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("SOCKETSTACK_TEST_CHROMIUM", filepath.Join(fake, "nope"))
	setEnsureChromium(func(string) bool { return false })
	t.Cleanup(func() { setEnsureChromium(nil) })

	payload, _ := json.Marshal(map[string]any{
		"url": "http://x", "count": 1, "timeout": 3, "mode": "封堵",
	})
	resp, err := runDT(t, 131, payload)
	if err != nil {
		t.Fatalf("chromium 预检失败应回错误 JSON 而非断连: %v", err)
	}
	body := unwrapDT131(t, resp)
	var m map[string]string
	json.Unmarshal(body, &m)
	if !strings.Contains(m["error"], "chromium") {
		t.Fatalf("want chromium error, got %q", body)
	}
}

// 缺 url / 未知键 → 断连（Python **data TypeError）
func TestDT131StrictPayload(t *testing.T) {
	setupChromium(t, true)
	if _, err := runDT(t, 131, []byte(`{"count":1}`)); err == nil {
		t.Fatal("missing url must disconnect")
	}
	if _, err := runDT(t, 131, []byte(`{"url":"http://x","bogus":1}`)); err == nil {
		t.Fatal("unknown key must disconnect")
	}
}

// interval 节奏：interval=1、count=3 至少耗时 ~2s（提交间 sleep）
func TestDT131IntervalPacing(t *testing.T) {
	setupChromium(t, true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	payload, _ := json.Marshal(map[string]any{
		"url": srv.URL, "count": 3, "interval": 1, "thread_count": 3, "timeout": 3, "mode": "封堵",
	})
	start := time.Now()
	if _, err := runDT(t, 131, payload); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 1800*time.Millisecond {
		t.Fatalf("interval pacing not applied: %v", elapsed)
	}
}
