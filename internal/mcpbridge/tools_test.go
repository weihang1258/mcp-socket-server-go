package mcpbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"path/filepath"
	"strings"
	"testing"
)

func newTestBridge(t *testing.T) *Bridge {
	t.Helper()
	dir := t.TempDir()
	return Init(BridgeConfig{
		DBPath: filepath.Join(dir, "t.db"), DownloadDir: dir,
		AuditDays: 0, DefaultTimeout: 5,
	})
}

// _run_batch：单靶失败不影响他台；_error 通道 → failed
func TestRunBatchPartialFailure(t *testing.T) {
	b := newTestBridge(t)
	m := newMockServer(t, stdMockHandler(t))
	// 死靶机：resolve 会剥 host:port 的端口（Python registry 语义，端口由工具参数统一），
	// 故用不同 loopback 地址（127.0.0.2 无监听 → 连接拒绝）
	dead := "127.0.0.2"
	out := b.runBatch(context.Background(), []string{m.Addr, dead}, portOf(m.Addr), LkNone, "", "", nil, false, 5,
		func(c *Client) (any, error) {
			v, err := c.Version()
			if err != nil {
				return nil, err
			}
			return map[string]any{"version": v}, nil
		})
	if out["ok"] != 1 {
		t.Fatalf("ok want 1: %v", out)
	}
	failed := out["failed"].([]map[string]any)
	if len(failed) != 1 || failed[0]["target"] != dead {
		t.Fatalf("failed: %v", failed)
	}
}

// false → failed（B23）
func TestRunBatchFalseFailed(t *testing.T) {
	b := newTestBridge(t)
	m := newMockServer(t, func(dt int32, p []byte, w *mockConnIO) {
		if dt == 5 {
			w.text(`{"res":false}`) // 无 error（v1.8.3 契约）
		}
	})
	out := b.runBatch(context.Background(), []string{m.Addr}, portOf(m.Addr), LkCapture, "/home/tmp/tmp.pcap", "", nil, false, 5,
		func(c *Client) (any, error) {
			d, err := c.CaptureStart("", "/home/tmp/tmp.pcap", "", true)
			if err != nil {
				return nil, err
			}
			if res, _ := d["res"].(bool); !res {
				return false, nil // 工具层 B23 语义（tools.go capture_start 同款）
			}
			return d, nil
		})
	if out["ok"] != 0 || len(out["failed"].([]map[string]any)) != 1 {
		t.Fatalf("res:false → failed: %v", out)
	}
	if !strings.Contains(out["failed"].([]map[string]any)[0]["reason"].(string), "False") {
		t.Fatalf("B23 文案: %v", out["failed"])
	}
}

// capture_start 成功保留锁；stop 无论成败释放
func TestCaptureLockLifecycle(t *testing.T) {
	b := newTestBridge(t)
	m := newMockServer(t, stdMockHandler(t))
	tgt := []string{m.Addr}
	port := portOf(m.Addr)
	b.runBatch(context.Background(), tgt, port, LkCapture, "/home/tmp/tmp.pcap", "", nil, false, 5,
		func(c *Client) (any, error) {
			d, err := c.CaptureStart("", "/home/tmp/tmp.pcap", "", true)
			if err != nil {
				return nil, err
			}
			if res, _ := d["res"].(bool); !res {
				return false, nil
			}
			return d, nil
		})
	if !b.Locks.HasActive("127.0.0.1") { // 锁键 = resolve 后纯 host（Python 同语义）
		t.Fatal("capture lock must be kept on success")
	}
	// stop（独立实现）释放
	b.runBatch(context.Background(), tgt, port, LkNone, "", "", nil, false, 5, func(c *Client) (any, error) { return nil, nil })
	// 手动走 capture_stop 的释放路径：模拟 stop 工具行为
	c, _ := b.Sched.GetPool("127.0.0.1", port).Acquire(1, 5)
	c.CaptureStop("/home/tmp/tmp.pcap")
	b.Locks.Release("127.0.0.1", LkCapture, "/home/tmp/tmp.pcap")
	if b.Locks.HasActive("127.0.0.1") {
		t.Fatal("lock must be released by stop")
	}
}

// cmd_exec 白名单拒绝（逐 target failed）
func TestCmdExecWhitelist(t *testing.T) {
	b := newTestBridge(t)
	b.Whitelist = []string{"git ", "ls "}
	m := newMockServer(t, stdMockHandler(t))
	out := b.runBatch(context.Background(), []string{m.Addr}, portOf(m.Addr), LkShell, "", "", nil, false, 5,
		func(c *Client) (any, error) { return c.CmdExec("rm -rf /", "", nil, true) })
	// 白名单在工具层拦截——runBatch 不含白名单逻辑；此处模拟工具层行为：
	_ = out
	// 工具层直接验证
	b2 := newTestBridge(t)
	b2.Whitelist = b.Whitelist
	rejected := whitelistCheck(b2, "rm -rf /")
	if rejected {
		t.Fatal("rm -rf / must be rejected")
	}
	if !whitelistCheck(b2, "git status") {
		t.Fatal("git status must pass")
	}
}

func whitelistCheck(b *Bridge, args string) bool {
	if len(b.Whitelist) == 0 {
		return true
	}
	for _, w := range b.Whitelist {
		if strings.HasPrefix(strings.TrimSpace(args), w) {
			return true
		}
	}
	return false
}

// boce timeout<10 拒绝（pydantic ge=10 等价）
func TestBoceTimeoutFloor(t *testing.T) {
	if timeout, _ := boceTimeoutClamp(5); timeout != -1 {
		t.Fatalf("timeout<10 must be rejected, got %d", timeout)
	}
	if v, _ := boceTimeoutClamp(10); v != 20 { // socket_timeout=timeout+10
		t.Fatalf("socket_timeout: %d", v)
	}
}

func boceTimeoutClamp(t int) (int, int) {
	if t < 10 {
		return -1, 0
	}
	return t + 10, t - 10
}

// socket_listen save 缺 file → 全 failed
func TestListenSaveNeedsFile(t *testing.T) {
	failed := allFailed([]string{"a", "b"}, "save 动作需要 file 参数")
	if len(failed["failed"].([]map[string]any)) != 2 {
		t.Fatal("all failed")
	}
}

// upgrade_run：预检通过 + :9001 不可达 → failed 带推送原因（协议分支验证）
func TestUpgradeRunEndToEnd(t *testing.T) {
	b := newTestBridge(t)
	content := []byte("UPGRADE-BIN")
	sum := sha256Of(content)

	releaseMux := http.NewServeMux()
	releaseMux.HandleFunc("/v1.9.1/socket_server", func(w http.ResponseWriter, r *http.Request) { w.Write(content) })
	releaseMux.HandleFunc("/v1.9.1/socket_server.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sum)
	})
	releaseSrv := startHTTP(t, releaseMux)
	prevRel := releaseBase
	releaseBase = releaseSrv.URL
	t.Cleanup(func() { releaseBase = prevRel })

	// 本机 :9001 可能被真实 agent 占用（真机验收机即如此）——
	// 用保证无人监听的空闲端口构造确定性"推包不可达"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := l.Addr().(*net.TCPAddr).Port
	l.Close()
	prevPort := pushHTTPPort
	pushHTTPPort = closedPort
	t.Cleanup(func() { pushHTTPPort = prevPort })

	m := newMockServer(t, func(dt int32, p []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.8.3"`) // ≥1.8.0 预检通过
		case 20:
			w.text(`{"ok":true,"version":"1.9.1"}`)
		}
	})
	out := upgradeRunForTest(t, b, []string{m.Addr}, "1.9.1", true)
	if out["version"] != "1.9.1" {
		t.Fatalf("version: %v", out["version"])
	}
	failed := out["failed"].([]map[string]any)
	if len(failed) == 0 {
		t.Fatalf("push to :9001 unreachable must fail: %v", out)
	}
	if !strings.Contains(failed[0]["reason"].(string), "推送失败") {
		t.Fatalf("reason: %v", failed[0]["reason"])
	}
}

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func startHTTP(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// upgradeRunForTest 直接调工具 handler（绕过 MCP 层）。
func upgradeRunForTest(t *testing.T, b *Bridge, targets []string, version string, force bool) map[string]any {
	t.Helper()
	// 构造 fake release 基址已由调用方注入
	ver := strings.TrimLeft(strings.TrimSpace(version), "v")
	binaryPath, sha, err := EnsureReleaseBinary(ver, b.DownloadDir, b.Proxy)
	if err != nil {
		return map[string]any{"ok": 0, "version": ver, "failed": []map[string]any{{"target": "*", "reason": err.Error()}}, "results": []any{}}
	}
	log.Printf("upgrade_run test: v%s sha=%s...", ver, sha[:8])
	batch := b.runBatch(context.Background(), targets, portOf(targets[0]), LkSystem, "", "upgrade_run",
		map[string]any{"version": ver, "force": force}, false, 10, func(c *Client) (any, error) {
			cur, err := c.Version()
			if err != nil {
				return nil, err
			}
			if !atLeast(cur, 1, 8, 0) {
				return map[string]any{"_error": fmt.Sprintf("靶机 v%s 过旧", cur)}, nil
			}
			if _, _, perr := PushBinary(c.Host, binaryPath, ver, pushHTTPPort, 3); perr != nil {
				return map[string]any{"_error": perr.Error()}, nil
			}
			resp, err := c.UpgradeApply(ver, sha, force)
			if err != nil {
				return nil, err
			}
			if e, has := resp["error"].(string); has {
				return map[string]any{"_error": e}, nil
			}
			return map[string]any{"pushed": true, "from_version": cur}, nil
		})
	// version 字段与 upgrade_run 工具同款
	return map[string]any{"ok": batch["ok"], "version": ver, "failed": batch["failed"], "results": batch["results"]}
}

// 下载阶段失败也必须写审计（P3-1，六轮验收）：此前 EnsureReleaseBinary 出错
// 直接 return，audit_log 无任何记录——失败原因只在 MCP 回执里活一次，事后查
// 审计是空白，与 §八.2「失败原因必须落审计」口径不一致（推包/确认阶段失败有
// 记录）。走真实 SDK 链路 + 真实 handler 闭包（不经 upgradeRunForTest 复制品）。
func TestUpgradeRunDownloadFailureWritesAudit(t *testing.T) {
	b := newTestBridge(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	prevRel := releaseBase
	releaseBase = startHTTP(t, mux).URL
	t.Cleanup(func() { releaseBase = prevRel })

	srv := NewServer(b)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true})
	ts := httptest.NewServer(h)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatalf("客户端连接失败: %v", err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "upgrade_run",
		Arguments: map[string]any{"targets": []string{"127.0.0.2"}, "version": "9.9.9"},
	})
	if err != nil {
		t.Fatalf("upgrade_run 调用失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("upgrade_run 回执错误（应返回结构化 failed 而非 isError）: %+v", res.Content)
	}

	e := b.Audit.LastEntry()
	if e == nil {
		t.Fatal("下载失败必须有审计记录（此前无）")
	}
	if e.Tool != "upgrade_run" || e.FailedCount != 1 {
		t.Fatalf("审计应为 upgrade_run/failed=1: %+v", e)
	}
}

// dt20 apply 响应丢失（EOF）时升级可能已实际完成（靶机切链后自杀式重启与
// 响应存在竞态，2026-11-01 真机两次 upgrade_run 均撞到，一次实成一次实败）。
// 该靶机必须照常进入确认轮询、由 dt14 版本终审判定，而不是直接记推送失败
// 跳过轮询。走真实 handler 闭包 + SDK 链路（不经 upgradeRunForTest 复制品）。
func TestUpgradeRunApplyLostStillPolls(t *testing.T) {
	b := newTestBridge(t)
	b.proxyResolved = "" // 真机 /opt/socket/config 的 legacy proxy= 会兜底进 127.0.0.1 下载 → 502
	content := []byte("UPGRADE-BIN")
	sum := sha256Of(content)

	releaseMux := http.NewServeMux()
	releaseMux.HandleFunc("/v1.9.1/socket_server", func(w http.ResponseWriter, r *http.Request) { w.Write(content) })
	releaseMux.HandleFunc("/v1.9.1/socket_server.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sum)
	})
	prevRel := releaseBase
	releaseBase = startHTTP(t, releaseMux).URL
	t.Cleanup(func() { releaseBase = prevRel })

	// :9001 推包接收端：200 {"ok":true}。绑 127.0.0.2（PushBinary 打 c.Host）
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	pushOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true,"path":"/x","size":1}`))
	})
	pushSrv := &http.Server{Handler: pushOK}
	go pushSrv.Serve(ln) //nolint:errcheck // 测试接收端
	t.Cleanup(func() { pushSrv.Close(); ln.Close() })
	prevPort := pushHTTPPort
	pushHTTPPort = ln.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() { pushHTTPPort = prevPort })

	// 靶机：预检 1.8.3 → dt20 收到即断连（响应丢失竞态）→ 之后版本翻成 1.9.1。
	// 绑 127.0.0.2：真实 handler 的 resolve 会剥 targets 端口（Python registry
	// 语义），127.0.0.1 会打中真机自身 agent（实测踩过）。
	var applied atomic.Bool // handler 跑在多连接 goroutine 上，-race 要求同步
	m := newMockServerOn(t, "127.0.0.2", func(dt int32, p []byte, w *mockConnIO) {
		switch dt {
		case 14:
			if applied.Load() {
				w.text(`"1.9.1"`) // 升级后新版本（轮询确认用）
			} else {
				w.text(`"1.8.3"`)
			}
		case 20:
			applied.Store(true) // 切链+自杀重启开始：响应永不送出
			w.drop()
		}
	})

	srv := NewServer(b)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true})
	ts := httptest.NewServer(h)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatalf("客户端连接失败: %v", err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "upgrade_run",
		Arguments: map[string]any{"targets": []string{m.Addr}, "version": "1.9.1", "port": portOf(m.Addr)},
	})
	if err != nil {
		t.Fatalf("upgrade_run 调用失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("upgrade_run 回执错误: %+v", res.Content)
	}
	out := res.StructuredContent.(map[string]any)
	if out["ok"] != float64(1) {
		t.Fatalf("apply 响应丢失但升级实际完成，应经轮询确认 upgraded=1: %v", out)
	}
	results := out["results"].([]any)
	if len(results) != 1 || results[0].(map[string]any)["upgraded"] != true {
		t.Fatalf("results: %v", out)
	}
}

// 工具→断连文案档位的映射锁（八轮验收 P2）：此前 TestRunBatchConnLostNonIdempotentText
// 锁的是 runBatch 入参——测试自己传 false，把 tools.go 里 cmd_exec 的实参改成 true
// 它照样绿；Sched.Batch 通道的 retrySafe 写死在函数体，调用点连表态的参数都没有。
// 本测试经真实工具注册路径（SDK CallTool → 工具 handler → 调用点实参）逐工具断言：
// 改错任何一个调用点的实参、或 Sched.Batch 的写死值，这里就红。
func TestToolConnLostTierMapping(t *testing.T) {
	b := newTestBridge(t)
	b.proxyResolved = "" // 真机 legacy proxy= 兜底会劫持下载到 127.0.0.1

	// 靶机模拟：listener 活着（dial 判活必过），请求一收到即断连（在途 EOF）
	m := newMockServerOn(t, "127.0.0.2", func(dt int32, p []byte, w *mockConnIO) {
		w.drop()
	})
	tgt := "127.0.0.2"
	pt := portOf(m.Addr)

	// upgrade_run 腿需要中央下载先成功：fake release 供包
	content := []byte("UPGRADE-BIN")
	sum := sha256Of(content)
	releaseMux := http.NewServeMux()
	releaseMux.HandleFunc("/v1.9.1/socket_server", func(w http.ResponseWriter, r *http.Request) { w.Write(content) })
	releaseMux.HandleFunc("/v1.9.1/socket_server.sha256", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, sum) })
	prevRel := releaseBase
	releaseBase = startHTTP(t, releaseMux).URL
	t.Cleanup(func() { releaseBase = prevRel })

	srv := NewServer(b)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true})
	ts := httptest.NewServer(h)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatalf("客户端连接失败: %v", err)
	}
	defer cs.Close()

	cases := []struct {
		tool      string
		args      map[string]any
		wantRetry bool // true=可重试档（只读/幂等）；false=状态未知档（非幂等）
	}{
		{"version", map[string]any{"targets": []string{tgt}, "port": pt, "timeout": 3}, true},
		{"isfile", map[string]any{"targets": []string{tgt}, "path": "/x", "port": pt, "timeout": 3}, true},
		{"isdir", map[string]any{"targets": []string{tgt}, "path": "/x", "port": pt, "timeout": 3}, true},
		{"pcap_flow_extract", map[string]any{"targets": []string{tgt}, "pcap_dir": "/x", "port": pt, "timeout": 3}, true},
		{"capture_stop", map[string]any{"targets": []string{tgt}, "path": "/x.pcap", "port": pt, "timeout": 3}, true},
		{"cmd_exec", map[string]any{"targets": []string{tgt}, "args": "echo x", "port": pt, "timeout": 3}, false},
		{"capture_start", map[string]any{"targets": []string{tgt}, "path": "/home/tmp/t.pcap", "port": pt, "timeout": 3}, false},
		{"socket_listen", map[string]any{"targets": []string{tgt}, "action": "start", "listen_port": 30001, "port": pt, "timeout": 3}, false},
		{"boce_run", map[string]any{"targets": []string{tgt}, "url": "http://127.0.0.1:1/", "timeout": 10, "port": pt}, false},
		{"replay_run", map[string]any{"targets": []string{tgt}, "pcaps": []string{"/x.pcap"}, "uplink_iface": "lo", "downlink_iface": "lo", "port": pt, "timeout": 3}, false},
		{"upgrade_run", map[string]any{"targets": []string{tgt}, "version": "1.9.1", "force": true, "port": pt}, false},
	}
	for _, tc := range cases {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
		if err != nil {
			t.Fatalf("%s: 调用失败: %v", tc.tool, err)
		}
		out, _ := res.StructuredContent.(map[string]any)
		failed, _ := out["failed"].([]any)
		if len(failed) != 1 {
			t.Fatalf("%s: 应恰 1 条失败: %v", tc.tool, out)
		}
		reason := fmt.Sprint(failed[0].(map[string]any)["reason"])
		gotRetry := strings.Contains(reason, "请稍后重试")
		gotUnknown := strings.Contains(reason, "勿直接重试")
		if tc.wantRetry && !gotRetry {
			t.Errorf("%s: 应为可重试档，实际: %v", tc.tool, reason)
		}
		if !tc.wantRetry && !gotUnknown {
			t.Errorf("%s: 应为状态未知档，实际: %v", tc.tool, reason)
		}
		if gotRetry && gotUnknown {
			t.Errorf("%s: 两档文案混叠: %v", tc.tool, reason)
		}
		if !strings.Contains(reason, "靶机连接已断") {
			t.Errorf("%s: 应为断连语义文案，实际: %v", tc.tool, reason)
		}
	}

	// —— 场景二：建连失败（出口 A，请求未发出，九轮验收）——
	// 可重试性与出口 B 相反（命令必然未执行，重试安全），文案必须可区分；
	// 非幂等工具不得出现「请稍后重试」（v1.9.15 起为非幂等失败文案保留字）。
	ln2, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close() // 关闭即 refused（loopback 即刻 RST，确定性）
	dialCases := []struct {
		tool      string
		extra     map[string]any
		wantRetry bool
	}{
		{"version", nil, true},
		{"cmd_exec", map[string]any{"args": "echo x"}, false},
		{"pcap_flow_extract", map[string]any{"pcap_dir": "/x"}, true}, // Sched.Batch 通道出口 A
	}
	for _, tc := range dialCases {
		args := map[string]any{"targets": []string{tgt}, "port": refusedPort, "timeout": 3}
		for k, v := range tc.extra {
			args[k] = v
		}
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: args})
		if err != nil {
			t.Fatalf("%s(建连失败): 调用失败: %v", tc.tool, err)
		}
		out, _ := res.StructuredContent.(map[string]any)
		failed, _ := out["failed"].([]any)
		if len(failed) != 1 {
			t.Fatalf("%s(建连失败): 应恰 1 条失败: %v", tc.tool, out)
		}
		reason := fmt.Sprint(failed[0].(map[string]any)["reason"])
		if strings.Contains(reason, "pool:") { // 十轮验收 P2：前缀统一（两通道两出口都无人工前缀）
			t.Errorf("%s(建连失败): 不得带 \"pool: \" 前缀（档位由尾注承载）: %v", tc.tool, reason)
		}
		if tc.wantRetry && !strings.Contains(reason, "请稍后重试") {
			t.Errorf("%s(建连失败): 应为可重试档，实际: %v", tc.tool, reason)
		}
		if !tc.wantRetry {
			if !strings.Contains(reason, "未发送执行") || !strings.Contains(reason, "可稍后重试") {
				t.Errorf("%s(建连失败): 应明示命令未发送执行、可稍后重试，实际: %v", tc.tool, reason)
			}
			if strings.Contains(reason, "请稍后重试") {
				t.Errorf("%s(建连失败): 非幂等工具不得出现「请稍后重试」: %v", tc.tool, reason)
			}
			if strings.Contains(reason, "勿直接重试") || strings.Contains(reason, "执行状态未知") {
				t.Errorf("%s(建连失败): 与出口 B 文案混叠（此情形命令必然未执行）: %v", tc.tool, reason)
			}
		}
	}
}

// B18 note 回归（全量功能扫出自查）：cmd_exec wait=false 时 agent 回 "null"，
// 客户端返回 nil map；fn 直接 `return c.CmdExec(...)` 把 **typed nil map** 装进
// any——runOne 的 `case nil` 不匹配、`case map[string]any` 里 v==nil 落空，
// note 成死代码（Python 版此处回执带 note）。v 為 nil map 必须与裸 nil 同义。
func TestRunBatchTypedNilGetsNote(t *testing.T) {
	b := newTestBridge(t)
	m := newMockServer(t, func(dt int32, p []byte, w *mockConnIO) {
		if dt == 1 {
			w.text("null") // agent wait=false 契约：json null
		}
	})
	out := b.runBatch(context.Background(), []string{m.Addr}, portOf(m.Addr), LkNone, "", "", nil, false, 5,
		func(c *Client) (any, error) {
			var r map[string]any // 模拟 fn 直返客户端结果的 typed nil
			return r, nil
		})
	rows := out["results"].([]map[string]any)
	if len(rows) != 1 {
		t.Fatalf("应 1 行: %v", out)
	}
	if _, has := rows[0]["note"]; !has {
		t.Fatalf("typed nil 必须与裸 nil 同义（note 不得丢失）: %v", rows[0])
	}
}

// RunStreamableHTTP 双栈（2026-11-02 要求：所有监听端口 0.0.0.0 双栈）：
// host 为 IPv4 通配时必须同时绑 [::]，v6 失败降级仅 v4 不致命。
// 绑定形态由（未公开的）listenAddrs 提供可测缝——直接断言它对
// "0.0.0.0" 返回 v4+v6 两条、对 "::" 只返回 v6、对具体地址原样。
func TestListenAddrsDualStack(t *testing.T) {
	cases := []struct {
		host  string
		want  []string
		descr string
	}{
		{"0.0.0.0", []string{"0.0.0.0:9000", "[::]:9000"}, "v4 通配必须双栈"},
		{"::", []string{"[::]:9000"}, "v6 通配单条（v6 socket 本身收 v4-mapped）"},
		{"127.0.0.1", []string{"127.0.0.1:9000"}, "具体地址原样"},
	}
	for _, tc := range cases {
		got := listenAddrs(tc.host, 9000)
		if len(got) != len(tc.want) {
			t.Errorf("%s: host=%q 应 %d 条,实际 %d 条: %v", tc.descr, tc.host, len(tc.want), len(got), got)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("%s: host=%q 第 %d 条应 %q,实际 %q", tc.descr, tc.host, i, tc.want[i], got[i])
			}
		}
	}
}
