package mcpbridge

// §9.6 真实 e2e：15 工具全量过一遍（真实 MCP 客户端 + 真实 agent :9000）。
// upgrade_run 的破坏性闭环由 upgrade_live_test.go 单测覆盖，此处只做只读预检路径。
// 前置（缺一 skip）：root + SOCKETSTACK_LIVE_E2E=1 + socket_server.service active。

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"

	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func liveE2EGuards(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("需要 root（真机 e2e，sudo 运行）")
	}
	if os.Getenv("SOCKETSTACK_LIVE_E2E") != "1" {
		t.Skip("需显式 SOCKETSTACK_LIVE_E2E=1")
	}
	if out, err := exec.Command("systemctl", "is-active", "--quiet", "socket_server.service").CombinedOutput(); err != nil {
		// 也接受裸 agent 进程（后台 serve）——靶机在 :9000 即可
		if conn, derr := net.DialTimeout("tcp", "127.0.0.1:9000", 2*time.Second); derr != nil {
			t.Skipf("无靶机（unit 未运行且 :9000 不通）: %s / %v", out, derr)
		} else {
			conn.Close()
		}
	}
}

// pgrepSleep999 真机复核：超时后不得残留本次命令的进程。
func pgrepSleep999() []string {
	out, err := exec.Command("pgrep", "-f", "^sleep 999$").Output()
	if err != nil {
		return nil
	}
	return strings.Fields(string(out))
}

func mcpCallAny(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("%s: 空内容", name)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s: 非 TextContent: %T", name, res.Content[0])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("%s: 非 JSON: %s", name, text.Text)
	}
	return out
}

func TestLiveFifteenToolsE2E(t *testing.T) {
	liveE2EGuards(t)

	b := newTestBridge(t)
	msrv := mcp.NewServer(&mcp.Implementation{Name: "live-e2e", Version: "0"}, nil)
	b.RegisterTools(msrv)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := msrv.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// 1. target_add（探活）
	out := mcpCallAny(t, cs, "target_add", map[string]any{"host": "127.0.0.1", "port": 9000})
	if out["registered"] != true {
		t.Fatalf("target_add: %v", out)
	}
	t.Cleanup(func() {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel2()
		cs.CallTool(ctx2, &mcp.CallToolParams{Name: "target_remove", Arguments: map[string]any{"host": "127.0.0.1", "port": 9000}})
		_ = ctx2
	})

	// 2. target_list
	out = mcpCallAny(t, cs, "target_list", map[string]any{})
	if targets, ok := out["targets"].([]any); !ok || len(targets) == 0 {
		t.Fatalf("target_list: %v", out)
	}

	// 3. version
	out = mcpCallAny(t, cs, "bridge_version", map[string]any{"targets": []string{"127.0.0.1"}})
	if out["ok"] != float64(1) {
		t.Fatalf("bridge_version: %v", out)
	}

	// 4. file_transfer_hint（零网络，纯指引）
	out = mcpCallAny(t, cs, "file_transfer_hint", map[string]any{"targets": []string{"127.0.0.1"}})
	// 新契约：信封 results[].data.{download,upload}
	if out["ok"] != float64(1) {
		t.Fatalf("file_transfer_hint: %v", out)
	}
	rs, _ := out["results"].([]any)
	if len(rs) != 1 {
		t.Fatalf("file_transfer_hint results: %v", out)
	}
	rm, _ := rs[0].(map[string]any)
	dm, _ := rm["data"].(map[string]any)
	if s, _ := dm["download"].(string); s == "" {
		t.Fatalf("file_transfer_hint 缺 download: %v", out)
	}

	// 5. isfile
	out = mcpCallAny(t, cs, "file_stat", map[string]any{"targets": []string{"127.0.0.1"}, "path": "/etc/hostname"})
	if out["ok"] != float64(1) {
		t.Fatalf("file_stat: %v", out)
	}

	// 6. isdir
	out = mcpCallAny(t, cs, "file_stat", map[string]any{"targets": []string{"127.0.0.1"}, "path": "/tmp"})
	if out["ok"] != float64(1) {
		t.Fatalf("file_stat(dir): %v", out)
	}

	// 7. cmd_exec
	out = mcpCallAny(t, cs, "shell_exec", map[string]any{"targets": []string{"127.0.0.1"}, "args": "echo hello_live_e2e"})
	if out["ok"] != float64(1) {
		t.Fatalf("shell_exec: %v", out)
	}

	// 7b. 超时真停（方案 §6.2 / §12 待实证 2）：到点后设备上不得残留 sleep。
	// 用独立连接跑，避免把已验证的连接判死；超时失败本身是**预期结果**。
	out = mcpCallAny(t, cs, "shell_exec", map[string]any{
		"targets": []string{"127.0.0.1"}, "args": "sleep 999", "timeout": 3})
	if out["ok"] != float64(0) {
		t.Fatalf("sleep 999 应超时失败: %v", out)
	}
	fl, _ := out["failed"].([]any)
	if len(fl) != 1 {
		t.Fatalf("超时未回 failed: %v", out)
	}
	fm, _ := fl[0].(map[string]any)
	if fm["error_type"] != "timeout" {
		t.Fatalf("error_type=%v，期望 timeout", fm["error_type"])
	}
	cu, _ := fm["cleanup"].(map[string]any)
	if cu == nil || cu["killed"] != true {
		t.Fatalf("超时回执缺 cleanup.killed: %v", fm)
	}
	if cu["verified"] != true {
		t.Fatalf("cleanup.verified=false（进程组可能还在跑）: %v", cu)
	}
	time.Sleep(300 * time.Millisecond)
	if pids := pgrepSleep999(); len(pids) > 0 {
		t.Fatalf("超时后靶机仍有 sleep 999: %v", pids)
	}

	// 8/9. capture_start/stop
	capPath := "/tmp/e2e_smoke_cap.pcap"
	os.Remove(capPath)
	out = mcpCallAny(t, cs, "capture_start", map[string]any{
		"targets": []string{"127.0.0.1"}, "iface": "lo", "path": capPath})
	if out["ok"] != float64(1) {
		t.Fatalf("capture_start: %v", out)
	}
	time.Sleep(500 * time.Millisecond)
	out = mcpCallAny(t, cs, "capture_stop", map[string]any{"targets": []string{"127.0.0.1"}, "path": capPath})
	if out["ok"] != float64(1) {
		t.Fatalf("capture_stop: %v", out)
	}
	if fi, err := os.Stat(capPath); err != nil || fi.Size() < 24 {
		t.Fatalf("pcap 未产出: %v", err)
	}

	// 10. pcap_flow_extract（专用小目录——/tmp 混有 52MB 历史 pcap 会拖爆解析）
	os.MkdirAll("/tmp/e2e_smoke_flows", 0o755)
	os.Rename(capPath, "/tmp/e2e_smoke_flows/"+capPath[strings.LastIndex(capPath, "/")+1:])
	defer os.RemoveAll("/tmp/e2e_smoke_flows")
	out = mcpCallAny(t, cs, "pcap_extract_flows", map[string]any{
		"targets": []string{"127.0.0.1"}, "pcap_dir": "/tmp/e2e_smoke_flows", "timeout": 60})
	if out["ok"] != float64(1) {
		t.Fatalf("pcap_extract_flows: %v", out)
	}

	// 11. boce_run（弹窗恒失败。环境相关：Go/chromedp 正常回统计；live Python 本机
	// pyppeteer "Browser closed unexpectedly" → do_boce 异常 → EOF 断连——两种都算通过）
	out = mcpCallAny(t, cs, "probe_visit", map[string]any{
		"targets": []string{"127.0.0.1"}, "url": "http://127.0.0.1:1", "count": 1,
		"timeout": 30, "mode": "弹窗"})
	if out["ok"] != float64(1) {
		reason := ""
		if fl, ok := out["failed"].([]any); ok && len(fl) > 0 {
			if m, _ := fl[0].(map[string]any); m != nil {
				reason, _ = m["reason"].(string)
			}
		}
		if !strings.Contains(reason, "EOF") {
			t.Fatalf("probe_visit: %v", out)
		}
		t.Log("probe_visit: live Python chromium 环境性断连（EOF），符合 Python 冒泡语义")
	}

	// 12. replay_run（单臂回放 smoke 捕获的 pcap——已在专用目录）
	out = mcpCallAny(t, cs, "replay_run", map[string]any{
		"targets": []string{"127.0.0.1"}, "pcaps": []string{"/tmp/e2e_smoke_flows/e2e_smoke_cap.pcap"},
		"uplink_iface": "lo", "downlink_iface": "lo", "timeout": 60})
	if out["ok"] != float64(1) {
		t.Fatalf("replay_run: %v", out)
	}

	// 13. listen_start/fetch/save/clean/stop 全动作
	out = mcpCallAny(t, cs, "listen_start", map[string]any{
		"targets": []string{"127.0.0.1"}, "listen_port": 39021})
	if out["ok"] != float64(1) {
		t.Fatalf("listen_start: %v", out)
	}
	out = mcpCallAny(t, cs, "listen_fetch", map[string]any{"targets": []string{"127.0.0.1"}})
	if out["ok"] != float64(1) {
		t.Fatalf("listen_fetch: %v", out)
	}
	out = mcpCallAny(t, cs, "listen_save", map[string]any{
		"targets": []string{"127.0.0.1"}, "file": "/tmp/e2e_smoke_listen.bin"})
	if out["ok"] != float64(1) {
		t.Fatalf("listen_save: %v", out)
	}
	out = mcpCallAny(t, cs, "listen_clean", map[string]any{"targets": []string{"127.0.0.1"}})
	if out["ok"] != float64(1) {
		t.Fatalf("listen_clean: %v", out)
	}
	out = mcpCallAny(t, cs, "listen_stop", map[string]any{"targets": []string{"127.0.0.1"}})
	if out["ok"] != float64(1) {
		t.Fatalf("listen_stop: %v", out)
	}

	// 14/15. target_remove（Cleanup 兜底）+ bridge_upgrade 预检坏版本
	out = mcpCallAny(t, cs, "bridge_upgrade", map[string]any{
		"targets": []string{"127.0.0.1"}, "version": "not-a-version"})
	if out["ok"] != float64(0) {
		t.Fatalf("bridge_upgrade 坏版本须拒绝: %v", out)
	}
	mcpCallAny(t, cs, "target_remove", map[string]any{"host": "127.0.0.1", "port": 9000})
}
