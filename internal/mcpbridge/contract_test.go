package mcpbridge

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// 方案 §2/§3 契约：45 个工具，每个都有 inputSchema / outputSchema / _meta。
func TestToolContract(t *testing.T) {
	b := newTestBridge(t)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	b.RegisterTools(srv)

	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) != 45 {
		t.Fatalf("want 45 tools, got %d", len(list.Tools))
	}
	got := map[string]bool{}
	for _, tl := range list.Tools {
		got[tl.Name] = true
		if tl.Description == "" {
			t.Errorf("%s: 缺 description", tl.Name)
		}
		if tl.InputSchema == nil {
			t.Errorf("%s: 缺 inputSchema", tl.Name)
		}
		if tl.OutputSchema == nil {
			t.Errorf("%s: 缺 outputSchema（Out 必须是具体类型）", tl.Name)
		}
		for _, k := range []string{"default_timeout_s", "timeout_basis", "danger_level"} {
			if _, ok := tl.Meta[k]; !ok {
				t.Errorf("%s: _meta 缺 %s", tl.Name, k)
			}
		}
		// 危险级别必须与方案一致：只断言"键存在"挡不住写错级别后的静默通过
		if want, ok := planDanger[tl.Name]; ok {
			if got := tl.Meta["danger_level"]; got != want {
				t.Errorf("%s: danger_level = %v，方案要求 %s", tl.Name, got, want)
			}
		} else {
			t.Errorf("%s: 未在 planDanger 登记（新增工具必须同步方案）", tl.Name)
		}
	}
	for name := range toolDanger {
		if !got[name] {
			t.Errorf("登记表里有 %s，但没注册该工具", name)
		}
	}
	for name := range toolDefaultTimeout {
		if !got[name] {
			t.Errorf("超时表里有 %s，但没注册该工具", name)
		}
	}

	// 方案 §7 的缺省超时独立抄一份：production 表被改也不会静默通过
	want := map[string]int{
		"target_list":         5,
		"target_add":          10,
		"target_remove":       10,
		"file_stat":           15,
		"file_list":           30,
		"file_mkdir":          15,
		"file_remove":         60,
		"file_get":            120,
		"file_put":            300,
		"file_unzip":          600,
		"file_transfer_hint":  5,
		"shell_exec":          60,
		"net_route":           15,
		"net_set_mtu":         30,
		"net_set_time":        30,
		"capture_start":       30,
		"capture_stop":        30,
		"replay_run":          300,
		"probe_visit":         60,
		"listen_start":        30,
		"listen_clean":        30,
		"listen_save":         30,
		"listen_fetch":        60,
		"listen_stop":         30,
		"pcap_extract_flows":  30,
		"dpi_get_info":        15,
		"dpi_get_config":      15,
		"dpi_apply_config":    1230,
		"dpi_service":         1230,
		"dpi_agent_service":   60,
		"dpi_switch_mode":     930,
		"dpi_read_stat":       15,
		"dpi_wait_stat":       60,
		"dpi_wait_file":       600,
		"dpi_check_stalled":   30,
		"dpi_policy_get":      15,
		"dpi_policy_put":      15,
		"dpi_policy_wait":     60,
		"dpi_policy_write":    15,
		"dpi_prepare_package": 600,
		"dpi_install":         930,
		"dpi_upgrade":         1500,
		"dpi_backup":          300,
		"bridge_version":      15,
		"bridge_upgrade":      60,
	}
	for name, sec := range want {
		if toolDefaultTimeout[name] != sec {
			t.Errorf("%s 缺省超时 = %d，方案 §7 要求 %d", name, toolDefaultTimeout[name], sec)
		}
	}
}

// planDanger 方案 §2/§3 的「工具 → 危险级别」独立快照：从 production 表复制一份，
// 单独维护。改名/降级/升级都会被这张表抓住，而 production 表自洽检测抓不到。
var planDanger = map[string]string{
	"target_list": DangerRead, "target_add": DangerWrite, "target_remove": DangerDestructive,
	"file_stat": DangerRead, "file_list": DangerRead, "file_mkdir": DangerWrite,
	"file_remove": DangerDestructive, "file_get": DangerRead, "file_put": DangerWrite,
	"file_unzip": DangerWrite, "file_transfer_hint": DangerRead,
	"shell_exec": DangerDestructive,
	"net_route":  DangerRead, "net_set_mtu": DangerDestructive, "net_set_time": DangerDestructive,
	"capture_start": DangerWrite, "capture_stop": DangerWrite,
	"replay_run": DangerDestructive, "probe_visit": DangerRead,
	"listen_start": DangerWrite, "listen_clean": DangerWrite, "listen_save": DangerWrite,
	"listen_fetch": DangerRead, "listen_stop": DangerWrite,
	"pcap_extract_flows": DangerRead,
	"dpi_get_info":       DangerRead, "dpi_get_config": DangerRead, "dpi_apply_config": DangerDestructive,
	"dpi_service": DangerDestructive, "dpi_agent_service": DangerDestructive, "dpi_switch_mode": DangerDestructive,
	"dpi_read_stat": DangerRead, "dpi_wait_stat": DangerRead, "dpi_wait_file": DangerRead, "dpi_check_stalled": DangerRead,
	"dpi_policy_get": DangerRead, "dpi_policy_put": DangerWrite, "dpi_policy_wait": DangerRead, "dpi_policy_write": DangerWrite,
	"dpi_prepare_package": DangerWrite, "dpi_install": DangerDestructive, "dpi_upgrade": DangerDestructive,
	"dpi_backup":     DangerWrite, // 与 production 同源，改名即红
	"bridge_version": DangerRead, "bridge_upgrade": DangerDestructive,
}
