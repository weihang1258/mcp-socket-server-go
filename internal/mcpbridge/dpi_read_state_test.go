package mcpbridge

// dpiVersion/dpiMode 的三态（读到 / 文件不存在 / 命令失败）是 dpi_get_info 与
// install/upgrade 判定的地基：文件不存在 = 未安装（正常），超时被杀 = 真失败。
// 评审指出的缺口：把 dpiVersion 的失败路径删掉、把 dpi_get_info 的守卫改成空操作，
// 全量测试仍然全绿。

import (
	"encoding/json"
	"strings"
	"testing"
)

func mockVerFile(t *testing.T, reply func(w *mockConnIO)) *Client {
	t.Helper()
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 1:
			reply(w)
		}
	})
	c, _ := dialClient(t, m)
	return c
}

func TestDpiVersionTriState(t *testing.T) {
	// ① 正常读到
	c := mockVerFile(t, func(w *mockConnIO) { cmdReply(w, 0, "dpi_ver: V1.0.6.3\n", "") })
	if v, rs := dpiVersion(c); rs != dpiReadOK || v != "1.0.6.3" {
		t.Fatalf("正常读取: %q %v", v, rs)
	}
	// ② 文件不存在（cat 非零、无输出）= 未安装，不是失败
	c = mockVerFile(t, func(w *mockConnIO) { cmdReply(w, 1, "", "cat: No such file or directory") })
	if v, rs := dpiVersion(c); rs != dpiReadMissing || v != "" {
		t.Fatalf("文件不存在应为 Missing: %q %v", v, rs)
	}
	// ③ 命令被杀 = 读不到，必须 Failed（不能伪装成"没有版本"）
	c = mockVerFile(t, func(w *mockConnIO) { timeoutReply(w) })
	if _, rs := dpiVersion(c); rs != dpiReadFailed {
		t.Fatalf("命令被杀应为 Failed，实际 %v", rs)
	}
}

func TestDpiModeTriState(t *testing.T) {
	c := mockVerFile(t, func(w *mockConnIO) { cmdReply(w, 0, "com_a_b_ok\n", "") })
	if v, rs := dpiMode(c); rs != dpiReadOK || v != "com_a_b" {
		t.Fatalf("正常读取: %q %v", v, rs)
	}
	c = mockVerFile(t, func(w *mockConnIO) { cmdReply(w, 1, "", "no such file") })
	if _, rs := dpiMode(c); rs != dpiReadMissing {
		t.Fatalf("文件不存在应为 Missing，实际 %v", rs)
	}
	c = mockVerFile(t, func(w *mockConnIO) { timeoutReply(w) })
	if _, rs := dpiMode(c); rs != dpiReadFailed {
		t.Fatalf("命令被杀应为 Failed，实际 %v", rs)
	}
}

// 装前核验：ver.txt/dpiconfig.ok 不存在 → 成功（字段为空），不能报失败。
func TestDpiGetInfoMissingFilesIsNotError(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if strings.Contains(p["args"], "ver.txt") || strings.Contains(p["args"], "dpiconfig.ok") {
				cmdReply(w, 1, "", "cat: No such file or directory")
				return
			}
			cmdReply(w, 0, "", "")
		}
	})
	env := callToolEnv[dpiInfoData](t, mcpServerFor(newTestBridge(t)), "dpi_get_info",
		map[string]any{"targets": []string{m.Addr}, "port": portOf(m.Addr), "timeout": 5})
	if env.Ok != 1 {
		t.Fatalf("装前核验（文件不存在）不应失败: %+v", env.Failed)
	}
	if env.Results[0].Data.Version != "" || env.Results[0].Data.Mode != "" {
		t.Fatalf("未安装时版本/模式应为空: %+v", env.Results[0].Data)
	}
}

// 命令被杀 → 必须失败，且不能报成 business。
func TestDpiGetInfoTimeoutFails(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if strings.Contains(p["args"], "ver.txt") {
				timeoutReply(w)
				return
			}
			cmdReply(w, 0, "", "")
		}
	})
	env := callToolEnv[dpiInfoData](t, mcpServerFor(newTestBridge(t)), "dpi_get_info",
		map[string]any{"targets": []string{m.Addr}, "port": portOf(m.Addr), "timeout": 5})
	if env.Ok != 0 || len(env.Failed) != 1 {
		t.Fatalf("读取被终止必须失败: %+v", env)
	}
}
