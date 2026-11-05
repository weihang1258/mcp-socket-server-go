package mcpbridge

// dpi_apply_config 读不到模块配置时必须失败：
// 原实现把"读不到"当空 map，所有键走"缺失 → 追加"，把配置写坏还报成功（评审 P1-2）。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestApplyConfigFailsWhenModfileUnreadable(t *testing.T) {
	// syscfg.json 读不到（命令被杀）→ modfileOf 失败 → 必须报错，且不能写出任何东西
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if strings.Contains(p["args"], "syscfg.json") {
				timeoutReply(w)
				return
			}
			cmdReply(w, 0, "", "")
		}
	})
	raw := newTestBridge(t).runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkSystem, "", false, 10, func(c *Client) (any, error) {
			mf, ok := modfileOfOK(c)
			if !ok || mf == "" {
				return nil, errStr("读取 syscfg.json 的 modfile 失败，无法确定模块配置文件")
			}
			return dpiApplyConfigData{Alive: true}, nil
		})
	if raw[0].Ok {
		t.Fatalf("读不到 modfile 却报成功: %+v", raw[0])
	}
	if !strings.Contains(raw[0].Err, "modfile") {
		t.Fatalf("失败原因应指出 modfile: %q", raw[0].Err)
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }

// upgradeViaSystem 轮询命令被杀时不得判"脚本已结束"。
func TestUpgradeViaSystemPollKilledIsError(t *testing.T) {
	var pollN int
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 7: // /etc/init.d/upms_agent_monitor 存在
			w.text(`{"res":true}`)
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if strings.Contains(p["args"], "wc -l") && strings.Contains(p["args"], "/opt/agent/agent") {
				cmdReply(w, 0, "1\n", "") // wc -l 的输出：agent 在跑
				return
			}
			if strings.Contains(p["args"], "upms_install.sh") {
				// 第一次轮询能看到脚本在跑（进入完成等待），之后预算耗尽被 agent 杀掉
				pollN++
				if pollN == 1 {
					cmdReply(w, 0, "root 777 upms_install.sh\n", "")
					return
				}
				timeoutReply(w)
				return
			}
			if strings.Contains(p["args"], "upms_agent_monitor") {
				cmdReply(w, 0, "", "") // 让 toggleAgent(start) 走到轮询
				return
			}
			cmdReply(w, 0, "", "")
		}
	})
	raw := newTestBridge(t).runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkSystem, "", false, 10, func(c *Client) (any, error) {
			// 直接走工具的真实路径：upgradeDPI 会用 failOf 把 *CmdError 透传出去
			return upgradeDPI(c, dpiUpgradeIn{
				BaseIn:           BaseIn{Targets: []string{m.Addr}},
				UpgradeScript:    "/home/tmp/x/upms_install.sh",
				TargetVersion:    "1.0.6.3",
				UseUpgradeSystem: true,
				StartTimeout:     1,
				CompleteTimeout:  1,
			}, 1, 1)
		})
	if raw[0].Ok {
		t.Fatalf("轮询被杀却报升级成功: %+v", raw[0])
	}
	if !strings.Contains(raw[0].Err, "超时") {
		t.Fatalf("应明确指出是轮询超时而不是'未找到结果文件': %q", raw[0].Err)
	}
	// 评审 P1-3：超时语义不能降级成 business，cleanup 必须带出来
	if raw[0].ErrType != ErrTimeout {
		t.Fatalf("轮询超时应归 timeout，实际 %q（err=%q）", raw[0].ErrType, raw[0].Err)
	}
	if raw[0].Cleanup == nil || !raw[0].Cleanup.Killed {
		t.Fatalf("轮询超时必须带 cleanup: %+v", raw[0].Cleanup)
	}
	// 同一串 marks 不能被打两遍
	if strings.Count(raw[0].Err, "无法确认升级脚本状态") > 1 {
		t.Fatalf("失败文案重复拼了 marks: %q", raw[0].Err)
	}
}
