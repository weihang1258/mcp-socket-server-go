package mcpbridge

// 这一组锁"测不到 ≠ 没发生"与"判定失败必须到信封"两类语义：
//   - P1-3：ps 命令被杀时 dpiProcCount 返回 ok=false，dpi_service(stop) 不能报成功
//   - P1-1：dpi_upgrade 版本/配置核对不符必须走 _error（runOne 不认 struct 的 OK=false）
//   - P1-5：@tag 展开成多台时 dpi_install/dpi_upgrade 必须拒绝
//   - P2-1：install.sh 超时被杀时 Failure.cleanup 必须带出来
// 都用 mock agent，不需要真机。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// killAllShell 让所有 dt1 都回"超时被杀"。
func killAllShell(w *mockConnIO) {
	timeoutReply(w)
}

func TestDpiServiceStopFailsWhenProcQueryKilled(t *testing.T) {
	// dpikill.sh 正常返回，但随后的 ps 一律被杀：测不到进程 → 不能说"已停"
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 7:
			w.text(`{"res":false}`)
		case 8:
			w.text(`{"res":false}`)
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if strings.Contains(p["args"], "ps -ef") {
				killAllShell(w)
				return
			}
			cmdReply(w, 0, "", "")
		}
	})
	b := newTestBridge(t)
	raw := b.runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkSystem, "", false, 5, func(c *Client) (any, error) {
			ok := dpiStopAll(c, 3)
			if !ok {
				return map[string]any{"_error": "DPI 停止失败或超时"}, nil
			}
			return dpiServiceData{OK: true}, nil
		})
	if raw[0].Ok {
		t.Fatalf("ps 全部被杀（测不到进程）却报停止成功: %+v", raw[0])
	}
}

func TestDpiUpgradeVersionMismatchReachesEnvelope(t *testing.T) {
	// 版本脚本恒回 1.0.5.0，目标 1.0.6.3：核对不符必须失败
	var md5Seq int
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 7: // isfile=false
			w.text(`{"res":false}`)
		case 8: // isdir=false：跳过备份（省掉 cp -r 与版本查询）
			w.text(`{"res":false}`)
		case 9:
			w.text(`null`)
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			switch {
			case strings.Contains(p["args"], "ver.txt"):
				cmdReply(w, 0, "1.0.5.0\n", "")
			case strings.Contains(p["args"], "dpiconfig.ok"):
				cmdReply(w, 0, "com_a_b\n", "")
			case strings.Contains(p["args"], "md5sum"):
				// 让 waitDPIAlive 通过（值变化），把用例推进到"版本核对"那一步
				md5Seq++
				cmdReply(w, 0, fmt.Sprintf("%d\n", md5Seq), "")
			default:
				cmdReply(w, 0, "", "")
			}
		}
	})
	b := newTestBridge(t)
	raw := b.runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkSystem, "", false, 30, func(c *Client) (any, error) {
			return upgradeDPI(c, dpiUpgradeIn{
				BaseIn:        BaseIn{Targets: []string{m.Addr}},
				UpgradeScript: "/home/tmp/dpi_pkg/x/upms_install.sh",
				TargetVersion: "1.0.6.3",
			}, 5, 5)
		})
	if raw[0].Ok {
		t.Fatalf("版本核对不符却报升级成功: %+v", raw[0])
	}
	if !strings.Contains(raw[0].Err, "1.0.6.3") {
		t.Fatalf("失败原因应包含期望版本（否则调用方不知道差在哪）: %q", raw[0].Err)
	}
}

func TestDpiInstallRejectsExpandedMultiTarget(t *testing.T) {
	// guard 必须对 resolve() 之后的结果生效：registry 里一个 @tag 可以展开成 N 台，
	// 只判 len(a.Targets) 会让 N 台并发删 /opt/dpi（评审 P1-5）。
	b := newTestBridge(t)
	// 每个 Bridge 现在各开一个 registry（去掉了包级单例），直接写本用例的库即可
	b.Registry.AddTarget("10.1.1.1", 9000, []string{"lab"}, "")
	b.Registry.AddTarget("10.1.1.2", 9000, []string{"lab"}, "")
	if got := len(b.resolve([]string{"@lab"})); got < 2 {
		t.Fatalf("@lab 应展开成 ≥2 台，实际 %d（测试前置失效）", got)
	}
	// 直接验证工具入口的 guard：用 in-memory MCP 调 dpi_install
	srv := mcpServerFor(b)
	env := callToolEnv[dpiInstallData](t, srv, "dpi_install", map[string]any{
		"targets": []string{"@lab"}, "install_script": "/x/install.sh", "timeout": 3})
	if env.Ok != 0 || len(env.Failed) < 2 {
		t.Fatalf("@tag 展开成多台时必须整批拒绝（原判据只看 len(targets)）: %+v", env)
	}
	// 必须是被 guard 拒绝，而不是"两台都连不上"——否则这条用例对 guard 不敏感
	for _, f := range env.Failed {
		if !strings.Contains(f.Reason, "一次只能装 1 台") {
			t.Fatalf("不是被单台 guard 拒绝的（原判据只看 len(targets)）: %+v", f)
		}
	}
}

func TestInstallScriptTimeoutCarriesCleanup(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 7: // dpi 目录不存在 → 跳过备份/停服，直接跑 install.sh
			w.text(`{"res":false}`)
		case 8:
			w.text(`{"res":false}`)
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if strings.Contains(p["args"], "install.sh") {
				timeoutReply(w) // agent 到点杀进程组
				return
			}
			cmdReply(w, 0, "", "")
		}
	})
	b := newTestBridge(t)
	raw := b.runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkSystem, "", false, 10, func(c *Client) (any, error) {
			return installDPI(c, dpiInstallIn{
				BaseIn:        BaseIn{Targets: []string{m.Addr}},
				InstallScript: "/home/tmp/x/install.sh",
			}, 3)
		})
	if raw[0].Ok {
		t.Fatalf("install.sh 被杀却报成功: %+v", raw[0])
	}
	if raw[0].ErrType != ErrTimeout {
		t.Fatalf("应归 timeout，实际 %q: %+v", raw[0].ErrType, raw[0])
	}
	if raw[0].Cleanup == nil || !raw[0].Cleanup.Killed || !raw[0].Cleanup.Verified {
		t.Fatalf("超时失败必须带 cleanup（评审 P2-1）: %+v", raw[0].Cleanup)
	}
}

// mcpServerFor 起一个只注册工具、走内存传输的服务端（供工具级用例复用）。
func mcpServerFor(b *Bridge) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	b.RegisterTools(srv)
	return srv
}

func callToolEnv[T any](t *testing.T, srv *mcp.Server, name string, args map[string]any) Envelope[T] {
	t.Helper()
	st, ct := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope[T]
	if err := json.Unmarshal([]byte(textOf(t, res)), &env); err != nil {
		t.Fatal(err)
	}
	return env
}

// P1-1 的第二个逃生口：ConfigDifferences 非空也必须到信封。
// 评审指出原用例只靠 Marks 分支变红，ConfigDifferences 那条没锁住。
func TestDpiUpgradeConfigMismatchReachesEnvelope(t *testing.T) {
	var md5Seq int
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 7: // isfile
			w.text(`{"res":false}`)
		case 8: // isdir=false → 备份跳过（不产生 Marks）
			w.text(`{"res":false}`)
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			switch {
			case strings.Contains(p["args"], "ver.txt"):
				cmdReply(w, 0, "1.0.6.3\n", "") // 版本对得上 → 不产生版本 Marks
			case strings.Contains(p["args"], "dpiconfig.ok"):
				cmdReply(w, 0, "com_a_b\n", "")
			case strings.Contains(p["args"], "md5sum"):
				md5Seq++
				cmdReply(w, 0, fmt.Sprintf("%d\n", md5Seq), "")
			case strings.Contains(p["args"], "xsa.json"):
				cmdReply(w, 0, `{"devinfo":{"province_id":1}}`, "") // 与期望不符
			default:
				cmdReply(w, 0, "", "")
			}
		}
	})
	raw := newTestBridge(t).runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkSystem, "", false, 10, func(c *Client) (any, error) {
			return upgradeDPI(c, dpiUpgradeIn{
				BaseIn:        BaseIn{Targets: []string{m.Addr}},
				UpgradeScript: "/home/tmp/x/upms_install.sh",
				TargetVersion: "1.0.6.3",
				XsaExpect:     map[string]any{"devinfo.province_id": 117},
			}, 1, 1)
		})
	if raw[0].Ok {
		t.Fatalf("xsa 配置与期望不符却报成功: %+v", raw[0])
	}
	if !strings.Contains(raw[0].Err, "province_id") {
		t.Fatalf("失败原因应指出哪个配置不符: %q", raw[0].Err)
	}
}
