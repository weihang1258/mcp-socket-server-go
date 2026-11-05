package mcpbridge

// §6 超时真停：桥把 agent 的超时回执翻成 error_type=timeout + cleanup，
// 并且真的把 timeout_s 发下去（不发 = agent 永远不限时）。

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"
)

func TestTimeoutReceiptMapsToCleanup(t *testing.T) {
	var gotTimeoutS float64
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		if dt == 14 { // 版本查询：支持 timeout_s 的 agent 才发这个字段
			w.text(`"1.9.27"`)
			return
		}
		if dt != 1 {
			return
		}
		var p map[string]any
		json.Unmarshal(payload, &p)
		if v, ok := p["timeout_s"].(float64); ok {
			gotTimeoutS = v
		}
		body, _ := json.Marshal(map[string]any{
			"code": -1, "stdout": "", "stderr": "命令超时，已杀进程组",
			"timeout": true, "killed": true, "verified": false, "pgid": 4321,
		})
		gz := gzipBytes(body)
		n := make([]byte, 4)
		binary.LittleEndian.PutUint32(n, uint32(len(gz)))
		w.raw(append(n, gz...))
	})
	b := newTestBridge(t)
	raw := b.runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkNone, "", false, 7, func(c *Client) (any, error) {
			return c.CmdExec("sleep 999", "", nil, true)
		})
	env := envelopeFrom[shellExecData](raw)

	// 发下去的是"剩余预算"（工具总超时 7 秒减去已耗时），所以是 1..7 之间的整数
	if gotTimeoutS < 1 || gotTimeoutS > 7 {
		t.Fatalf("agent 没收到合理的 timeout_s：got %v", gotTimeoutS)
	}
	if len(env.Failed) != 1 || env.Failed[0].ErrorType != ErrTimeout {
		t.Fatalf("want error_type=timeout: %+v", env.Failed)
	}
	cu := env.Failed[0].Cleanup
	if cu == nil {
		t.Fatal("超时失败缺 cleanup")
	}
	if !cu.Killed || cu.Verified {
		t.Fatalf("cleanup 必须原样透传 killed=true/verified=false: %+v", cu)
	}
}

// 老版本 agent 会拒绝 timeout_s（unexpected keyword argument，命令根本不执行）。
// 版本低于引入版本时桥必须不带这个字段——宁可停不下来，也不能把命令搞失败。
func TestNoTimeoutSForOldAgent(t *testing.T) {
	testNoTimeoutSAtVersion(t, "1.9.20")
}

// 真机事故固化（2026-11-05）：1.9.26 的已发布二进制不认识 timeout_s——能力
// 进了源码却没升版本号，桥看到"1.9.26 >= 1.9.26"就发，结果每条 dt1 都
// TypeError 断连。门限因此上移到 1.9.27；这条钉住 1.9.26 仍属"老 agent"。
func TestNoTimeoutSFor1926ReleasedBinary(t *testing.T) {
	testNoTimeoutSAtVersion(t, "1.9.26")
}

func testNoTimeoutSAtVersion(t *testing.T, agentVer string) {
	t.Helper()
	var gotTimeoutS any
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		if dt == 14 {
			w.text(`"` + agentVer + `"`)
			return
		}
		if dt != 1 {
			return
		}
		var p map[string]any
		json.Unmarshal(payload, &p)
		gotTimeoutS = p["timeout_s"]
		body, _ := json.Marshal(map[string]any{"code": 0, "stdout": "ok", "stderr": ""})
		gz := gzipBytes(body)
		n := make([]byte, 4)
		binary.LittleEndian.PutUint32(n, uint32(len(gz)))
		w.raw(append(n, gz...))
	})
	b := newTestBridge(t)
	raw := b.runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkNone, "", false, 7, func(c *Client) (any, error) {
			return c.CmdExec("id", "", nil, true)
		})
	if !raw[0].Ok {
		t.Fatalf("老 agent 上命令不应失败: %+v", raw[0])
	}
	if gotTimeoutS != nil {
		t.Fatalf("老版 agent 不该收到 timeout_s: %v", gotTimeoutS)
	}
}

// dt0（回放）与 dt131（拨测）也必须走版本门：老 agent 收到 timeout_s 会直接
// TypeError，命令根本不执行。曾经只有 dt1 加了门禁。
func TestNoTimeoutSForOldAgentReplayAndBoce(t *testing.T) {
	var replayGot, boceGot any
	var replaySeen, boceSeen bool
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		if dt == 14 {
			w.text(`"1.8.3"`)
			return
		}
		var p map[string]any
		json.Unmarshal(payload, &p)
		switch dt {
		case 0:
			replaySeen = true
			replayGot = p["timeout_s"]
			w.text(`{"total_packets":1,"status":"ok"}`)
		case 131:
			boceSeen = true
			boceGot = p["timeout_s"]
			body := []byte(`{"success_rate":1,"details":[]}`)
			n := make([]byte, 4)
			binary.LittleEndian.PutUint32(n, uint32(len(body)))
			w.raw(append(n, body...))
		}
	})
	b := newTestBridge(t)
	b.runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkNone, "", false, 7, func(c *Client) (any, error) {
			return c.ReplayRun([]string{"/x.pcap"}, "lo", "", nil, nil, 50, nil, nil, nil, nil)
		})
	b.runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkNone, "", false, 7, func(c *Client) (any, error) {
			return c.BoceRun("http://x", 1, 0, 1, 10, "", "")
		})
	if !replaySeen || !boceSeen {
		t.Fatalf("mock 未收到 dt0/dt131（测试本身失效）: replay=%v boce=%v", replaySeen, boceSeen)
	}
	if replayGot != nil {
		t.Fatalf("老 agent 的 replay 不该收到 timeout_s: %v", replayGot)
	}
	if boceGot != nil {
		t.Fatalf("老 agent 的拨测不该收到 timeout_s: %v", boceGot)
	}
}

// h2：子命令行内有 code!=0 分支时，超时回执同样带 code=-1——必须判 timeout 而不是
// business，否则调用方看不到 cleanup，也不知道设备上是否还有残留进程。
func TestTimeoutReceiptOnCodeBranchIsTimeout(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		if dt == 14 {
			w.text(`"1.9.27"`)
			return
		}
		if dt != 1 {
			return
		}
		body, _ := json.Marshal(map[string]any{
			"code": -1, "stdout": "", "stderr": "命令超时，已杀进程组",
			"timeout": true, "killed": true, "verified": true, "pgid": 777,
		})
		gz := gzipBytes(body)
		n := make([]byte, 4)
		binary.LittleEndian.PutUint32(n, uint32(len(gz)))
		w.raw(append(n, gz...))
	})
	// file_list 走的是 `if code != 0 → failMap` 分支（全部非 shellOK 路径的最小代表）
	raw := newTestBridge(t).runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
		LkNone, "", true, 5, func(c *Client) (any, error) {
			out, err := shell(c, "find ./ -maxdepth 1")
			if err != nil {
				return nil, err
			}
			if code := intOf(out["code"]); code != 0 {
				return failMap(out, fmt.Sprint(out["stderr"])), nil
			}
			return out, nil
		})
	if raw[0].Ok || raw[0].ErrType != ErrTimeout {
		t.Fatalf("超时回执被判成 %q（应 timeout）: %+v", raw[0].ErrType, raw[0])
	}
	if raw[0].Cleanup == nil || !raw[0].Cleanup.Killed || !raw[0].Cleanup.Verified {
		t.Fatalf("timeout 失败必须带 cleanup: %+v", raw[0].Cleanup)
	}
}
