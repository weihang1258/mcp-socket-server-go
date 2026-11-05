package mcpbridge

// 「一台都没匹配到」必须是可见失败（评审遗留项）。
//
// resolve 会静默丢掉未知 @tag 和未登记主机，若剩下 0 台就照常组装，信封是
// total=0/ok=0 —— 调用方（尤其大模型）读起来像"全部成功"，据此以为动作已
// 下发到靶机。这里把三条路径都钉住：批量工具、纯本地工具、正常展开不受影响。

import (
	"context"
	"strings"
	"testing"
)

func TestUnknownTagIsVisibleFailure(t *testing.T) {
	b := newTestBridge(t)
	env := runEnvelope[shellExecData](b, context.Background(),
		BaseIn{Targets: []string{"@no-such-tag"}}, "shell_exec", nil, LkNone, "", false,
		func(c *Client) (any, error) {
			t.Fatal("不应连任何靶机（没有目标可连）")
			return nil, nil
		})
	if env.Ok != 0 || len(env.Failed) != 1 {
		t.Fatalf("未知 @tag 必须给出一条失败: %+v", env)
	}
	f := env.Failed[0]
	if !strings.Contains(f.Reason, "没有匹配到任何靶机") || !strings.Contains(f.Reason, "@no-such-tag") {
		t.Fatalf("失败文案要说明是哪个 tag 没展开: %q", f.Reason)
	}
	if f.ErrorType != ErrBusiness {
		t.Fatalf("应归 business（参数问题，不是网络）: %q", f.ErrorType)
	}
}

// 空 targets（resolve 前就是 0 台）也要如实说出来，而不是空信封。
func TestEmptyTargetsIsVisibleFailure(t *testing.T) {
	b := newTestBridge(t)
	env := runEnvelope[shellExecData](b, context.Background(), BaseIn{}, "shell_exec", nil,
		LkNone, "", false, func(c *Client) (any, error) { return nil, nil })
	if env.Ok != 0 || len(env.Failed) != 1 || !strings.Contains(env.Failed[0].Reason, "targets 为空") {
		t.Fatalf("空 targets 必须给出可见失败: %+v", env)
	}
}

// 不走 runBatchResults 的纯本地工具同样不能回 0/0。
func TestFileTransferHintUnknownTagIsVisibleFailure(t *testing.T) {
	env := emptyResolveEnvelope[fileTransferHintData]([]string{"@gone"})
	if env.Ok != 0 || env.Total != 1 || len(env.Failed) != 1 {
		t.Fatalf("纯本地工具也要给可见失败: %+v", env)
	}
	if !strings.Contains(env.Failed[0].Reason, "@gone") {
		t.Fatalf("文案要带上原输入: %q", env.Failed[0].Reason)
	}
}

// 正常展开不能被上面这条守卫误伤。
func TestResolvedTagStillRuns(t *testing.T) {
	b := newTestBridge(t)
	if r := b.Registry.AddTarget("127.0.0.1", 9000, []string{"lab"}, ""); r["ok"] != true {
		t.Fatalf("AddTarget: %v", r)
	}
	if got := len(b.resolve([]string{"@lab"})); got != 1 {
		t.Fatalf("@lab 应展开成 1 台，实际 %d", got)
	}
}
