package mcpbridge

// 工具面描述契约（2026-11-06 用户要求「示例、精准、精简、能让大模型正确使用」）。
//
// 这些断言防的是「描述随时间腐化」：超时句被复制回来、新工具漏 title、
// 输出字段又变成无描述。任何一条变红都说明模型侧的可读性退化了。

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func listAllTools(t *testing.T) []*mcp.Tool {
	t.Helper()
	b := newTestBridge(t)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	b.RegisterTools(srv)
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
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
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	return list.Tools
}

// TestEveryToolHasTitleAndTrigger 每个工具都要有人类可读标题与使用时机。
func TestEveryToolHasTitleAndTrigger(t *testing.T) {
	for _, tl := range listAllTools(t) {
		if strings.TrimSpace(tl.Title) == "" {
			t.Errorf("%s: 缺 title（模型列表里会退化成机器名）", tl.Name)
		}
		d := tl.Description
		if !strings.Contains(d, "什么时候用") && !strings.Contains(d, "第一步") {
			t.Errorf("%s: 描述没说什么时候用，模型不知道何时该选它", tl.Name)
		}
	}
}

// TestDescriptionsHaveNoTimeoutNoise 超时信息只留 _meta，别在描述里重复。
func TestDescriptionsHaveNoTimeoutNoise(t *testing.T) {
	dt := regexp.MustCompile(`dt\d+`)
	for _, tl := range listAllTools(t) {
		d := tl.Description
		if strings.Contains(d, "超时缺省") {
			t.Errorf("%s: 描述重复了超时缺省值（_meta.default_timeout_s 已承载）", tl.Name)
		}
		if strings.Contains(d, "依据：") {
			t.Errorf("%s: 描述里留了「依据：」（属 _meta.timeout_basis）", tl.Name)
		}
		if dt.MatchString(d) {
			t.Errorf("%s: 描述暴露了内部协议号（%s），对模型是噪音", tl.Name, dt.FindString(d))
		}
	}
}

// TestOutputFieldsHaveDescriptions 输出字段无描述 = 模型拿到结果看不懂语义。
func TestOutputFieldsHaveDescriptions(t *testing.T) {
	missing := 0
	for _, tl := range listAllTools(t) {
		os, ok := tl.OutputSchema.(map[string]any)
		if !ok {
			continue
		}
		data := digDataSchema(os)
		for name, raw := range data {
			p, _ := raw.(map[string]any)
			if d, _ := p["description"].(string); strings.TrimSpace(d) == "" {
				t.Errorf("%s: 输出字段 %s 无描述", tl.Name, name)
				missing++
			}
		}
	}
	if missing > 0 {
		t.Fatalf("共 %d 个输出字段缺描述", missing)
	}
}

// TestInputFieldsHaveDescriptions 输入字段无描述 = 模型不知道填什么。
func TestInputFieldsHaveDescriptions(t *testing.T) {
	for _, tl := range listAllTools(t) {
		is, ok := tl.InputSchema.(map[string]any)
		if !ok {
			continue
		}
		props, _ := is["properties"].(map[string]any)
		for name, raw := range props {
			p, _ := raw.(map[string]any)
			if d, _ := p["description"].(string); strings.TrimSpace(d) == "" {
				t.Errorf("%s: 输入字段 %s 无描述", tl.Name, name)
			}
		}
	}
}

// TestServerInstructionsExist 服务级说明是「这组工具管什么」的唯一入口：
// 模型在 ToolSearch 里按字面量找工具，说明里漏掉一个名字，那个能力就等于不存在。
func TestServerInstructionsExist(t *testing.T) {
	for _, want := range []string{"远程主机", "靶机", "抓包", "回放", "DPI", "target_list", "shell_exec"} {
		if !strings.Contains(ServerInstructions, want) {
			t.Errorf("ServerInstructions 缺关键内容 %q", want)
		}
	}
	var missing []string
	for _, tl := range listAllTools(t) {
		if !strings.Contains(ServerInstructions, tl.Name) {
			missing = append(missing, tl.Name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("ServerInstructions 未点名这些工具（模型搜不到就不会用）：%s", strings.Join(missing, ", "))
	}
}

// TestServerInstructionsDontDictateOtherTools 只说明自己是远程工具，不指导
// 宿主的内置工具怎么用——harness 各不相同，工具集不在本服务管辖范围内。
func TestServerInstructionsDontDictateOtherTools(t *testing.T) {
	for _, bad := range []string{"内置工具", "内置 Read", "内置 Bash", "与内置", "不要用 file_"} {
		if strings.Contains(ServerInstructions, bad) {
			t.Errorf("ServerInstructions 越界指导宿主工具：出现 %q", bad)
		}
	}
}

// digDataSchema 从 Envelope 的 outputSchema 里取出 data 对象的 properties。
func digDataSchema(os map[string]any) map[string]any {
	props, _ := os["properties"].(map[string]any)
	res, _ := props["results"].(map[string]any)
	items, _ := res["items"].(map[string]any)
	iprops, _ := items["properties"].(map[string]any)
	data, _ := iprops["data"].(map[string]any)
	dprops, _ := data["properties"].(map[string]any)
	return dprops
}
