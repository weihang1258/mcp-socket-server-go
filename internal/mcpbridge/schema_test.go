package mcpbridge

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// P0 验收：工具经 SDK 注册后 inputSchema 必须带 properties（LLM 可见参数文档）
func TestToolsHaveInputSchemas(t *testing.T) {
	b := newTestBridge(t)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	b.RegisterTools(srv)

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	serverSession, err := srv.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) < 15 {
		t.Fatalf("want >=15 tools, got %d", len(list.Tools))
	}
	for _, tool := range list.Tools {
		if tool.InputSchema == nil {
			t.Fatalf("tool %s: nil input schema", tool.Name)
		}
		raw, _ := json.Marshal(tool.InputSchema)
		var schema struct {
			Properties map[string]any `json:"properties"`
		}
		json.Unmarshal(raw, &schema)
		props := len(schema.Properties)
		switch tool.Name {
		case "list_targets":
			if props > 2 {
				t.Fatalf("list_targets props %d", props)
			}
		case "cmd_exec":
			if props < 6 { // targets/args/cwd/env/wait/port/timeout/description
				t.Fatalf("cmd_exec props %d (schema empty?)", props)
			}
		case "upgrade_run":
			if props < 4 {
				t.Fatalf("upgrade_run props %d", props)
			}
		}
	}
}
