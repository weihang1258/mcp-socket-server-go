package main

import "testing"

// A13 回归：mcp restart 必须走 systemd 重启，不再掉进 stdio 阻塞
func TestMCPRestartDispatch(t *testing.T) {
	if act := mcpAction([]string{"restart"}); act != "svc:restart" {
		t.Fatalf("mcp restart → %q（应为 svc:restart）", act)
	}
}
