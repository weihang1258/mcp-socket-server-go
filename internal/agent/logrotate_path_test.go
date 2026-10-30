package agent

import (
	"testing"

	"github.com/weihang1258/mcp-socket-server-go/internal/svc"
)

// logrotate 配置里的路径必须与 agent 实际写入的路径一致。两处独立定义
// （svc 不能反向依赖 agent），一旦漂移，轮转就指向一个没人写的文件——静默失效。
func TestLogrotatePathMatchesAgentLogPath(t *testing.T) {
	if svc.AgentLogPath != DefaultLogPath {
		t.Fatalf("svc.AgentLogPath=%q 与 agent.DefaultLogPath=%q 不一致，轮转会失效",
			svc.AgentLogPath, DefaultLogPath)
	}
}
