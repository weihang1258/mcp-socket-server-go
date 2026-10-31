package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsZeroConfig(t *testing.T) {
	os.Unsetenv("MCP_BIND_HOST")
	os.Unsetenv("MCP_BIND_PORT")
	os.Unsetenv("MCP_LOG_LEVEL")
	os.Unsetenv("MCP_DEFAULT_TIMEOUT")
	os.Unsetenv("SOCKET_SERVER_LOG")
	cfg := Load("")
	if cfg.Agent.TCPPort != 9000 {
		t.Errorf("agent tcp_port want 9000 got %d", cfg.Agent.TCPPort)
	}
	if cfg.Agent.LogFile != "/var/log/socket_server.log" {
		t.Errorf("agent log_file want default, got %q", cfg.Agent.LogFile)
	}
	if cfg.MCP.Bind.Host != "0.0.0.0" || cfg.MCP.Bind.Port != 9010 {
		t.Errorf("mcp bind want 0.0.0.0:9010 got %s:%d", cfg.MCP.Bind.Host, cfg.MCP.Bind.Port)
	}
	if cfg.MCP.DBPath != "/var/lib/socketstack/mcp.db" {
		t.Errorf("db_path want /var/lib/socketstack/mcp.db got %q", cfg.MCP.DBPath)
	}
	if cfg.MCP.BehindProxy {
		t.Error("behind_proxy want false")
	}
	if cfg.MCP.Pool.MaxConnPerTarget != 5 || cfg.MCP.Pool.IdleTimeout != 600 ||
		cfg.MCP.Pool.BorrowTimeout != 10 || cfg.MCP.Pool.MaxGlobalConcurrency != 50 {
		t.Errorf("pool defaults wrong: %+v", cfg.MCP.Pool)
	}
	if cfg.MCP.AuditRetentionDays != 90 {
		t.Errorf("audit_retention want 90 got %d", cfg.MCP.AuditRetentionDays)
	}
	if cfg.MCP.DefaultTimeout != 30 {
		t.Errorf("default_timeout want 30 got %d", cfg.MCP.DefaultTimeout)
	}
	if len(cfg.MCP.CmdExecWhitelist) != 0 {
		t.Errorf("whitelist want empty")
	}
}

func TestYAMLOverride(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	yaml := `
agent:
  tcp_port: 9500
  log_file: /tmp/x.log
mcp:
  bind: {host: 127.0.0.1, port: 9090}
  proxy: http://p:7897
  cmd_exec_whitelist: ["git ", "ls "]
`
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Load(p)
	if cfg.Agent.TCPPort != 9500 || cfg.Agent.LogFile != "/tmp/x.log" {
		t.Errorf("agent override wrong: %+v", cfg.Agent)
	}
	if cfg.MCP.Bind.Host != "127.0.0.1" || cfg.MCP.Bind.Port != 9090 {
		t.Errorf("bind override wrong: %+v", cfg.MCP.Bind)
	}
	if cfg.MCP.Proxy != "http://p:7897" {
		t.Errorf("proxy wrong: %q", cfg.MCP.Proxy)
	}
	if len(cfg.MCP.CmdExecWhitelist) != 2 || cfg.MCP.CmdExecWhitelist[0] != "git " {
		t.Errorf("whitelist wrong: %v", cfg.MCP.CmdExecWhitelist)
	}
	// 未覆盖键保持默认
	if cfg.MCP.Pool.MaxConnPerTarget != 5 {
		t.Errorf("pool default lost on override: %+v", cfg.MCP.Pool)
	}
}

func TestEnvOverrideWhitelist(t *testing.T) {
	t.Setenv("MCP_BIND_HOST", "10.0.0.1")
	t.Setenv("MCP_BIND_PORT", "9999")
	t.Setenv("MCP_LOG_LEVEL", "DEBUG")
	t.Setenv("MCP_DEFAULT_TIMEOUT", "45")
	t.Setenv("SOCKET_SERVER_LOG", "/tmp/ss.log")
	cfg := Load("")
	if cfg.MCP.Bind.Host != "10.0.0.1" || cfg.MCP.Bind.Port != 9999 {
		t.Errorf("bind env wrong: %+v", cfg.MCP.Bind)
	}
	if cfg.MCP.LogLevel != "DEBUG" {
		t.Errorf("log level env wrong: %q", cfg.MCP.LogLevel)
	}
	if cfg.MCP.DefaultTimeout != 45 {
		t.Errorf("default_timeout env wrong: %d", cfg.MCP.DefaultTimeout)
	}
	if cfg.Agent.LogFile != "/tmp/ss.log" {
		t.Errorf("SOCKET_SERVER_LOG wrong: %q", cfg.Agent.LogFile)
	}
}

func TestMissingFileUsesDefaults(t *testing.T) {
	cfg := Load("/nonexistent/c.yaml")
	if cfg.Agent.TCPPort != 9000 {
		t.Errorf("missing file should be zero-config, got %+v", cfg.Agent)
	}
}

// chromium 预取默认关闭：内网靶机连不上 npmmirror，无条件预取会让每次重启
// 都白跑一次 536MB 下载（Python 是「用到才触发」，见 handlers.py:263）。
func TestChromiumPrefetchDefaultsOff(t *testing.T) {
	cfg := Load("")
	if cfg.Agent.ChromiumPrefetch {
		t.Fatal("chromium_prefetch 须默认关闭（内网靶机不能打外网）")
	}
}

func TestChromiumPrefetchCanBeEnabled(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/c.yaml"
	os.WriteFile(p, []byte("agent:\n  chromium_prefetch: true\n"), 0o644)
	if cfg := Load(p); !cfg.Agent.ChromiumPrefetch {
		t.Fatal("配置写 chromium_prefetch: true 须生效")
	}
}

// mcp 子键写在顶层会被 YAML 静默丢弃（未知顶层键不报错）——真机中央的
// config.yaml 就这么错过：upgrade_mirror/proxy/upgrade_repo 全在顶层，
// 文件看着配好了、程序一条没读到，下载裸连 GitHub 失败（五轮验收定位）。
// 解析侧必须能检出并告警。
func TestMisplacedKeys(t *testing.T) {
	flat := `# 顶层写法（错误）
upgrade_repo: weihang1258/mcp-socket-server-go
upgrade_mirror: https://gh-proxy.com/
proxy: http://10.12.186.204:7897
`
	got := MisplacedKeys([]byte(flat))
	if len(got) != 3 {
		t.Fatalf("顶层 3 个 mcp 子键应全部检出，实际 %d: %v", len(got), got)
	}

	nested := `mcp:
  upgrade_mirror: https://gh-proxy.com/
  proxy: http://10.12.186.204:7897
`
	if got := MisplacedKeys([]byte(nested)); len(got) != 0 {
		t.Fatalf("嵌套写法不应告警，实际 %v", got)
	}

	// 畸形 YAML：不炸，返回空（Load 本身也不报这种）
	if got := MisplacedKeys([]byte(":\n\t- ]")); got != nil {
		t.Fatalf("畸形 YAML 应静默返回空，实际 %v", got)
	}
}
