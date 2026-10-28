package svc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// agent 单元模板必须与 Python supervisor.py UNIT_CONTENT 逐字一致
// （ensure_unit_correct 做整文件 strip 比对，模板漂移 = 自愈失效 + 回滚断裂，设计 §8）。
func TestAgentUnitContentMatchesPython(t *testing.T) {
	const pythonUnit = `[Unit]
Description=socket_server TCP Service
After=network.target

[Service]
Type=simple
ExecStart={exec_path} serve
Restart=always
RestartSec=5
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
`
	got := AgentUnitContent("/opt/socket/versions/current/socket_server")
	want := strings.ReplaceAll(pythonUnit, "{exec_path}", "/opt/socket/versions/current/socket_server")
	if got != want {
		t.Fatalf("agent unit template drift:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	// strip 比对语义（supervisor.py:96）：strings.TrimSpace 后相等
	if strings.TrimSpace(got) != strings.TrimSpace(want) {
		t.Fatal("strip-compare would fail")
	}
}

func TestMCPUnitContent(t *testing.T) {
	got := MCPUnitContent()
	for _, want := range []string{
		"ExecStart=/usr/local/bin/socketstack mcp serve",
		"Restart=on-failure",
		"WorkingDirectory=/var/lib/socketstack",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("mcp unit missing %q in:\n%s", want, got)
		}
	}
}

func TestUnitPaths(t *testing.T) {
	if AgentUnitPath != "/etc/systemd/system/socket_server.service" {
		t.Errorf("agent unit path must stay Python-compatible, got %q", AgentUnitPath)
	}
	if MCPUnitPath != "/etc/systemd/system/socketstack-mcp.service" {
		t.Errorf("mcp unit path wrong: %q", MCPUnitPath)
	}
}

// /opt/socket 目录与 config 初始化（对齐 supervisor._ensure_dirs：config 缺省写 autoupgrade=on，
// 已存在不动——http_port=/proxy= 等旧键不能被覆盖丢失）
func TestEnsureDirsInitializesConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SOCKETSTACK_TEST_ROOT", dir)
	root = dir
	defer func() { root = "/opt/socket" }()

	if err := EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatalf("config not created: %v", err)
	}
	if string(data) != "autoupgrade=on\n" {
		t.Fatalf("config want autoupgrade=on, got %q", data)
	}
	// 二次调用不覆盖已有内容
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("autoupgrade=off\nhttp_port=9001\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "config"))
	if string(data) != "autoupgrade=off\nhttp_port=9001\n" {
		t.Fatalf("existing config must not be overwritten, got %q", data)
	}
	// versions 目录存在
	if fi, err := os.Stat(filepath.Join(dir, "versions")); err != nil || !fi.IsDir() {
		t.Fatalf("versions dir missing: %v", err)
	}
}
