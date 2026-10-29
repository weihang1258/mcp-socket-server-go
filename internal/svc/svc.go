// Package svc systemd 单元管理（设计文档 §8）。
//
// 互操作铁律：agent 单元沿用 Python socket_server.service（路径/模板逐字一致），
// Go CLI 接受裸 serve 别名 → 旧 unit 可直接拉起 Go 二进制、回滚不断裂。
// systemctl 操作是薄包装（root 执行）；单元测试只覆盖纯函数（模板/路径/config 初始化）。
package svc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	AgentUnitPath = "/etc/systemd/system/socket_server.service" // 与 Python supervisor.UNIT_PATH 相同
	MCPUnitPath   = "/etc/systemd/system/socketstack-mcp.service"
	ServiceName   = "socket_server" // systemctl 操作的 agent 单元名（对齐 Python SERVICE_NAME）
	MCPService    = "socketstack-mcp"
	InstallDir    = "/opt/socket"
	VersionsDir   = "/opt/socket/versions"
	ConfigPath    = "/opt/socket/config"
	CurrentLink   = "/opt/socket/versions/current"
	BinPath       = "/usr/local/bin/socketstack"
)

// root 供测试注入临时根目录；生产恒为 /opt/socket。
var root = InstallDir

// agentUnitTemplate 与 Python supervisor.py UNIT_CONTENT 逐字一致（含末尾换行）。
const agentUnitTemplate = `[Unit]
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

func AgentUnitContent(execPath string) string {
	return strings.ReplaceAll(agentUnitTemplate, "{exec_path}", execPath)
}

// MCPUnitContent mcp 单元。StateDirectory 让 systemd 在 ExecStart 前建好
// /var/lib/socketstack（默认 db_path/download_dir 的父目录，§12#11 改的绝对路径）。
// 没有它，全新机器上首次启动会因目录不存在直接 Fatal（sqlite 报的
// "unable to open database file: out of memory" 还看不出真因）。
func MCPUnitContent() string {
	return `[Unit]
Description=socketstack MCP Bridge
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/lib/socketstack
StateDirectory=socketstack
ExecStart=` + BinPath + ` mcp serve
Restart=on-failure

[Install]
WantedBy=multi-user.target
`
}

// EnsureDirs 创建 versions/ 并初始化 config（已存在不覆盖，对齐 Python _ensure_dirs）。
func EnsureDirs() error {
	if err := os.MkdirAll(filepath.Join(root, "versions"), 0o755); err != nil {
		return err
	}
	cfg := filepath.Join(root, "config")
	if _, err := os.Stat(cfg); os.IsNotExist(err) {
		return os.WriteFile(cfg, []byte("autoupgrade=on\n"), 0o644)
	}
	return nil
}

// WriteUnit 写入单元文件并 daemon-reload（对齐 Python _write_unit）。
func WriteUnit(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("写入 %s 需要 root 权限: %w", path, err)
	}
	return systemctl("daemon-reload")
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// systemctlOk 执行 systemctl 并返回是否成功（is-active 等探测用）。
func systemctlOk(args ...string) bool {
	return exec.Command("systemctl", args...).Run() == nil
}

// ---- agent 单元操作（对齐 Python supervisor 语义） ----

func AgentEnable() error {
	if err := EnsureDirs(); err != nil {
		return err
	}
	execPath := FindCurrentBinary()
	if execPath == "" {
		return fmt.Errorf("找不到 socket_server 二进制，请先部署")
	}
	if err := WriteUnit(AgentUnitPath, AgentUnitContent(execPath)); err != nil {
		return err
	}
	return systemctl("enable", ServiceName)
}

// EnsureUnitCorrect 启动自愈（对齐 ensure_unit_correct）：
// current 链接无效直接返回（交给 enable）；unit 不存在不创建；
// 整文件 strip 比对不一致才重写。
func EnsureUnitCorrect() {
	if err := EnsureDirs(); err != nil {
		return
	}
	expectedExec := filepath.Join(CurrentLink, "socket_server")
	if fi, err := os.Stat(expectedExec); err != nil || fi.IsDir() {
		return
	}
	existing, err := os.ReadFile(AgentUnitPath)
	if err != nil {
		return // unit 不存在，不在此创建
	}
	expected := AgentUnitContent(expectedExec)
	if strings.TrimSpace(string(existing)) == strings.TrimSpace(expected) {
		return
	}
	if err := WriteUnit(AgentUnitPath, expected); err == nil {
		// Python 版在此打日志"已修正 systemd unit ExecStart（自愈）"；由调用方接日志
		_ = err
	}
}

func AgentStart() error   { return systemctl("start", ServiceName) }
func AgentRestart() error { return systemctl("restart", ServiceName) }
func AgentStop() error    { return systemctl("stop", ServiceName) }
func AgentDisable() error { return systemctl("disable", ServiceName) }
func AgentActive() bool   { return systemctlOk("is-active", ServiceName) }

// ---- mcp 单元操作（新增单元，Python 无对应） ----

func MCPInstall() error {
	if err := WriteUnit(MCPUnitPath, MCPUnitContent()); err != nil {
		return err
	}
	return systemctl("enable", MCPService)
}

func MCPStart() error   { return systemctl("start", MCPService) }
func MCPStop() error    { return systemctl("stop", MCPService) }
func MCPDisable() error { return systemctl("disable", MCPService) }
func MCPActive() bool   { return systemctlOk("is-active", MCPService) }

// FindCurrentBinary 找 current 软链下的二进制（不解析软链，对齐 _find_current_binary）：
// current 链接 → /opt/socket/socket_server fallback → PATH 上的 socketstack。
func FindCurrentBinary() string {
	current := filepath.Join(CurrentLink, "socket_server")
	if fi, err := os.Stat(current); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
		return current
	}
	fallback := filepath.Join(InstallDir, "socket_server")
	if fi, err := os.Stat(fallback); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
		return fallback
	}
	if p, err := exec.LookPath("socketstack"); err == nil {
		return p
	}
	return ""
}
