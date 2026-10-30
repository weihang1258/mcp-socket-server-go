// Package svc systemd 单元管理（设计文档 §8）。
//
// 互操作铁律：agent 单元沿用 Python socket_server.service（路径/模板逐字一致），
// Go CLI 接受裸 serve 别名 → 旧 unit 可直接拉起 Go 二进制、回滚不断裂。
// systemctl 操作是薄包装（root 执行）；单元测试只覆盖纯函数（模板/路径/config 初始化）。
package svc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
	if err := writeUnitFile(path, content); err != nil {
		return fmt.Errorf("写入 %s 需要 root 权限: %w", path, err)
	}
	return systemctl("daemon-reload")
}

// 单元备份：覆写前留副本。写坏一个 unit 没有副本就只能重装整机。
const (
	bakPrefix      = ".bak."
	bakGlob        = bakPrefix + "*"
	maxUnitBackups = 3
)

var timeNowFn = time.Now // 测试可注入

// writeUnitFile 覆写单元文件；内容未变则跳过，有旧内容则先备份。
//
// 不备份会怎样：WriteUnit 是 O_TRUNC 直写，改坏 ExecStart 后机器重启就起不来，
// 而 /etc/systemd/system 下的原文件已经没了。
func writeUnitFile(path, content string) error {
	old, readErr := os.ReadFile(path)
	hadOld := readErr == nil
	if hadOld && string(old) == content {
		return nil
	}
	if !hadOld && !errors.Is(readErr, fs.ErrNotExist) {
		// 存在但读不到（EACCES/EISDIR…）：不能当作「没有旧文件」直接覆写，
		// 那样等于无备份地把读不到的内容冲掉。
		return readErr
	}
	bak := ""
	if hadOld {
		// 时间戳用固定宽度的零填充，避免不同纳秒位数时字符串排序错乱
		bak = path + bakPrefix + fmt.Sprintf("%019d", timeNowFn().UnixNano())
		if err := os.Rename(path, bak); err != nil {
			// 备份没建成就不覆写：否则「写坏可回滚」在这条路径上根本不成立，
			// 而用户还以为有备份。
			return fmt.Errorf("备份 %s 失败，已放弃覆写: %w", path, err)
		}
		pruneUnitBackups(path)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		// 写失败时还原刚建的那一份（精确路径，不靠文件名排序猜）
		if bak != "" {
			if rerr := os.Rename(bak, path); rerr != nil {
				return fmt.Errorf("写入失败且还原失败（unit 可能在 %s，请手动移回）: %v: %w", bak, rerr, err)
			}
		}
		return err
	}
	return nil
}

// pruneUnitBackups 只留最近 maxUnitBackups 份（文件名里的纳秒时间戳保证可排序）。
func pruneUnitBackups(path string) {
	m, _ := filepath.Glob(path + bakGlob)
	if len(m) <= maxUnitBackups {
		return
	}
	sort.Strings(m)
	for _, f := range m[:len(m)-maxUnitBackups] {
		os.Remove(f)
	}
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
func MCPRestart() error { return systemctl("restart", MCPService) }
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
