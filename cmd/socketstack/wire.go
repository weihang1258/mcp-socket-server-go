package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/weihang1258/mcp-socket-server-go/internal/agent"
	"github.com/weihang1258/mcp-socket-server-go/internal/config"
	"github.com/weihang1258/mcp-socket-server-go/internal/mcpbridge"
	"github.com/weihang1258/mcp-socket-server-go/internal/svc"
)

// netListen 双栈监听（agent :9000：tcp4 通配必成 + tcp6 尽力降级）。
// 返回组合 listener；v6 由独立 goroutine 服务。
func netListen(port string) (net.Listener, error) {
	ln4, err := net.Listen("tcp4", "0.0.0.0:"+port)
	if err != nil {
		return nil, err
	}
	if ln6, err := net.Listen("tcp6", "[::]:"+port); err == nil {
		go agent.Serve(ln6) // v6 复用同一处理循环
	}
	return ln4, nil
}

// runMCPServe Streamable HTTP（mcp 单元 ExecStart 唯一入口）。
func runMCPServe(cfg config.Config) {
	b := mcpbridge.Init(mcpbridge.BridgeConfig{
		DBPath: cfg.MCP.DBPath, DownloadDir: cfg.MCP.DownloadDir, Proxy: cfg.MCP.Proxy,
		LogLevel: cfg.MCP.LogLevel, AuditDays: cfg.MCP.AuditRetentionDays,
		Whitelist: cfg.MCP.CmdExecWhitelist, BindHost: cfg.MCP.Bind.Host, BindPort: cfg.MCP.Bind.Port,
		DefaultTimeout: cfg.MCP.DefaultTimeout,
	})
	if err := mcpbridge.RunStreamableHTTP(context.Background(), b, cfg.MCP.Bind.Host, cfg.MCP.Bind.Port); err != nil {
		fmt.Fprintln(os.Stderr, "mcp serve 失败:", err)
		os.Exit(1)
	}
}

// runMCPStdio 本地 stdio（阻塞）。
func runMCPStdio() {
	cfg := loadCfg()
	b := mcpbridge.Init(mcpbridge.BridgeConfig{
		DBPath: cfg.MCP.DBPath, DownloadDir: cfg.MCP.DownloadDir, Proxy: cfg.MCP.Proxy,
		LogLevel: cfg.MCP.LogLevel, AuditDays: cfg.MCP.AuditRetentionDays,
		Whitelist: cfg.MCP.CmdExecWhitelist, DefaultTimeout: cfg.MCP.DefaultTimeout,
	})
	if err := mcpbridge.RunStdio(context.Background(), b); err != nil {
		fmt.Fprintln(os.Stderr, "mcp 失败:", err)
		os.Exit(1)
	}
}

// installSelf 复制自身到 /usr/local/bin/socketstack + 装 agent 单元（+ 可选 mcp 单元）。
// 首次部署：自身落盘 versions/<版本>/socket_server + current 软链（§8 布局）。
func installSelf(withMCP bool) error {
	if err := copySelf(); err != nil {
		return err
	}
	if err := svcEnsureDirs(); err != nil {
		return err
	}
	if err := seedInitialVersion(); err != nil {
		return err
	}
	if err := svcAgentEnable(); err != nil {
		return err
	}
	fmt.Println("agent 单元已启用")
	if withMCP {
		if err := svcMCPInstall(); err != nil {
			return err
		}
		fmt.Println("mcp 单元已启用（同机调试；标准部署请分机安装）")
	}
	return nil
}

func copySelf() error {
	src, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(svcBinPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("写 %s 需要 root: %w", svcBinPath, err)
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

// seedInitialVersion 无既有部署时把 /usr/local/bin 二进制作为当前版本落盘。
func seedInitialVersion() error {
	cur := filepath.Join(svcVersionsDir, "current")
	if fi, err := os.Stat(filepath.Join(cur, "socket_server")); err == nil && !fi.IsDir() {
		return nil
	}
	vdir := filepath.Join(svcVersionsDir, agent.Version)
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		return err
	}
	if err := copyFileTo(svcBinPath, filepath.Join(vdir, "socket_server")); err != nil {
		return err
	}
	tmp := cur + ".tmp"
	os.Remove(tmp)
	if err := os.Symlink(vdir, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, cur)
}

func copyFileTo(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func uninstallSelf() error {
	svcMCPDisable()
	svcAgentDisable()
	os.Remove(filepath.Join(svcVersionsDir, "current")) // 数据式卸载：保留 versions/配置/DB
	return nil
}

// svc 薄转发（便于测试注入）。
var (
	svcBinPath      = "/usr/local/bin/socketstack"
	svcVersionsDir  = "/opt/socket/versions"
	svcEnsureDirs   = svc.EnsureDirs
	svcAgentEnable  = svc.AgentEnable
	svcAgentDisable = svc.AgentDisable
	svcMCPInstall   = svc.MCPInstall
	svcMCPDisable   = svc.MCPDisable
)

var _ = errors.New
