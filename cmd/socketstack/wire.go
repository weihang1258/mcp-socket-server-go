package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
		UpgradeRepo: cfg.MCP.UpgradeRepo, UpgradeMirror: cfg.MCP.UpgradeMirror,
		LogLevel: cfg.MCP.LogLevel, AuditDays: cfg.MCP.AuditRetentionDays,
		Whitelist:      cfg.MCP.CmdExecWhitelist,
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
		UpgradeRepo: cfg.MCP.UpgradeRepo, UpgradeMirror: cfg.MCP.UpgradeMirror,
		LogLevel: cfg.MCP.LogLevel, AuditDays: cfg.MCP.AuditRetentionDays,
		Whitelist: cfg.MCP.CmdExecWhitelist, DefaultTimeout: cfg.MCP.DefaultTimeout,
	})
	if err := mcpbridge.RunStdio(context.Background(), b); err != nil {
		fmt.Fprintln(os.Stderr, "mcp 失败:", err)
		os.Exit(1)
	}
}

// installSelf 部署二进制 + 装并启动单元（agent；--with-mcp 额外装 mcp）。
//
// 全机只落**一份**二进制：versions/<版本>/socket_server 是真身，current 软链
// 指向它，/usr/local/bin/socketstack 再软链到 current/socket_server。
// 以前 /usr/local/bin 存的是第二份独立拷贝，升级后两处会漂移，
// 每次发版也得手工装两遍。
func installSelf(withMCP bool) error {
	if err := svcEnsureDirs(); err != nil {
		return err
	}
	if err := seedInitialVersion(); err != nil {
		return err
	}
	if err := linkCLI(); err != nil {
		return err
	}
	// 系统依赖 best-effort（与 Python install.sh 同策略）：失败仅告警不中断。
	// 启动服务之前装，这样 agent 起来时 ethtool/拨测库已经就位。
	for _, w := range installDeps() {
		fmt.Fprintln(os.Stderr, "警告:", w)
	}
	if err := svcAgentEnable(); err != nil {
		return err
	}
	// 装完即能用，且新二进制必须真的生效。只用 start 不够：单元本来就 active
	// 时 start 是空操作，进程继续跑被 rename 替换掉的旧 inode——真机实测
	// /proc/<pid>/exe 指向 "(deleted)"，日志停在装之前那个时刻。
	if err := svcAgentRestartFn(); err != nil {
		return err
	}
	fmt.Println("agent 单元已启用并启动")
	if withMCP {
		if err := svcMCPInstall(); err != nil {
			return err
		}
		if err := svcMCPRestartFn(); err != nil {
			return err
		}
		fmt.Println("mcp 单元已启用并启动（同机调试；标准部署请分机安装）")
	}
	return nil
}

// currentVersion 当前安装版本号（安装路径与 softlink 目标的一环）。
func currentVersion() string { return agent.Version }

// linkCLI 把 /usr/local/bin/socketstack 做成指向 current/socket_server 的软链。
// 旧布局留下的真文件（第二份拷贝）先删掉再建链。
func linkCLI() error {
	if err := os.MkdirAll(filepath.Dir(svcBinPath), 0o755); err != nil {
		return err
	}
	if err := os.Remove(svcBinPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("移除旧入口 %s 失败: %w", svcBinPath, err)
	}
	return os.Symlink(filepath.Join(svcVersionsDir, "current", "socket_server"), svcBinPath)
}

// seedInitialVersion 把**当前运行的二进制自身**落盘为该版本的真身，并原子切
// current 指向它。
//
// 覆盖语义：已有目录/current 也照样覆盖——`install` 是「装或覆盖修复」的唯
// 一入口（Python 版 install.sh 同样行为），早退会让新二进制悄悄丢掉。
// 必须落自身（os.Executable）：/usr/local/bin 是指向 current 的软链，首次
// 安装时悬空，读它只会得到 ENOENT。
//
// 版本切换的**另一条路**是 dt20 中央推送（finalizePushedVersion + switchTo），
// 那条路写的是别的版本目录，二者互不干扰。
func seedInitialVersion() error {
	self, err := exePathFn()
	if err != nil {
		return err
	}
	vdir := filepath.Join(svcVersionsDir, agent.Version)
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		return err
	}
	// 先写临时文件再 rename：install 时进程可能正从旧 inode 运行，
	// 直接截断写入会让正在跑的进程拿到半截文件。
	tmpBin := filepath.Join(vdir, ".socket_server.tmp")
	if err := copyFileTo(self, tmpBin); err != nil {
		return err
	}
	if err := os.Rename(tmpBin, filepath.Join(vdir, "socket_server")); err != nil {
		return err
	}
	cur := filepath.Join(svcVersionsDir, "current")
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
	// PATH 入口是指向 current 的软链，current 一删就悬空——留着只会让
	// 用户敲 socketstack 得到 "No such file or directory"。
	if err := os.Remove(svcBinPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("移除入口 %s 失败: %w", svcBinPath, err)
	}
	return nil
}

// statusReport 一屏给出「程序在哪、日志在哪、跑没跑」。
func statusReport() string {
	var b strings.Builder
	fmt.Fprintf(&b, "版本      : v%s\n", agent.Version)
	fmt.Fprintf(&b, "agent 服务: %s (%s.service)\n", activeText(svcAgentActive()), svc.ServiceName)
	fmt.Fprintf(&b, "mcp 服务  : %s (%s.service)\n", activeText(svcMCPActive()), svc.MCPService)
	b.WriteString("\n路径\n")
	fmt.Fprintf(&b, "  入口 (CLI)   %s -> %s/current/socket_server\n", svcBinPath, svcVersionsDir)
	fmt.Fprintf(&b, "  当前版本目录 %s/current/socket_server\n", svcVersionsDir)
	fmt.Fprintf(&b, "  旧键配置     %s\n", svc.ConfigPath)
	fmt.Fprintf(&b, "  新配置       %s\n", configPath)
	fmt.Fprintf(&b, "  数据/数据库  /var/lib/socketstack\n")
	b.WriteString("\n日志\n")
	b.WriteString("  agent  tail -f /var/log/socket_server.log\n")
	b.WriteString("  mcp    journalctl -u socketstack-mcp -f\n")
	// 拨测依赖预检：缺库时只会在首次 boce_run 炸，且报的是 .so 名，
	// 装包还得人工反查包名。这里提前点破并给出可复制的命令。
	if diag := chromiumDepsDiag(); diag != "" {
		b.WriteString("\n拨测依赖（chromium）\n")
		b.WriteString(diag)
	}
	return b.String()
}

// lddFn 测试注入点。
var lddFn = func(path string) ([]byte, error) { return exec.Command("ldd", path).Output() }

// chromiumDepsDiag 探测 chromium 缺失的运行期库；正常或未装 chromium 时返回空。
func chromiumDepsDiag() string {
	chrome := agent.ChromiumPath()
	if fi, err := os.Stat(chrome); err != nil || fi.IsDir() {
		return "" // 未下载 chromium 不算问题（首次 boce 才会下）
	}
	out, err := lddFn(chrome)
	if err != nil {
		return ""
	}
	missing := svc.MissingLibsFromLdd(string(out))
	if len(missing) == 0 {
		return "  正常\n"
	}
	pm := svc.DetectPkgManager()
	var b strings.Builder
	fmt.Fprintf(&b, "  缺 %d 个库（boce_run 会失败）: %s\n", len(missing), strings.Join(missing, ", "))
	if pm != "" {
		fmt.Fprintf(&b, "  修复: sudo %s\n", svc.InstallDepsCommand(pm, svc.ChromiumDepPackages()))
	}
	return b.String()
}

func activeText(ok bool) string {
	if ok {
		return "active"
	}
	return "inactive"
}

// svc 薄转发（便于测试注入）。
var (
	svcBinPath        = "/usr/local/bin/socketstack"
	svcVersionsDir    = "/opt/socket/versions"
	svcEnsureDirs     = svc.EnsureDirs
	svcAgentEnable    = svc.AgentEnable
	svcAgentStart     = svc.AgentStart
	svcAgentRestartFn = svc.AgentRestart
	svcAgentDisable   = svc.AgentDisable
	svcAgentActive    = svc.AgentActive
	svcMCPInstall     = svc.MCPInstall
	svcMCPStart       = svc.MCPStart
	svcMCPRestartFn   = svc.MCPRestart
	svcMCPDisable     = svc.MCPDisable
	svcMCPActive      = svc.MCPActive
	installDeps       = svc.InstallDeps
	// exePathFn 取自身可执行文件路径（测试替换，避免依赖真实的 /proc/self/exe）。
	exePathFn = func() (string, error) { return os.Executable() }
)

// CLI 分派可注入点（测试用）。
var (
	svcDispatchFn = svcDispatch
	runMCPServeFn = func() { runMCPServe(loadCfg()) }
	runMCPStdioFn = runMCPStdio
)

// agent 启动编排的可注入点（测试替换，避免触碰真实 /opt/socket 与环境）。
var (
	setupEnv         = agent.SetupEnvironment
	readHTTPPort     = agent.ReadHTTPPort
	startHTTPFile    = agent.StartHTTPFileServer
	prefetchChromium = agent.PrefetchChromium
)

// agentSetAutoupgrade 写 /opt/socket/config 的 autoupgrade 键（转发 agent 包）。
func agentSetAutoupgrade(state string) error {
	return agent.SetAutoupgrade(state)
}
