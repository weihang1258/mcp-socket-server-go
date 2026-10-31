// socketstack 合体二进制入口（设计 §0/§8）：
//
//	socketstack               # mcp stdio（本地 MCP 客户端）
//	socketstack mcp serve     # Streamable HTTP（mcp 单元唯一入口）
//	socketstack agent | serve # agent 模式（serve = agent 别名，升级互操作 §8）
//	socketstack install [--with-mcp] | uninstall
//	socketstack agent|mcp start|stop|status|enable|disable
//	socketstack agent autoupgrade on|off
//
// 开关权威 = systemd 双单元；子命令不读任何 enabled 键。
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/weihang1258/mcp-socket-server-go/internal/agent"
	"github.com/weihang1258/mcp-socket-server-go/internal/config"
	"github.com/weihang1258/mcp-socket-server-go/internal/svc"
)

const agentUsage = `socketstack — socket_server(agent) + mcp_socket_server(mcp) 合体

用法:
  socketstack                     mcp stdio 模式（本地接入）
  socketstack mcp serve           MCP Streamable HTTP :9010/mcp
  socketstack agent               agent 模式（:9000 + :9001）
  socketstack serve               agent 模式别名（旧 unit 兼容入口）
  socketstack install [--with-mcp]
  socketstack uninstall
  socketstack deps install-browser  安装浏览器拨测（boce）所需 chromium 运行库
  socketstack status              一屏看版本/服务状态/路径/日志
  socketstack agent|mcp start|stop|status|enable|disable
  socketstack agent autoupgrade on|off
  socketstack version`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		runMCPStdio()
		return
	}
	switch args[0] {
	case "serve": // serve = agent 别名（Python unit ExecStart 兼容）
		runAgent(args[1:])
	case "agent":
		if len(args) > 1 {
			switch args[1] {
			case "start", "stop", "restart", "status", "enable", "disable":
				svcDispatch("agent", args[1])
				return
			case "autoupgrade":
				if len(args) < 3 || (args[2] != "on" && args[2] != "off") {
					fmt.Fprintln(os.Stderr, "用法: socketstack agent autoupgrade on|off")
					os.Exit(2)
				}
				if err := agentSetAutoupgrade(args[2]); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				fmt.Printf("自动升级已%s\n", map[string]string{"on": "开启", "off": "关闭"}[args[2]])
				return
			}
		}
		runAgent(args[1:])
	case "mcp":
		runMCP(args[1:])
	case "install":
		runInstall(args[1:])
	case "uninstall":
		runUninstall(args[1:])
	case "deps":
		runDeps(args[1:])
		return
	case "status":
		fmt.Print(statusReport())
	case "version", "-v", "--version":
		fmt.Printf("socketstack v%s\n", agent.Version)
	case "-h", "--help", "help":
		fmt.Println(agentUsage)
	default:
		fmt.Fprintln(os.Stderr, "未知命令: "+args[0])
		fmt.Println(agentUsage)
		os.Exit(2)
	}
}

const configPath = "/etc/socketstack/config.yaml"

func loadCfg() config.Config { return config.Load(configPath) }

// runAgent agent 前台模式（serve 编排顺序：自愈 → :9001 → TCP）。
func runAgent(args []string) {
	cfg := loadCfg()
	testMode := os.Getenv("SOCKETSTACK_TEST_MODE") == "1"
	if !testMode {
		svc.EnsureUnitCorrect() // 自愈（失败仅 warn 不阻断）
	}
	ln, addr, stop := startAgent(cfg, testMode)
	if ln == nil {
		fmt.Fprintln(os.Stderr, "agent 启动失败: 端口监听失败", addr)
		os.Exit(1)
	}
	defer stop()
	if !testMode {
		go agent.PruneAtStartup() // 异步：慢盘不拖监听建立；升级后的自动重启即触发
	}
	fmt.Printf("socketstack agent listening %s (dt14 v%s)\n", addr, agent.Version)
	select {} // 前台阻塞运行（systemd/信号管理生命周期）
}

// startAgent 启动 :9001（失败仅 warn）+ :9000 双栈阻塞监听。
// 返回 listener 与地址；stop 关闭全部。
func startAgent(cfg config.Config, testMode bool) (ln interface{}, addr string, stop func()) {
	if !testMode {
		setupEnv()
	}
	// :9001 必须先于阻塞的 TCP 主循环（http_port 读 /opt/socket/config；0=关闭）
	if !testMode {
		httpPort := readHTTPPort()
		startHTTPFile(httpPort) // 失败仅 warn，不影响 :9000
		// chromium 后台预取：默认关闭（内网靶机连不上 npmmirror，无条件预取会让每次
		// 重启白跑一次 536MB 下载，而 Python 是「用到才触发」）。能上外网的部署在
		// config.yaml 里设 agent.chromium_prefetch: true，即可消除「首次 boce 被
		// timeout+10(130s) 判死」。
		if cfg.Agent.ChromiumPrefetch {
			prefetchChromium()
		}
	}
	tcpLn, err := netListen(strconv.Itoa(cfg.Agent.TCPPort))
	if err != nil {
		return nil, "", func() {}
	}
	go agent.Serve(tcpLn)
	return tcpLn, tcpLn.Addr().String(), func() { tcpLn.Close() }
}

// mcpAction 判定 mcp 子命令动作：serve / 单元操作 / stdio / help。
//
// `mcp --help` 不能掉进 stdio——那会阻塞在读 stdin 上，用户以为卡死。
func mcpAction(args []string) string {
	if len(args) == 0 {
		return "stdio"
	}
	switch args[0] {
	case "serve":
		return "serve"
	case "start", "stop", "status", "enable", "disable":
		return "svc:" + args[0]
	case "-h", "--help", "help":
		return "help"
	}
	return "stdio"
}

func runMCP(args []string) {
	act := mcpAction(args)
	switch {
	case act == "serve":
		runMCPServeFn()
	case act == "help":
		fmt.Println(agentUsage)
	case strings.HasPrefix(act, "svc:"):
		svcDispatchFn("mcp", strings.TrimPrefix(act, "svc:"))
	default:
		runMCPStdioFn()
	}
}

// installUsage install 子命令的用法（认识参数时才打印）。
const installUsage = `用法: socketstack install [--with-mcp]

  --with-mcp  同时安装并启动 mcp 单元（同机调试用；标准部署请分机安装）`

// parseInstallArgs 解析 install 参数，返回 (withMCP, 动作)。
//
// 动作非空表示**不要安装**：help = 用户要用法，unknown = 参数不认识。
// 以前是「遍历挑出 --with-mcp，其余静默丢弃」，于是 `install --help` 会真的
// 执行安装并重启服务——客户端反馈的「连接被断」很大一部分就来自这里。
func parseInstallArgs(args []string) (bool, string) {
	withMCP, act := false, ""
	for _, a := range args {
		switch a {
		case "--with-mcp":
			withMCP = true
		case "-h", "--help", "help":
			if act == "" {
				act = "help"
			}
		default:
			act = "unknown"
		}
	}
	return withMCP, act
}

// depsUsage deps 子命令用法。
const depsUsage = `用法: socketstack deps install-browser

安装浏览器拨测（boce_run 浏览器模式）所需的 chromium 运行库。
默认 install 不安装任何系统包；只有需要浏览器拨测的机器才执行本命令。
安装失败以非 0 退出。`

// runDeps deps 子命令：目前唯一动作 install-browser。严格解析，
// 与 install/uninstall 同约定（help 退 0、未知参数退 2、均不执行）。
// help 在任何位置都生效（验收实测 `deps install-browser --help` 曾退 2）。
func runDeps(args []string) {
	sawHelp, sawRun := false, false
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			sawHelp = true
		case "install-browser":
			sawRun = true
		default:
			fmt.Fprintln(os.Stderr, "deps: 未知参数 "+a+"\n"+depsUsage)
			exitFn(2)
			return
		}
	}
	switch {
	case sawHelp:
		fmt.Println(depsUsage)
		return
	case sawRun:
	default: // 空参数
		fmt.Fprintln(os.Stderr, "deps: 未指定动作\n"+depsUsage)
		exitFn(2)
		return
	}
	if err := installBrowserDepsFn(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitFn(1)
		return
	}
	fmt.Println("浏览器依赖已安装")
}

func runInstall(args []string) {
	withMCP, act := parseInstallArgs(args)
	switch act {
	case "help":
		fmt.Println(installUsage)
		return
	case "unknown":
		fmt.Fprintln(os.Stderr, "install: 未知参数\n"+installUsage)
		exitFn(2)
		return // exitFn 生产实现会退出；可注入实现不会，必须显式返回
	}
	if err := installSelfFn(withMCP); err != nil {
		fmt.Fprintln(os.Stderr, "install 失败:", err)
		exitFn(1)
	}
	fmt.Println("install 完成" + map[bool]string{true: "（含 mcp 单元）", false: ""}[withMCP])
}

// uninstallUsage uninstall 子命令的用法。
const uninstallUsage = `用法: socketstack uninstall

停用并删除 agent / mcp 单元，移除 current 软链与 PATH 入口。
/opt/socket/versions、配置与 mcp 数据库保留。`

// parseNoArgCommand 解析「不带任何有效参数」的子命令（uninstall）。
// 返回 run / help / unknown。help 与 unknown 都不得执行实际操作——
// 卸载会 disable 单元、删 current 软链，误执行代价比安装大得多。
func parseNoArgCommand(args []string) string {
	act := "run"
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			if act == "run" {
				act = "help"
			}
		default:
			act = "unknown"
		}
	}
	return act
}

func runUninstall(args []string) {
	switch parseNoArgCommand(args) {
	case "help":
		fmt.Println(uninstallUsage)
		return
	case "unknown":
		fmt.Fprintln(os.Stderr, "uninstall: 未知参数\n"+uninstallUsage)
		exitFn(2)
		return // 同上：注入的 exitFn 不退出时必须显式返回，否则照样会卸载
	}
	if err := uninstallSelfFn(); err != nil {
		fmt.Fprintln(os.Stderr, "uninstall 失败:", err)
		exitFn(1)
	}
	fmt.Println("uninstall 完成（/opt/socket/versions、配置与 mcp DB 保留）")
}

// svcDispatch agent|mcp 单元操作。
func svcDispatch(target, action string) {
	var err error
	switch {
	case target == "agent" && action == "start":
		err = svc.AgentStart()
	case target == "agent" && action == "stop":
		err = svc.AgentStop()
	case target == "agent" && action == "restart":
		err = svcAgentRestartFn()
	case target == "agent" && action == "enable":
		err = svc.AgentEnable()
	case target == "agent" && action == "disable":
		err = svc.AgentDisable()
	case target == "agent" && action == "status":
		fmt.Printf("socket_server.service: %v\n", svc.AgentActive())
		return
	case target == "mcp" && action == "start":
		err = svc.MCPStart()
	case target == "mcp" && action == "stop":
		err = svc.MCPStop()
	case target == "mcp" && action == "enable":
		err = svc.MCPInstall()
	case target == "mcp" && action == "disable":
		err = svc.MCPDisable()
	case target == "mcp" && action == "status":
		fmt.Printf("socketstack-mcp.service: %v\n", svc.MCPActive())
		return
	default:
		fmt.Fprintln(os.Stderr, "未知操作:", action)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
