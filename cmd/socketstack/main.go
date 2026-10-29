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
			case "start", "stop", "status", "enable", "disable":
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
		runUninstall()
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
	fmt.Printf("socketstack agent listening %s (dt14 v%s)\n", addr, agent.Version)
	select {} // 前台阻塞运行（systemd/信号管理生命周期）
}

// startAgent 启动 :9001（失败仅 warn）+ :9000 双栈阻塞监听。
// 返回 listener 与地址；stop 关闭全部。
func startAgent(cfg config.Config, testMode bool) (ln interface{}, addr string, stop func()) {
	if !testMode {
		agent.SetupEnvironment()
	}
	// :9001 必须先于阻塞的 TCP 主循环（http_port 读 /opt/socket/config；0=关闭）
	if !testMode {
		httpPort := agent.ReadHTTPPort()
		agent.StartHTTPFileServer(httpPort) // 失败仅 warn，不影响 :9000
	}
	tcpLn, err := netListen(strconv.Itoa(cfg.Agent.TCPPort))
	if err != nil {
		return nil, "", func() {}
	}
	go agent.Serve(tcpLn)
	return tcpLn, tcpLn.Addr().String(), func() { tcpLn.Close() }
}

func runMCP(args []string) {
	if len(args) > 0 && args[0] == "serve" {
		cfg := loadCfg()
		runMCPServe(cfg)
		return
	}
	runMCPStdio()
}

func runInstall(args []string) {
	withMCP := false
	for _, a := range args {
		if a == "--with-mcp" {
			withMCP = true
		}
	}
	if err := installSelf(withMCP); err != nil {
		fmt.Fprintln(os.Stderr, "install 失败:", err)
		os.Exit(1)
	}
	fmt.Println("install 完成" + map[bool]string{true: "（含 mcp 单元）", false: ""}[withMCP])
}

func runUninstall() {
	if err := uninstallSelf(); err != nil {
		fmt.Fprintln(os.Stderr, "uninstall 失败:", err)
		os.Exit(1)
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
