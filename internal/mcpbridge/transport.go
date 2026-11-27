// 传输（transport.py 移植）：stdio（本地）+ Streamable HTTP（:PORT/mcp）。
// DNS rebinding 保护关闭对齐 Python（内网信任，设计 §1 非目标）。
package mcpbridge

import (
	"context"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ServerInstructions 服务级说明：客户端在 initialize 时拿到，作为独立的
// MCP instructions 块交给模型。这是「这组工具管什么」的唯一服务级入口——
// 45 个子工具描述装不下整体认知，没有它模型只知道有一堆 file_get/shell_exec，
// 不知道该在什么场景想起来。
//
// 写作原则：
//   - 只说自己是什么（远程主机操作），不说别的工具该用什么——harness 各不相同，
//     内置工具集不在本服务管辖范围内。
//   - 列全 12 类能力 + 触发关键词：ToolSearch 只做字面量匹配，模型得先想到
//     对应的词才搜得到。
const ServerInstructions = `操作**远程主机**（靶机/服务器/设备）：socket_server 协议连远端执行命令、传文件、
抓包、流量回放、DPI 设备管理。所有操作发生在被连接的机器上，不是本机。

【12 类 48 个工具】1 登记 target_list/target_add/target_remove；2 命令 shell_exec；
3 文件 file_get/file_put/file_stat/file_list/file_mkdir/file_remove/file_unzip/file_transfer_hint；
4 网络 net_route/net_set_mtu/net_set_time；5 抓包 capture_start/capture_stop；6 回放 replay_run；
7 流分析 pcap_extract_flows；8 收流 listen_start/listen_fetch/listen_save/listen_clean/listen_stop；
9 拨测 probe_visit；10 桥自身 bridge_version/bridge_upgrade；11 IP 段 ip_db_load/ip_lookup；
12 DPI：dpi_get_info/dpi_service/dpi_agent_service/dpi_switch_mode/dpi_apply_config/dpi_get_config/
dpi_read_stat/dpi_wait_stat/dpi_wait_file/dpi_check_stalled/dpi_policy_get/dpi_policy_put/dpi_policy_write/
dpi_policy_wait/dpi_clean_stat/dpi_backup/dpi_prepare_package/dpi_install/dpi_upgrade。
远程/靶机/抓包/pcap/回放/打流/收流/传文件到远端/DPI/策略下发/封堵/拨测/IP 方向判定——想到这些词就搜本服务；
各工具时机与入参见其自身 description。

【典型序列】target_list→target_add；抓包 net_route→capture_start→业务流量→capture_stop→file_get；
回放 file_put→replay_run（同机抓包回放互斥）；收流 listen_start→listen_fetch/save→listen_stop；
DPI dpi_get_info→dpi_prepare_package→dpi_install/dpi_upgrade→dpi_get_info 复核。

【结果约定】统一信封 {ok,total,results[],failed[]}；failed[] 含 target/reason/error_type（network|timeout|business）；
timeout 可能带 cleanup{killed,verified}，verified=false=未确认远端进程退出，勿假定环境已释放。
多台主机 targets 数组或 @tag 标签；不可逆（file_remove/dpi_install/dpi_upgrade/dpi_switch_mode）先确认。`

// NewServer 构建 mcp.Server（serverInfo.version = 桥版本——工具面/说明面变更升版本，与 dt14 分离）。
func NewServer(b *Bridge) *mcp.Server {
	impl := &mcp.Implementation{Name: "mcp-socket-server", Version: BridgeVersion}
	s := mcp.NewServer(impl, &mcp.ServerOptions{Instructions: ServerInstructions})
	b.RegisterTools(s)
	return s
}

// RunStdio 本地 stdio 模式（阻塞）。
func RunStdio(ctx context.Context, b *Bridge) error {
	s := NewServer(b)
	return s.Run(ctx, &mcp.StdioTransport{})
}

// listenAddrs MCP HTTP 监听地址列表（2026-11-02：所有监听端口 0.0.0.0 双栈）。
// host 为 IPv4 通配时补 [::] 一条（tcp4/tcp6 分开绑——net.Listen("tcp","0.0.0.0:p")
// 实际生成 AF_INET6 通配，直接叠加会 EADDRINUSE）；其余 host 原样单条。
func listenAddrs(host string, port int) []string {
	p := strconv.Itoa(port)
	if host == "0.0.0.0" {
		return []string{net.JoinHostPort("0.0.0.0", p), net.JoinHostPort("::", p)}
	}
	return []string{net.JoinHostPort(host, p)}
}

// RunStreamableHTTP Streamable HTTP（端点 /mcp），绑定 cfg host:port（阻塞）。
// host 为 IPv4 通配时双栈：v6 绑定失败降级仅 v4（与 agent :9000/:9001 同策略）。
func RunStreamableHTTP(ctx context.Context, b *Bridge, host string, port int) error {
	s := NewServer(b)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true}) // 对齐 Python 显式关闭 rebinding 保护
	// WithSourceIP 必须在 handler 外层：go-sdk 用 req.Context() 建会话，
	// 中间件注入的值才能传到工具 handler（streamable.go:700）。
	srv := &http.Server{Handler: WithSourceIP(handler)}
	addrs := listenAddrs(host, port)
	network := "tcp4"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "tcp6" // 具体 IPv6 地址（::1 等）不能用 tcp4；双栈通配仍显式分绑
	}
	ln, err := net.Listen(network, addrs[0])
	if err != nil {
		return err
	}
	if len(addrs) == 2 {
		if ln6, err6 := net.Listen("tcp6", addrs[1]); err6 == nil {
			defer ln6.Close()
			go srv.Serve(ln6) //nolint:errcheck // Serve 在 Close 后返回 ErrServerClosed
			log.Printf("MCP Streamable HTTP 监听 %s/mcp (IPv6, 双栈)", addrs[1])
		} else {
			log.Printf("MCP Streamable HTTP IPv6 监听失败:%v,降级为仅 IPv4 模式", err6)
		}
	}
	log.Printf("MCP Streamable HTTP 监听 %s/mcp (log_level=%s)", addrs[0], b.Cfg.LogLevel)
	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
