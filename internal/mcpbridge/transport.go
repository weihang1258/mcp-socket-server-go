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
// MCP instructions 块交给模型。这是「这组工具管什么、和内置工具怎么分工」
// 的唯一服务级入口——45 个子工具描述装不下整体认知，没有它模型只知道
// 有一堆 file_get/shell_exec，不知道该在什么场景想起来。
const ServerInstructions = `这组工具用于操作**远程靶机**（通过 socket_server 协议连接），不是本地机器。

【与内置工具的分工】
- 本地文件：用内置 Read / Write / Glob / Grep，不要用 file_get / file_put。
- 本地命令：用内置 Bash，不要用 shell_exec。
- 远程靶机上的文件与命令：用本组工具（file_* / shell_exec）。
- 判据：路径或命令要在另一台机器上执行时，才用本组工具。

【典型调用序列】
- 第一次接触靶机：target_list 看有哪些 → target_add 登记新机器（会先探活）。
- 执行远程命令：shell_exec（args 是完整命令字符串）。
- 传文件：file_put 上传 → shell_exec chmod +x → 执行；回传用 file_get。
- 抓包分析：net_route 确认网卡 → capture_start → 跑业务流量 → capture_stop → file_get 取回 pcap。
- 回放对比：file_put 传 pcap → replay_run；要同时抓包请用另一台靶机（同机互斥）。
- 端口收流：listen_start → 业务流量 → listen_fetch（回桥侧）或 listen_save（留靶机）→ listen_stop。
- DPI 设备：dpi_get_info 看现状 → dpi_prepare_package → dpi_install / dpi_upgrade → dpi_get_info 复核。

【结果约定】
所有工具返回统一信封：{ok, total, results[], failed[]}。
- results[].data 是该工具的具体结果，字段含义见各工具 outputSchema。
- failed[] 每项含 target / reason / error_type（network | timeout | business）。
- error_type=timeout 时可能带 cleanup{killed,verified}；verified 为 false 表示
  无法确认靶机上的进程已退出，不要假定环境已释放。

【注意】
- 工具名不带服务前缀，但都属于本服务；多台靶机用 targets 传数组，或 @tag 按标签批量选。
- 涉及不可逆操作（file_remove / dpi_install / dpi_upgrade）时，先确认路径和目标。`

// NewServer 构建 mcp.Server（serverInfo.version = 桥版本 0.4.0，与 dt14 分离）。
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
