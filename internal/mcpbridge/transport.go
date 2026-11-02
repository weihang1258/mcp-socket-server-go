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

// NewServer 构建 mcp.Server（serverInfo.version = 桥版本 0.4.0，与 dt14 分离）。
func NewServer(b *Bridge) *mcp.Server {
	impl := &mcp.Implementation{Name: "mcp-socket-server", Version: BridgeVersion}
	s := mcp.NewServer(impl, nil)
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
