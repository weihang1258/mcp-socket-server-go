// 传输（transport.py 移植）：stdio（本地）+ Streamable HTTP（:PORT/mcp）。
// DNS rebinding 保护关闭对齐 Python（内网信任，设计 §1 非目标）。
package mcpbridge

import (
	"context"
	"fmt"
	"log"
	"net/http"

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

// RunStreamableHTTP Streamable HTTP（端点 /mcp），绑定 cfg host:port（阻塞）。
func RunStreamableHTTP(ctx context.Context, b *Bridge, host string, port int) error {
	s := NewServer(b)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("MCP Streamable HTTP 监听 %s/mcp (log_level=%s)", addr, b.Cfg.LogLevel)
	srv := &http.Server{Addr: addr, Handler: handler}
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
