// 审计来源 IP（P3-1）。原先 tools.go 三处硬编码 "internal"，
// 出事后无从追溯是谁调的工具。
//
// 关键：go-sdk 的 StreamableHTTP handler 用 req.Context() 建会话（见
// streamable.go:700 "Pass req.Context() here, to allow middleware to add
// context values"），所以外层包一个 middleware 把来源写进 context 即可，
// 工具 handler 的 ctx 里就能取到。
package mcpbridge

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type sourceIPKey struct{}

// withSourceIP 把已归一化的来源写进 context。
func withSourceIP(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, sourceIPKey{}, normalizeRemoteAddr(addr))
}

// sourceIPFromCtx 取来源；无值（stdio 模式）回退 "internal"。
func sourceIPFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(sourceIPKey{}).(string); ok && v != "" {
		return v
	}
	return "internal"
}

// normalizeRemoteAddr "10.1.2.3:5678" → "10.1.2.3"；"[fd00::5]:80" → "fd00::5"。
func normalizeRemoteAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return strings.Trim(addr, "[]")
}

// clientIP 取调用方 IP：X-Forwarded-For 首个地址优先（反代场景），否则 RemoteAddr。
func clientIP(remoteAddr, xff string) string {
	if s := strings.TrimSpace(xff); s != "" {
		first := s
		if i := strings.IndexByte(s, ','); i >= 0 {
			first = strings.TrimSpace(s[:i])
		}
		if first != "" {
			return normalizeRemoteAddr(first)
		}
	}
	return normalizeRemoteAddr(remoteAddr)
}

// WithSourceIP 中间件：把调用方 IP 注入请求 context。
func WithSourceIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"))
		next.ServeHTTP(w, r.WithContext(withSourceIP(r.Context(), ip)))
	})
}
