package mcpbridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// P3-1：审计里的 source_ip 原先硬编码 "internal"，出事后无法追溯是谁调的。
// RunStreamableHTTP 外面包一层中间件把 r.RemoteAddr 放进 context，工具层取出来。
func TestSourceIPFromContext(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{"带端口的 IPv4", "10.12.131.35:54321", "10.12.131.35"},
		{"带方括号的 IPv6", "[fd00::5]:1234", "fd00::5"},
		{"裸地址", "10.1.2.3", "10.1.2.3"},
		{"空", "", ""},
	}
	for _, c := range cases {
		if got := normalizeRemoteAddr(c.addr); got != c.want {
			t.Errorf("%s: normalizeRemoteAddr(%q) = %q，期望 %q", c.name, c.addr, got, c.want)
		}
	}
}

// context 里没有来源地址时（stdio 模式）回退 "internal"，保持旧行为。
func TestSourceIPFallsBackToInternal(t *testing.T) {
	if got := sourceIPFromCtx(t.Context()); got != "internal" {
		t.Fatalf("无 context 值时应为 internal，实际 %q", got)
	}
}

// 中间件注入后，工具层能拿到真实来源。
func TestSourceIPRoundTrip(t *testing.T) {
	ctx := withSourceIP(t.Context(), "10.12.131.35:54321")
	if got := sourceIPFromCtx(ctx); got != "10.12.131.35" {
		t.Fatalf("应取到 10.12.131.35，实际 %q", got)
	}
}

// X-Forwarded-For 优先于 RemoteAddr（反代场景）。
func TestSourceIPPrefersForwardedFor(t *testing.T) {
	if got := clientIP("10.0.0.1:1234", "203.0.113.9, 10.0.0.1"); got != "203.0.113.9" {
		t.Fatalf("应取 XFF 首个地址，实际 %q", got)
	}
	if got := clientIP("10.0.0.1:1234", ""); got != "10.0.0.1" {
		t.Fatalf("无 XFF 时用 RemoteAddr，实际 %q", got)
	}
	// XFF 里塞垃圾不能变成空来源
	if got := clientIP("10.0.0.1:1234", "  "); got != "10.0.0.1" {
		t.Fatalf("XFF 空白应回退 RemoteAddr，实际 %q", got)
	}
}

// 端到端：中间件注入 → context → 审计落库。这条锁住「三处 audit 真的用了 ctx」，
// 而不只是 sourceip.go 的函数本身正确。
func TestAuditSourceIPAwareOfContext(t *testing.T) {
	db := filepath.Join(t.TempDir(), "audit.db")
	a, err := OpenAudit(db, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b := &Bridge{Audit: a}
	ctx := withSourceIP(context.Background(), "10.12.131.35:54321")
	b.writeAudit(ctx, "cmd_exec", map[string]any{"args": "id"},
		[]TargetResult{{Target: "t1", Ok: true}}, time.Now())

	got := a.LastEntry()
	if got == nil {
		t.Fatal("应有审计记录")
	}
	if got.SourceIP != "10.12.131.35" {
		t.Fatalf("审计应记录真实来源 IP，实际 %q", got.SourceIP)
	}
}

// stdio 模式没有 HTTP 来源，仍落 "internal"（与旧行为一致）。
func TestAuditSourceIPInternalWhenNoContext(t *testing.T) {
	db := filepath.Join(t.TempDir(), "audit2.db")
	a, err := OpenAudit(db, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b := &Bridge{Audit: a}
	b.writeAudit(context.Background(), "cmd_exec", map[string]any{"args": "id"},
		[]TargetResult{{Target: "t1", Ok: true}}, time.Now())

	if got := a.LastEntry(); got == nil || got.SourceIP != "internal" {
		t.Fatalf("无来源时应落 internal，实际 %+v", got)
	}
}

// 真实 HTTP 请求走完整链路：WithSourceIP 中间件 → 请求 context → handler 内可取。
// 这条锁住中间件的接线，而不只是 normalizeRemoteAddr 这类纯函数。
func TestWithSourceIPMiddlewareEndToEnd(t *testing.T) {
	var seen string
	h := WithSourceIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = sourceIPFromCtx(r.Context())
	}))
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.RemoteAddr = "10.12.131.35:54321"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "10.12.131.35" {
		t.Fatalf("中间件应注入来源 IP，handler 内取到 %q", seen)
	}
}

// 反代场景：X-Forwarded-For 优先。
func TestWithSourceIPMiddlewareHonorsXFF(t *testing.T) {
	var seen string
	h := WithSourceIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = sourceIPFromCtx(r.Context())
	}))
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "203.0.113.9" {
		t.Fatalf("应取 XFF 首个地址，实际 %q", seen)
	}
}

// 真链路：真 SDK Streamable HTTP 服务端 + WithSourceIP 中间件 + 真 SDK 客户端发
// 一次工具调用，断言审计里是调用方 IP。
//
// 上面两条测试只证明「中间件注入了」「writeAudit 会读 ctx」，都没证明 go-sdk
// 会把 req.Context() 一路传到工具 handler（transport.go 的注释就是这么假设的）。
// SDK 升级后这条传播链断掉，只有这条测试会红。
func TestSourceIPReachesAuditThroughRealSDK(t *testing.T) {
	b := newTestBridge(t)
	m := newMockServer(t, stdMockHandler(t))
	srv := NewServer(b)

	h := WithSourceIP(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatalf("客户端连接失败: %v", err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "cmd_exec",
		Arguments: map[string]any{"targets": []string{m.Addr}, "args": "id", "port": portOf(m.Addr)},
	})
	if err != nil {
		t.Fatalf("cmd_exec 调用失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("cmd_exec 返回错误: %+v", res.Content)
	}

	got := b.Audit.LastEntry()
	if got == nil {
		t.Fatal("应有审计记录")
	}
	// httptest 服务端看到的 RemoteAddr 是客户端回环地址（非 internal），
	// 这正说明来源是从 HTTP 层带下来的，而不是 fallback。
	if got.SourceIP != "127.0.0.1" {
		t.Fatalf("审计来源应为 127.0.0.1，实际 %q", got.SourceIP)
	}
}
