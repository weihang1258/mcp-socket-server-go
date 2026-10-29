package mcpbridge

// 传输层：Streamable HTTP 绑定 cfg host:port（mcp 默认 9010）。
// 关键回归：host 为 v6 字面量（"::1"）时地址拼接必须带方括号，否则监听失败。

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPTransportBindsIPv4(t *testing.T) {
	testHTTPTransportBind(t, "127.0.0.1")
}

func TestHTTPTransportBindsIPv6Literal(t *testing.T) {
	if !ipv6LoopbackAvailable() {
		t.Skip("本机无 ::1")
	}
	testHTTPTransportBind(t, "::1")
}

func testHTTPTransportBind(t *testing.T, host string) {
	t.Helper()
	port := freeTCPPort(t, host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- RunStreamableHTTP(ctx, Init(BridgeConfig{DBPath: t.TempDir() + "/mcp.db"}), host, port)
	}()

	addr := net.JoinHostPort(host, fmt.Sprint(port))
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for i := 0; i < 100; i++ {
		req, err := http.NewRequest("POST", "http://"+addr+"/mcp", nil)
		if err != nil {
			lastErr = err
		} else if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			return // 已监听（状态码无关，端点存在即证明 bind 成功）
		} else {
			lastErr = err
		}
		select {
		case err := <-done:
			t.Fatalf("%s:%d 监听失败: %v (last dial err: %v)", host, port, err, lastErr)
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("%s:%d 未在 5s 内可达: %v", host, port, lastErr)
}

func freeTCPPort(t *testing.T, host string) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("%s 不可绑定: %v", host, err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func ipv6LoopbackAvailable() bool {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return false
	}
	ln.Close()
	return true
}
