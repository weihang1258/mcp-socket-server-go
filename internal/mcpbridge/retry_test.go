package mcpbridge

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// P1-2/P2-2：连不上时不该只回一句裸 "not connected"。靶机重启期间（upgrade_run
// 后 RestartSec=5）客户端看到的应该是有意义的提示，且连接建立失败值得重试。
//
// 关键约束：只对「连不上」重试，绝不重试已发出的请求——cmd_exec 非幂等，
// 重试会执行两次。
func TestDialRetriesOnConnectFailure(t *testing.T) {
	var attempts atomic.Int32
	prevDial, prevSleep := dialFn, dialBackoffSleepFn
	defer func() { dialFn, dialBackoffSleepFn = prevDial, prevSleep }()
	dialBackoffSleepFn = func(time.Duration) {} // 测试不真睡

	// 前两次拒绝，第三次成功
	dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if attempts.Add(1) < 3 {
			return nil, errors.New("connection refused")
		}
		return &fakeConn{}, nil
	}

	c := NewClient("10.0.0.1", 9000, 30)
	if err := c.connectWithRetry(); err != nil {
		t.Fatalf("第三次应成功，实际 %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("应尝试 3 次，实际 %d", attempts.Load())
	}
}

// 全部失败时返回带可读文案的错误，而不是裸 "not connected"。
func TestDialRetryExhaustedMessage(t *testing.T) {
	var attempts atomic.Int32
	prevDial, prevSleep := dialFn, dialBackoffSleepFn
	defer func() { dialFn, dialBackoffSleepFn = prevDial, prevSleep }()
	dialBackoffSleepFn = func(time.Duration) {}

	dialFn = func(string, string, time.Duration) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("connection refused")
	}

	c := NewClient("10.0.0.1", 9000, 30)
	err := c.connectWithRetry()
	if err == nil {
		t.Fatal("全部失败应返回错误")
	}
	if attempts.Load() != 3 {
		t.Fatalf("应尝试 3 次，实际 %d", attempts.Load())
	}
	msg := err.Error()
	if !strings.Contains(msg, "10.0.0.1:9000") {
		t.Fatalf("错误应包含目标地址，实际 %q", msg)
	}
	if !strings.Contains(msg, "重启") {
		t.Fatalf("错误应提示靶机可能在重启，实际 %q", msg)
	}
}

// send 本身绝不重试：连接断了就报错，让调用方决定。
func TestSendDoesNotRetry(t *testing.T) {
	c := NewClient("10.0.0.1", 9000, 1)
	err := c.send(0, []byte("x"))
	if err == nil {
		t.Fatal("无连接时 send 应失败")
	}
	if !strings.Contains(err.Error(), "未连接") {
		t.Fatalf("错误文案应可读（含「未连接」），实际 %q", err)
	}
}

// fakeConn 满足 net.Conn，仅用于 dial 成功路径。
type fakeConn struct{}

func (f *fakeConn) Read([]byte) (int, error)         { return 0, errors.New("EOF") }
func (f *fakeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "fake" }

// 轮询路径必须用一次性 dial：connectWithRetry 会把「3s 一轮」拖成
// 「3×timeout+退避」，upgrade_run 的 180s 预算只够跑 10 轮。
func TestDialOnceDoesNotRetry(t *testing.T) {
	var attempts atomic.Int32
	prevDial := dialFn
	defer func() { dialFn = prevDial }()
	dialFn = func(string, string, time.Duration) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("connection refused")
	}

	c := NewClient("10.0.0.1", 9000, 5)
	if err := c.dialOnce(); err == nil {
		t.Fatal("应失败")
	}
	if attempts.Load() != 1 {
		t.Fatalf("dialOnce 只能尝试 1 次，实际 %d", attempts.Load())
	}
}

// 建连超时必须独立于业务 socket 超时：cmd_exec 默认 60s，若拿它当 dial 超时，
// 靶机不可达时 3 次重试会把 60s 放大成 ~181s——重试本是为吃 5~15s 重启窗口。
func TestDialTimeoutCapped(t *testing.T) {
	cases := []struct {
		timeout int
		want    time.Duration
	}{
		{60, 5 * time.Second},  // 业务超时大 → 用上限
		{300, 5 * time.Second}, // boce_run
		{3, 3 * time.Second},   // 业务超时小 → 用它
		{0, 5 * time.Second},   // 未设置 → 上限
	}
	for _, c := range cases {
		cl := NewClient("h", 1, c.timeout)
		if got := cl.dialTimeout(); got != c.want {
			t.Errorf("Timeout=%d: dialTimeout() = %v，期望 %v", c.timeout, got, c.want)
		}
	}
}
