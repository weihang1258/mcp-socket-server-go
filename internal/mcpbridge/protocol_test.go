package mcpbridge

import (
	"bytes"
	"context"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/weihang1258/mcp-socket-server-go/internal/frame"
	"time"
)

// ---- mock socket_server（对拍基座，按 datatype 回 canned 响应）----

type mockServer struct {
	ln       net.Listener
	Addr     string
	mu       sync.Mutex
	received []mockRecv // 收到的 (dt, payload)
	handler  func(dt int32, payload []byte, w *mockConnIO)
}

type mockRecv struct {
	DT      int32
	Payload []byte
}

// mockConnIO 模拟服务端响应写出（支持分片/原始字节）。
type mockConnIO struct {
	conn net.Conn
}

func (m *mockConnIO) raw(b []byte)             { m.conn.Write(b) }
func (m *mockConnIO) text(s string)            { m.conn.Write([]byte(s)) }
func (m *mockConnIO) frame(dt int32, p []byte) { m.conn.Write(frame.Encode(dt, p)) }
func (m *mockConnIO) drop()                    { m.conn.Close() } // 模拟响应丢失（对端自杀式断连 → 客户端 EOF）
func (m *mockConnIO) fileResp(gz bool, c []byte) {
	n := make([]byte, 8)
	binary.LittleEndian.PutUint64(n, uint64(len(c)))
	m.conn.Write(n)
	m.conn.Write(c)
}

func newMockServer(t *testing.T, handler func(dt int32, payload []byte, w *mockConnIO)) *mockServer {
	t.Helper()
	return newMockServerOn(t, "127.0.0.1", handler)
}

// newMockServerOn 指定绑定地址（127.0.0.2 等 loopback 别名——真实 handler 的
// resolve 会剥 targets 端口，127.0.0.1 会打中真机自身 agent 的测试用它隔离）。
func newMockServerOn(t *testing.T, host string, handler func(dt int32, payload []byte, w *mockConnIO)) *mockServer {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	m := &mockServer{ln: ln, Addr: ln.Addr().String(), handler: handler}
	t.Cleanup(func() { ln.Close() })
	go m.acceptLoop()
	return m
}

func (m *mockServer) acceptLoop() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		go m.serveConn(conn)
	}
}

func (m *mockServer) serveConn(conn net.Conn) {
	defer conn.Close()
	for {
		dt, payload, err := frame.Read(conn)
		if err != nil {
			return
		}
		m.mu.Lock()
		m.received = append(m.received, mockRecv{dt, payload})
		m.mu.Unlock()
		if m.handler != nil {
			m.handler(dt, payload, &mockConnIO{conn})
		}
	}
}

func (m *mockServer) recvs() []mockRecv {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mockRecv, len(m.received))
	copy(out, m.received)
	return out
}

// 标准 handler：常用 datatype 的 canned 响应
func stdMockHandler(t *testing.T) func(int32, []byte, *mockConnIO) {
	return func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.8.3"`)
		case 7:
			w.text(`{"res":true}`)
		case 8:
			w.text(`{"res":false}`)
		case 1:
			var p struct {
				Args string `json:"args"`
				Wait bool   `json:"wait"`
			}
			json.Unmarshal(payload, &p)
			var b []byte
			if !p.Wait {
				b = []byte("null") // Python exec_cmd wait=false → json.dumps(None)
			} else {
				b, _ = json.Marshal(map[string]any{"code": 0, "stdout": stringsRepeat("o", 70000), "stderr": ""})
			}
			gz := gzipBytes(b)
			n := make([]byte, 4)
			binary.LittleEndian.PutUint32(n, uint32(len(gz)))
			w.raw(append(n, gz...))
		case 131:
			b, _ := json.Marshal(map[string]any{"total": 1, "success": 1, "fail": 0, "time": 0.5, "success_ratio": "100.00%"})
			w.frame(131, b)
		case 0:
			w.text(`{"total_packets":1}`)
		case 5:
			w.text(`{"res":true}`)
		case 6:
			w.text(`{"res":true}`)
		case 171:
			w.text(`{"pid":["111"]}`)
		case 172:
			w.text("ok")
		case 173:
			w.text("ok")
		case 175:
			w.text("ok")
		case 174:
			w.fileResp(true, gzipBytes([]byte("listen-data")))
		case 20:
			w.text(`{"ok":true,"version":"1.9.1"}`)
		}
	}
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

// ---- 客户端基础 ----

func TestClientVersionAndReceives(t *testing.T) {
	m := newMockServer(t, stdMockHandler(t))
	c := NewClient(hostOf(m.Addr), portOf(m.Addr), 5)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v, err := c.Version()
	if err != nil || v != "1.8.3" {
		t.Fatalf("version: %q %v", v, err)
	}
	ok, err := c.Isfile("/x")
	if err != nil || !ok {
		t.Fatalf("isfile: %v %v", ok, err)
	}
	ok, err = c.Isdir("/x")
	if err != nil || ok {
		t.Fatalf("isdir: %v %v", ok, err)
	}
	// 持久连接：同一连接多轮
	recvs := m.recvs()
	if len(recvs) != 3 {
		t.Fatalf("want 3 requests on same conn, got %d", len(recvs))
	}
}

func TestClientCmdExecTruncation(t *testing.T) {
	m := newMockServer(t, stdMockHandler(t))
	c, _ := dialClient(t, m)
	out, err := c.CmdExec("ls", "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(out["stdout"].(string)) != 65536 {
		t.Fatalf("stdout truncated to 65536 chars, got %d", len(out["stdout"].(string)))
	}
	if out["stdout_truncated"] != true {
		t.Fatal("truncated flag missing")
	}
	// wait=false → None → {"note":...} 由 _run_batch 层处理；client 层回 nil
	out2, err := c.CmdExec("ls", "", nil, false)
	if err != nil || out2 != nil {
		t.Fatalf("wait=false want nil: %v %v", out2, err)
	}
}

// 174 fetch：正常 [8B Q][gzip] 与首字节 { 错误 JSON 两态
func TestClientListenFetch(t *testing.T) {
	normal := newMockServer(t, stdMockHandler(t))
	c, _ := dialClient(t, normal)
	data, err := c.SocketListen("fetch", 30001, "", 1<<20)
	if err != nil || string(data.([]byte)) != "listen-data" {
		t.Fatalf("fetch: %v %v", data, err)
	}
	errState := newMockServer(t, func(dt int32, p []byte, w *mockConnIO) {
		if dt == 174 {
			w.text(`{"error":"未启动监听"}`)
		}
	})
	c2, _ := dialClient(t, errState)
	_, err = c2.SocketListen("fetch", 30001, "", 1<<20)
	if err == nil || !strings.Contains(err.Error(), "未启动监听") {
		t.Fatalf("174 error JSON: %v", err)
	}
}

// 172/173/175 错误形态：裸 error 与 {"error"} 双兼容
func TestClientListenErrorShapes(t *testing.T) {
	m := newMockServer(t, func(dt int32, p []byte, w *mockConnIO) {
		switch dt {
		case 172:
			w.text("error") // 裸 error（回退后契约）
		case 173:
			w.text(`{"error":"无法写入"}`) // 1.7.1 JSON（兼容分支）
		}
	})
	c, _ := dialClient(t, m)
	if _, err := c.SocketListen("clean", 30001, "", 0); err == nil {
		t.Fatal("clean bare error must fail")
	}
	if _, err := c.SocketListen("save", 30001, "/tmp/x", 0); err == nil || !strings.Contains(err.Error(), "无法写入") {
		t.Fatalf("save JSON error: %v", err)
	}
}

// dt20 upgrade_apply
func TestClientUpgradeApply(t *testing.T) {
	m := newMockServer(t, stdMockHandler(t))
	c, _ := dialClient(t, m)
	resp, err := c.UpgradeApply("1.9.1", stringsRepeat("a", 64), true)
	if err != nil || resp["ok"] != true {
		t.Fatalf("apply: %v %v", resp, err)
	}
}

// ---- 池 ----

func TestPoolBasics(t *testing.T) {
	m := newMockServer(t, stdMockHandler(t))
	p := NewTargetPool(hostOf(m.Addr), portOf(m.Addr))
	conns := make([]*Client, 5)
	for i := range conns {
		c, err := p.Acquire(1, 5)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		conns[i] = c
	}
	// 第 6 个：池满超时
	if _, err := p.Acquire(1, 5); err == nil {
		t.Fatal("pool full must timeout")
	}
	p.Release(conns[0], true)
	c6, err := p.Acquire(1, 5)
	if err != nil {
		t.Fatalf("reuse after release: %v", err)
	}
	if c6 != conns[0] {
		t.Fatal("must reuse same client")
	}
}

func TestPoolConnectFailRollback(t *testing.T) {
	// 死端口：acquire 失败必须回滚 _inuse（否则 5 次后永久耗尽）
	p := NewTargetPool("127.0.0.1", 1) // port 1 不可连
	for i := 0; i < 10; i++ {
		if _, err := p.Acquire(1, 1); err == nil {
			t.Fatal("want fail")
		}
	}
	// 仍可继续尝试（计数未泄漏）——无 panic 即可
}

func TestPoolUnhealthyClosed(t *testing.T) {
	m := newMockServer(t, stdMockHandler(t))
	p := NewTargetPool(hostOf(m.Addr), portOf(m.Addr))
	c1, _ := p.Acquire(1, 5)
	p.Release(c1, false) // 不健康：锁外关闭不入池
	c2, _ := p.Acquire(1, 5)
	if c2 == c1 {
		t.Fatal("unhealthy must not be reused")
	}
}

// ---- helpers ----

func dialClient(t *testing.T, m *mockServer) (*Client, error) {
	t.Helper()
	c := NewClient(hostOf(m.Addr), portOf(m.Addr), 5)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, nil
}

func hostOf(addr string) string {
	i := strings.LastIndex(addr, ":")
	return strings.Trim(addr[:i], "[]")
}

func portOf(addr string) int {
	i := strings.LastIndex(addr, ":")
	n, _ := strconv.Atoi(addr[i+1:])
	return n
}

// 读错误（reset/EOF）不得吞成空响应（六轮验收 P2）：当前第一个 Read 的
// 非 timeout 错误与短探超时走同一分支返回 nil，上层拿空字节去 json.Unmarshal
// 报成 "unexpected end of JSON input"，误导往协议不兼容/数据截断排查。
// Python 语义是 socket.timeout 才 return，ConnectionResetError 冒泡——对齐。
func TestRecvUntilTimeoutErrorNotSwallowed(t *testing.T) {
	// 对端 accept 即关 → 客户端第一 Read 得 EOF
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	addr := l.Addr().(*net.TCPAddr)
	c := NewClient("127.0.0.1", addr.Port, 5)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.recvUntilTimeout(300 * time.Millisecond); err == nil {
		t.Fatal("对端关闭必须冒泡，不得吞成空响应")
	}

	// 对照：静默连接（无响应）→ 第一 Read 超时 → (空, nil) 契约保持
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	go func() {
		for {
			cn, e := l2.Accept()
			if e != nil {
				return
			}
			t.Cleanup(func() { cn.Close() })
		}
	}()
	addr2 := l2.Addr().(*net.TCPAddr)
	c2 := NewClient("127.0.0.1", addr2.Port, 1)
	if err := c2.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	out, err := c2.recvUntilTimeout(200 * time.Millisecond)
	if err != nil {
		t.Fatalf("静默超时应保持 (空, nil) 契约: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("静默超时应为空: %q", out)
	}
}

// 空闲连接复用前必须探活（六轮验收 P2）：靶机重启后池里的半开连接各吞一次
// 请求，并发 N 路同一时刻集中失败 N 条。Acquire 探针检出即丢弃、换新建。
func TestPoolAcquireSkipsDeadIdle(t *testing.T) {
	m := newMockServer(t, stdMockHandler(t))
	p := NewTargetPool(hostOf(m.Addr), portOf(m.Addr))

	// 半开：底层 TCP 已死（服务端关），Client.conn 非 nil——Release 却标健康
	c1, err := p.Acquire(1, 5)
	if err != nil {
		t.Fatal(err)
	}
	c1.conn.Close()
	p.Release(c1, true)

	// 已 Close：conn=nil 的死亡连接同样入池
	c2, err := p.Acquire(1, 5)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	p.Release(c2, true)

	// 两次 Acquire 都必须跳过死连接，拿到的是新建活连接
	for i := 0; i < 2; i++ {
		c, err := p.Acquire(1, 5)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		if c == c1 || c == c2 {
			t.Fatalf("死连接被复用（第 %d 次）", i)
		}
		if !probeAlive(c) {
			t.Fatalf("Acquire 返回的应是活连接（第 %d 次）", i)
		}
	}
}

// FIN 传播窗口（六轮验收 P2 复测）：服务端进程死亡瞬间，旧连接的 FIN 还没
// 跨网到达——读探针读不到任何异常（判活），复用即 EOF，并发 N 路同时全败。
// 读探针永远覆盖不了这个窗口；换 dial 验证：进程死=监听 socket 关=新 SYN
// 即刻 RST，不受 FIN 传播影响。判死后弃复用走新建（connectWithRetry 退避
// 吃重启窗口），最终报建连重试文案。
func TestAcquireDialCheckRejectsReuseWhenListenerClosed(t *testing.T) {
	// 模拟：listener 关闭（进程死）但已建立连接的 FIN 未达（客户端侧仍 ESTABLISHED）
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpL := l.(*net.TCPListener)
	raw, err := net.DialTCP("tcp", nil, tcpL.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// 服务端 accept 后立即关 listener（连接仍活——FIN 未达模拟）
	srv, _ := l.Accept()
	defer srv.Close()
	l.Close()

	addr := srv.LocalAddr().(*net.TCPAddr)
	p := NewTargetPool("127.0.0.1", addr.Port)
	c1 := NewClient("127.0.0.1", addr.Port, 5)
	c1.conn = raw // 池中连接：本侧 ESTABLISHED，读探针必然判活
	p.Release(c1, true)

	c2, err := p.Acquire(1, 5)
	if err == nil {
		c2.Close()
		t.Fatal("listener 已关：dial 验证应弃复用，新建也应失败")
	}
	if !strings.Contains(err.Error(), "靶机可能正在重启") {
		t.Fatalf("应为建连失败文案（可判读），实际: %v", err)
	}
}

// runBatch 的连接级错误文案语义化：裸 EOF 现场无法判断「等一秒重试即可」。
// 只读工具（version 等）：重复执行无副作用，文案建议稍后重试。
func TestRunBatchEOFGetsFriendlyText(t *testing.T) {
	// 服务端 accept 即关：Version 的读得到 EOF
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	addr := l.Addr().(*net.TCPAddr)
	b := newTestBridge(t)
	out := b.runBatch(context.Background(), []string{"127.0.0.1"}, addr.Port, LkNone, "", "version", nil, true, 5,
		func(c *Client) (any, error) { return c.Version() })
	failed := out["failed"].([]map[string]any)
	if len(failed) != 1 {
		t.Fatalf("应失败: %+v", out)
	}
	reason := fmt.Sprint(failed[0]["reason"])
	if !strings.Contains(reason, "靶机可能正在重启") || !strings.Contains(reason, "请稍后重试") {
		t.Fatalf("只读工具 EOF 应带可重试文案，实际: %v", reason)
	}
}

// 非幂等工具（cmd_exec 等）在途断连：命令可能已部分执行或已完成但响应丢失，
// 执行状态未知——文案必须阻止盲目重试（2026-11-01 七轮验收 P2：真机实测
// 「请稍后重试」引导重复执行，S 已写入、E 未写）。runBatch 显式传 retrySafe=false。
func TestRunBatchConnLostNonIdempotentText(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	addr := l.Addr().(*net.TCPAddr)
	b := newTestBridge(t)
	for _, tool := range []string{"cmd_exec", "replay_run"} { // 各非幂等调用点同传 false，此处抽验
		out := b.runBatch(context.Background(), []string{"127.0.0.1"}, addr.Port, LkNone, "", tool, nil, false, 5,
			func(c *Client) (any, error) { return c.Version() })
		failed := out["failed"].([]map[string]any)
		if len(failed) != 1 {
			t.Fatalf("%s: 应失败: %+v", tool, out)
		}
		reason := fmt.Sprint(failed[0]["reason"])
		if !strings.Contains(reason, "执行状态未知") || !strings.Contains(reason, "勿直接重试") {
			t.Fatalf("%s: 非幂等工具 EOF 必须阻止盲目重试，实际: %v", tool, reason)
		}
		if strings.Contains(reason, "请稍后重试") {
			t.Fatalf("%s: 不得出现「请稍后重试」: %v", tool, reason)
		}
	}
}
