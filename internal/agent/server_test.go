package agent

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/weihang1258/mcp-socket-server-go/internal/frame"
)

// 启动测试 agent，返回地址。测试结束自动关闭。
func startTestAgent(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go Serve(ln)
	return ln.Addr().String()
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// recvDeadline 读响应；超时返回空（区分"无响应"与读到数据）。
func recvDeadline(t *testing.T, c net.Conn, d time.Duration) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		return nil
	}
	return buf[:n]
}

// dt14 返回 json 字符串版本号（json.dumps(VERSION) 带引号）
func TestDT14Version(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	if _, err := c.Write(frame.Encode(14, nil)); err != nil {
		t.Fatal(err)
	}
	got := recvDeadline(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("no response for dt14")
	}
	var v string
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatalf("dt14 response not quoted JSON string: %q (%v)", got, err)
	}
	if v != Version {
		t.Fatalf("version want %q got %q", Version, v)
	}
}

// 持久连接：未知 datatype 无响应，连接继续，后续帧正常处理
func TestUnknownDTNoResponseConnAlive(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	c.Write(frame.Encode(999, nil))
	if got := recvDeadline(t, c, 300*time.Millisecond); got != nil {
		t.Fatalf("unknown dt must be silent, got %q", got)
	}
	c.Write(frame.Encode(14, nil))
	got := recvDeadline(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("conn died after unknown dt")
	}
	var v string
	json.Unmarshal(got, &v)
	if v != Version {
		t.Fatalf("second dt14 wrong: %q", v)
	}
}

// 帧体 <4B：跳过该帧继续（无响应不断连）
func TestFrameBodyTooSmallSkipped(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	// len=2 的帧体（2 字节垃圾）
	bad := make([]byte, 6)
	binary.LittleEndian.PutUint32(bad[:4], 2)
	bad[4], bad[5] = 0xAA, 0xBB
	c.Write(bad)
	if got := recvDeadline(t, c, 300*time.Millisecond); got != nil {
		t.Fatalf("short body must be silent, got %q", got)
	}
	c.Write(frame.Encode(14, nil))
	if got := recvDeadline(t, c, 2*time.Second); got == nil {
		t.Fatal("conn died after short body frame")
	}
}

// 超长帧（累计 > len）：丢弃当前累计（含嵌入的下一帧头），等下一帧头。
// Python 一次 recv 拿到的所有超收字节全弃——故合法帧必须等服务端消化完超收后再发。
func TestOvershootDiscarded(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	h := make([]byte, 4)
	binary.LittleEndian.PutUint32(h, 8)
	// 第一写：声明 len=8，实发 16 字节（超收 8 字节全部丢弃）
	c.Write(append(h, make([]byte, 16)...))
	time.Sleep(200 * time.Millisecond)
	// 第二写：合法 dt14（新帧头）
	c.Write(frame.Encode(14, nil))
	got := recvDeadline(t, c, 2*time.Second)
	if got == nil {
		t.Fatal("overshoot broke framing; no response to following valid frame")
	}
	var v string
	json.Unmarshal(got, &v)
	if v != Version {
		t.Fatalf("wrong response after overshoot: %q", v)
	}
}

// dt21 畸形 JSON：立即断连（无响应）
func TestDT21MalformedJSONDisconnects(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	c.Write(frame.Encode(21, []byte("not-json")))
	if got := recvDeadline(t, c, 1*time.Second); got != nil {
		t.Fatalf("malformed dt21 must be silent, got %q", got)
	}
	// 连接应已被服务端关闭：再写再读得到 EOF
	c.Write(frame.Encode(14, nil))
	if got := recvDeadline(t, c, 1*time.Second); got != nil {
		t.Fatalf("conn should be closed, got %q", got)
	}
}

// dt24 无前置 dt21：self.gzip 未初始化 quirk → 断连（§2 连接级状态）
func TestDT24WithoutDT21Disconnects(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	c.Write(frame.Encode(24, nil))
	if got := recvDeadline(t, c, 1*time.Second); got != nil {
		t.Fatalf("dt24 without dt21 must be silent, got %q", got)
	}
	c.Write(frame.Encode(14, nil))
	if got := recvDeadline(t, c, 1*time.Second); got != nil {
		t.Fatal("conn should be closed after naked dt24")
	}
}

// dt22 payload >8B：struct.error quirk → 断连
func TestDT22OversizedLengthDisconnects(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	c.Write(frame.Encode(22, make([]byte, 9)))
	if got := recvDeadline(t, c, 1*time.Second); got != nil {
		t.Fatalf("dt22 >8B must be silent, got %q", got)
	}
	c.Write(frame.Encode(14, nil))
	if got := recvDeadline(t, c, 1*time.Second); got != nil {
		t.Fatal("conn should be closed after 9B dt22")
	}
}

// 首包 <4B：断连
func TestFirstChunkTooShortDisconnects(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	c.Write([]byte{0x01, 0x02})
	if got := recvDeadline(t, c, 1*time.Second); got != nil {
		t.Fatalf("short first chunk must be silent, got %q", got)
	}
	c.Write(frame.Encode(14, nil))
	if got := recvDeadline(t, c, 1*time.Second); got != nil {
		t.Fatal("conn should be closed after 2-byte first chunk")
	}
}

// do() 异常 → 断连无响应：以 dt200 畸形 JSON 为探针
func TestHandlerErrorDisconnects(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	c.Write(frame.Encode(200, []byte("not-json")))
	if got := recvDeadline(t, c, 1*time.Second); got != nil {
		t.Fatalf("handler error must be silent, got %q", got)
	}
	c.Write(frame.Encode(14, nil))
	if got := recvDeadline(t, c, 1*time.Second); got != nil {
		t.Fatal("conn should be closed after handler error")
	}
}
