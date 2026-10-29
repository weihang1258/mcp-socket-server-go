package agent

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 真机验收（设计 §9.4）：AF_PACKET 真实 socket 抓包。非 root 自动跳过。
func TestRealAFPacketCaptureOnLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root/CAP_NET_RAW（sudo 运行）")
	}
	// 直接用真实实现，绕过测试注入
	prev := openPacketSocketFn
	openPacketSocketFn = openPacketSocketLinux
	t.Cleanup(func() { openPacketSocketFn = prev })

	path := filepath.Join(t.TempDir(), "real.pcap")
	src := newFakeSource()
	_ = src
	// 造 loopback 流量：本地 listener + 拨号
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	defer ln.Close()

	if ok, err := tcpdumpStart("lo", path, "", false); err != nil {
		t.Fatalf("start: %v", err)
	} else if !ok {
		t.Fatal("start want true")
	}
	// 产生回环流量
	for i := 0; i < 5; i++ {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err == nil {
			c.Write([]byte("ping"))
			c.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // 收完在途帧
	if resp, _ := runDT(t, 6, mustJSON(t, map[string]string{"path": path})); string(resp) != `{"res":true}` {
		t.Fatalf("stop: %q", resp)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(data[:4]) != 0xA1B23C4D {
		t.Fatalf("magic: %x", data[:4])
	}
	// 回环抓包至少应捕到若干帧（含我们拨号产生的 TCP）
	if len(data) <= 24+16 {
		t.Fatalf("no packets captured: %d bytes", len(data))
	}
	t.Logf("captured %d bytes of pcap from lo", len(data))
}

// 真机验收：AF_PACKET 发送（回放链路）。非 root 跳过。
func TestRealAFPacketSendOnLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root/CAP_NET_RAW（sudo 运行）")
	}
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no lo")
	}
	_ = iface
	// 构造最小合法以太帧（回环不校验，能 send 成功即验收发送链路）
	pkt := make([]byte, 60)
	for i := range pkt {
		pkt[i] = byte(i)
	}
	binary.BigEndian.PutUint16(pkt[12:], 0x0800)
	if err := replaySendLinux("lo", pkt); err != nil {
		t.Fatalf("raw send: %v", err)
	}
	if err := replaySendLinux("lo", pkt); err != nil {
		t.Fatalf("raw send (socket reuse): %v", err)
	}
}
