package agent

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- fake 发送器 ----

type fakeSender struct {
	mu     sync.Mutex
	sent   [][]byte
	ifaces []string
}

func (f *fakeSender) send(iface string, pkt []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	f.sent = append(f.sent, cp)
	f.ifaces = append(f.ifaces, iface)
	return nil
}

func (f *fakeSender) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sent) }

// ---- pcap 构造（复用 capture_test 的 helpers）----

func writeReplayPcap(t *testing.T, path string, div int, frames ...[]byte) {
	t.Helper()
	var buf []byte
	g := make([]byte, 24)
	magic := uint32(0xA1B2C3D4)
	if div == int(1e9) {
		magic = 0xA1B23C4D
	}
	binary.LittleEndian.PutUint32(g, magic)
	binary.LittleEndian.PutUint32(g[20:], 1)
	buf = append(buf, g...)
	for _, f := range frames {
		buf = append(buf, pcapRecord(f)...)
	}
	os.WriteFile(path, buf, 0o644)
}

func replayDT0(t *testing.T, payload map[string]any) (map[string]any, error) {
	t.Helper()
	resp, err := runDT(t, 0, mustJSON(t, payload))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("dt0 resp: %v (%q)", err, resp)
	}
	return m, nil
}

// 方向判定 + 上下行计数：SYN 上行、数据包反向 → downlink
func TestReplayerDirectionCounts(t *testing.T) {
	resetReplaySender(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "d.pcap")
	writeReplayPcap(t, p, int(1e6),
		ipv4("10.20.0.1", "10.20.0.2", 6, tcpSeg(1000, 80, 0x02, nil)), // SYN → uplink
		ipv4("10.20.0.2", "10.20.0.1", 6, tcpSeg(80, 1000, 0x10, nil)), // 反向流 → downlink
	)
	m, err := replayDT0(t, map[string]any{
		"pcaps": []string{p}, "uplink_iface": "up0", "downlink_iface": "down0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if m["total_packets"] != float64(2) || m["flow_count"] != float64(1) {
		t.Fatalf("stats: %v", m)
	}
	if m["uplink_packets"] != float64(1) || m["downlink_packets"] != float64(1) {
		t.Fatalf("direction counts: %v", m)
	}
	if got := replaySender.ifaces; len(got) == 2 && (got[0] != "up0" || got[1] != "down0") {
		t.Fatalf("iface per direction: %v", got)
	}
	// 字节统计 max(orig_len, 60)
	if m["total_bytes"] != float64(120) {
		t.Fatalf("bytes want 120 got %v", m["total_bytes"])
	}
}

// 非 IPv4/IPv6 帧跳过（不发送不计数）；坏帧 warn 跳过
func TestReplayerSkipsNonIP(t *testing.T) {
	resetReplaySender(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "s.pcap")
	writeReplayPcap(t, p, int(1e6),
		ethFrame(0x88CC, []byte{1, 2, 3}), // LLDP → 跳过
		ipv4("10.21.0.1", "10.21.0.2", 17, udpSeg(1, 2)),
	)
	m, err := replayDT0(t, map[string]any{
		"pcaps": []string{p}, "uplink_iface": "u", "downlink_iface": "d",
	})
	if err != nil {
		t.Fatal(err)
	}
	if m["total_packets"] != float64(1) || replaySender.count() != 1 {
		t.Fatalf("non-IP not skipped: %v", m)
	}
}

// directionless + 无改写 + 不强制建流 → 不建流全 uplink
func TestReplayerDirectionless(t *testing.T) {
	resetReplaySender(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "dl.pcap")
	writeReplayPcap(t, p, int(1e6),
		ipv4("10.22.0.2", "10.22.0.1", 17, udpSeg(2, 1)),
	)
	m, err := replayDT0(t, map[string]any{
		"pcaps": []string{p}, "uplink_iface": "single", "downlink_iface": "single",
	})
	if err != nil {
		t.Fatal(err)
	}
	if m["flow_count"] != float64(0) || m["uplink_packets"] != float64(1) || m["downlink_packets"] != float64(0) {
		t.Fatalf("directionless: %v", m)
	}
}

// hint 优先；失配保持默认 uplink（if/elif 不回退 SYN）
func TestReplayerHintPriority(t *testing.T) {
	resetReplaySender(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "h.pcap")
	writeReplayPcap(t, p, int(1e6),
		ipv4("10.23.0.9", "10.23.0.8", 6, tcpSeg(1, 2, 0x02, nil)), // SYN 若被询判 uplink
	)
	// 命中 hint：src=client → uplink
	m, _ := replayDT0(t, map[string]any{
		"pcaps": []string{p}, "uplink_iface": "u", "downlink_iface": "d",
		"client_ip_hint": "10.23.0.9", "server_ip_hint": "10.23.0.8",
	})
	if m["uplink_packets"] != float64(1) {
		t.Fatalf("hint match: %v", m)
	}
	// hint 失配（角色颠倒且 IP 不符）→ 保持默认 uplink，不回退 SYN 判定
	m, _ = replayDT0(t, map[string]any{
		"pcaps": []string{p}, "uplink_iface": "u", "downlink_iface": "d",
		"client_ip_hint": "99.9.9.9", "server_ip_hint": "88.8.8.8",
	})
	if m["uplink_packets"] != float64(1) || m["downlink_packets"] != float64(0) {
		t.Fatalf("hint mismatch must stay default uplink: %v", m)
	}
}

// force 改写：对称换向 + IP/TCP 校验和重算正确
func TestReplayerForceRewrite(t *testing.T) {
	resetReplaySender(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "f.pcap")
	writeReplayPcap(t, p, int(1e6),
		ipv4("10.24.0.1", "10.24.0.2", 6, tcpSeg(3000, 80, 0x02, nil)), // uplink
		ipv4("10.24.0.2", "10.24.0.1", 6, tcpSeg(80, 3000, 0x10, nil)), // downlink
	)
	_, err := replayDT0(t, map[string]any{
		"pcaps": []string{p}, "uplink_iface": "u", "downlink_iface": "d",
		"force_ip_src": "172.31.1.1", "force_ip_dst": "172.31.1.2",
		"force_sport": 40000, "force_dport": 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, pkt := range replaySender.sent {
		if len(pkt) < 14+20+20 {
			t.Fatalf("pkt %d truncated", i)
		}
		payload := pkt[14:]
		src := net.IP(payload[12:16]).String()
		dst := net.IP(payload[16:20]).String()
		sport := binary.BigEndian.Uint16(payload[20:22])
		dport := binary.BigEndian.Uint16(payload[22:24])
		if i == 0 { // uplink: src=force_src dst=force_dst
			if src != "172.31.1.1" || dst != "172.31.1.2" || sport != 40000 || dport != 443 {
				t.Fatalf("uplink rewrite: %s:%d->%s:%d", src, sport, dst, dport)
			}
		} else { // downlink: 对称换向
			if src != "172.31.1.2" || dst != "172.31.1.1" || sport != 443 || dport != 40000 {
				t.Fatalf("downlink rewrite: %s:%d->%s:%d", src, sport, dst, dport)
			}
		}
		// IP 校验和必须有效
		if ipChecksum(payload[:20]) != 0 {
			t.Fatalf("pkt %d IP checksum invalid", i)
		}
		// TCP 校验和（含伪头）有效
		ihl := int(payload[0]&0x0F) * 4
		if tcpChecksum(payload[:ihl], payload[ihl:]) != 0 {
			t.Fatalf("pkt %d TCP checksum invalid", i)
		}
	}
}

// 无 force → 原样发出（不改写）
func TestReplayerNoForceUnchanged(t *testing.T) {
	resetReplaySender(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "n.pcap")
	orig := ipv4("10.25.0.1", "10.25.0.2", 17, udpSeg(5, 6))
	writeReplayPcap(t, p, int(1e6), orig)
	_, err := replayDT0(t, map[string]any{
		"pcaps": []string{p}, "uplink_iface": "u", "downlink_iface": "d",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(replaySender.sent[0]) != string(orig) {
		t.Fatal("no-force must send original")
	}
}

// VLAN：打标（无→插）/替换（有 8100→换 TCI）
func TestReplayerVLAN(t *testing.T) {
	resetReplaySender(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "v.pcap")
	plain := ipv4("10.26.0.1", "10.26.0.2", 17, udpSeg(7, 8))
	withVlan := make([]byte, 0, len(plain)+4)
	withVlan = append(withVlan, plain[:12]...)
	var t4 [4]byte
	binary.BigEndian.PutUint16(t4[:2], 0x8100)
	binary.BigEndian.PutUint16(t4[2:], 50)
	withVlan = append(withVlan, t4[:]...)
	binary.BigEndian.PutUint16(t4[:2], 0x0800)
	withVlan = append(withVlan, t4[:2]...)
	withVlan = append(withVlan, plain[14:]...)
	writeReplayPcap(t, p, int(1e6), plain, withVlan)
	_, err := replayDT0(t, map[string]any{
		"pcaps": []string{p}, "uplink_iface": "u", "downlink_iface": "d",
		"uplink_vlan": 300, "downlink_vlan": 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 包1：无 VLAN → 插 300；包2：有 50 → 替换 300
	for i, pkt := range replaySender.sent {
		if binary.BigEndian.Uint16(pkt[12:14]) != 0x8100 {
			t.Fatalf("pkt %d no vlan tag", i)
		}
		if got := binary.BigEndian.Uint16(pkt[14:16]); got != 300 {
			t.Fatalf("pkt %d tci want 300 got %d", i, got)
		}
	}
}

// mbps 全局限速：total_bytes*8/mbps >= elapsed（宽断言）
func TestReplayerMbpsPacing(t *testing.T) {
	resetReplaySender(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "m.pcap")
	frames := make([][]byte, 10)
	for i := range frames {
		frames[i] = ipv4("10.27.0.1", "10.27.0.2", 17, udpSeg(9, 10))
	}
	writeReplayPcap(t, p, int(1e6), frames...)
	start := time.Now()
	m, err := replayDT0(t, map[string]any{
		"pcaps": []string{p}, "uplink_iface": "u", "downlink_iface": "d", "mbps": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start).Seconds()
	want := float64(m["total_bytes"].(float64)) * 8 / 1e6
	if elapsed+0.05 < want { // 应至少睡到 global pacing
		t.Fatalf("pacing: elapsed %.3f want >= %.3f", elapsed, want)
	}
	if m["actual_mbps"] == nil || m["target_mbps"] != float64(1) {
		t.Fatalf("mbps fields: %v", m)
	}
}

// dt0 校验：缺参数固定文案；未知键断连；status=error 透传
func TestReplayerDT0Validation(t *testing.T) {
	resetReplaySender(t)
	// 缺参数（含缺 pcaps）→ 固定文案
	resp, err := runDT(t, 0, mustJSON(t, map[string]any{"uplink_iface": "u"}))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	json.Unmarshal(resp, &m)
	if m["status"] != "error" || m["message"] != "Missing required parameters: uplink_iface or downlink_iface" {
		t.Fatalf("fixed message: %q", resp)
	}
	// 未知键 → TypeError 被 dt0 try/except 捕获 → error JSON（Python 语义，审查确认）
	resp2, err := runDT(t, 0, mustJSON(t, map[string]any{
		"pcaps": []string{"/x"}, "uplink_iface": "u", "downlink_iface": "d", "bogus": 1,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var m2 map[string]string
	json.Unmarshal(resp2, &m2)
	if m2["status"] != "error" {
		t.Fatalf("unknown key want error JSON, got %q", resp2)
	}
	// 文件缺失 → error JSON "pcap不存在："
	resp3, err := runDT(t, 0, mustJSON(t, map[string]any{
		"pcaps": []string{"/no/such.pcap"}, "uplink_iface": "u", "downlink_iface": "d",
	}))
	if err != nil {
		t.Fatal(err)
	}
	var m3 map[string]string
	json.Unmarshal(resp3, &m3)
	if m3["status"] != "error" || !strings.Contains(m3["message"], "pcap不存在") {
		t.Fatalf("missing file want error JSON: %q", resp3)
	}
}

// ns magic 时间戳除数（1e9）：可解析（不炸即通过，时序影响在 pacing 已测）
func TestReplayerNsMagic(t *testing.T) {
	resetReplaySender(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "ns.pcap")
	writeReplayPcap(t, p, int(1e9), ipv4("10.28.0.1", "10.28.0.2", 17, udpSeg(11, 12)))
	m, err := replayDT0(t, map[string]any{
		"pcaps": []string{p}, "uplink_iface": "u", "downlink_iface": "d",
	})
	if err != nil {
		t.Fatal(err)
	}
	if m["total_packets"] != float64(1) {
		t.Fatalf("ns magic parse: %v", m)
	}
}

var replaySender *fakeSender

func resetReplaySender(t *testing.T) {
	t.Helper()
	replaySender = &fakeSender{}
	prev := replaySendFn
	replaySendFn = func(iface string, pkt []byte) error { return replaySender.send(iface, pkt) }
	t.Cleanup(func() { replaySendFn = prev; replaySender = nil })
}
