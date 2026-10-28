package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// ---- 合成 pcap 构造 ----

func pcapGlobal() []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 0xA1B2C3D4) // 微秒 magic
	binary.LittleEndian.PutUint32(b[8:], 65535)
	binary.LittleEndian.PutUint32(b[20:], 1) // Ethernet
	return b
}

func pcapRecord(data []byte) []byte {
	b := make([]byte, 16+len(data))
	binary.LittleEndian.PutUint32(b[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(b[12:], uint32(len(data)))
	copy(b[16:], data)
	return b
}

func ethFrame(ethType uint16, payload []byte) []byte {
	b := make([]byte, 14+len(payload))
	binary.BigEndian.PutUint16(b[12:], ethType)
	copy(b[14:], payload)
	return b
}

func ipv4(src, dst string, proto byte, trans []byte) []byte {
	p := make([]byte, 20+len(trans))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(20+len(trans)))
	p[8] = 64
	p[9] = proto
	copy(p[12:], net.ParseIP(src).To4())
	copy(p[16:], net.ParseIP(dst).To4())
	copy(p[20:], trans)
	return ethFrame(0x0800, p)
}

func ipv6(src, dst string, nextHeader byte, trans []byte) []byte {
	p := make([]byte, 40+len(trans))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], uint16(len(trans)))
	p[6] = nextHeader
	copy(p[8:], net.ParseIP(src).To16())
	copy(p[24:], net.ParseIP(dst).To16())
	copy(p[40:], trans)
	return ethFrame(0x86DD, p)
}

func tcpSeg(sport, dport uint16, flags byte, app []byte) []byte {
	t := make([]byte, 20+len(app))
	binary.BigEndian.PutUint16(t, sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	t[12] = 5 << 4
	t[13] = flags
	copy(t[20:], app)
	return t
}

func udpSeg(sport, dport uint16) []byte {
	t := make([]byte, 8)
	binary.BigEndian.PutUint16(t, sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	return t
}

func writePcap(t *testing.T, path string, frames ...[]byte) {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(pcapGlobal())
	for _, f := range frames {
		buf.Write(pcapRecord(f))
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

type flowOut map[string]any

func runDT200(t *testing.T, dir string) []flowOut {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"pcap_dir": dir})
	resp, err := runDT(t, 200, payload)
	if err != nil {
		t.Fatal(err)
	}
	// dt200 响应带 [4B i] 前缀（Python struct.pack("i", len(res)) + res）
	if len(resp) < 4 {
		t.Fatalf("dt200 response missing length prefix: %q", resp)
	}
	n := binary.LittleEndian.Uint32(resp[:4])
	if int(n) != len(resp)-4 {
		t.Fatalf("prefix %d != body %d", n, len(resp)-4)
	}
	var flows []flowOut
	if err := json.Unmarshal(resp[4:], &flows); err != nil {
		t.Fatalf("dt200 body not JSON: %v (%q)", err, resp[4:])
	}
	return flows
}

// 基本五元组 + 字符串字段 + protoType 映射
func TestDT200BasicFlows(t *testing.T) {
	dir := t.TempDir()
	writePcap(t, filepath.Join(dir, "a.pcap"),
		ipv4("10.0.0.1", "10.0.0.2", 6, tcpSeg(1000, 80, 0x02, nil)), // SYN
		ipv4("10.0.0.2", "10.0.0.1", 6, tcpSeg(80, 1000, 0x12, nil)), // SYN+ACK
		ipv4("10.0.0.1", "10.0.0.2", 17, udpSeg(5353, 53)),           // UDP 独立流
		ipv4("10.0.0.3", "10.0.0.4", 132, tcpSeg(7, 8, 0, nil)),      // SCTP → "3"
		ipv4("10.0.0.5", "10.0.0.6", 1, []byte{8, 0, 0, 0}),          // ICMP → "4"
		ipv4("10.0.0.7", "10.0.0.8", 47, []byte{9, 9, 9, 9}),         // GRE → 跳过
	)
	flows := runDT200(t, dir)
	if len(flows) != 4 {
		t.Fatalf("want 4 flows (TCP/UDP/SCTP/ICMP), got %d: %v", len(flows), flows)
	}
	byKey := map[string]flowOut{}
	for _, f := range flows {
		byKey[f["protoType"].(string)+":"+f["srcIp"].(string)] = f
	}
	tcp := byKey["1:10.0.0.1"]
	if tcp == nil {
		t.Fatalf("tcp flow missing: %v", flows)
	}
	// SYN 发起方为客户端 → src=10.0.0.1
	if tcp["srcPort"] != "1000" || tcp["destPort"] != "80" || tcp["destIp"] != "10.0.0.2" {
		t.Fatalf("tcp fields wrong (must be strings): %v", tcp)
	}
	if byKey["2:10.0.0.1"] == nil {
		t.Fatalf("udp flow missing: %v", flows)
	}
	if byKey["3:10.0.0.3"] == nil {
		t.Fatal("sctp flow missing")
	}
	icmp := byKey["4:10.0.0.5"]
	if icmp == nil || icmp["srcPort"] != "0" || icmp["destPort"] != "0" {
		t.Fatalf("icmp ports must be string 0: %v", icmp)
	}
}

// IPv6：固定 offset 6 不走扩展头；端口字符串
func TestDT200IPv6(t *testing.T) {
	dir := t.TempDir()
	writePcap(t, filepath.Join(dir, "v6.pcap"),
		ipv6("fd00::1", "fd00::2", 17, udpSeg(1111, 2222)),
	)
	flows := runDT200(t, dir)
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %v", flows)
	}
	f := flows[0]
	if f["srcIp"] != "fd00::1" || f["srcPort"] != "1111" || f["protoType"] != "2" {
		t.Fatalf("v6 flow wrong: %v", f)
	}
}

// VLAN 单层：0x8100 内层解析
func TestDT200VLAN(t *testing.T) {
	dir := t.TempDir()
	inner := ipv4("10.1.0.1", "10.1.0.2", 6, tcpSeg(1, 2, 0x02, nil))
	// 剥掉外层 eth 头再套 VLAN 帧
	frame_ := inner[14:]
	vlan := make([]byte, 0, 18+len(frame_))
	vlan = append(vlan, inner[:12]...)
	var t4 [4]byte
	binary.BigEndian.PutUint16(t4[:2], 0x8100)
	binary.BigEndian.PutUint16(t4[2:], 100)
	vlan = append(vlan, t4[:]...)
	binary.BigEndian.PutUint16(t4[:2], 0x0800)
	vlan = append(vlan, t4[:2]...)
	vlan = append(vlan, frame_...)
	writePcap(t, filepath.Join(dir, "vlan.pcap"), vlan)
	flows := runDT200(t, dir)
	if len(flows) != 1 || flows[0]["srcIp"] != "10.1.0.1" {
		t.Fatalf("vlan flow wrong: %v", flows)
	}
}

// 方向判定：首包 SYN+ACK → 接收方为客户端；HTTP 请求/响应修正；一次锁定
func TestDT200DirectionRules(t *testing.T) {
	dir := t.TempDir()
	// 流1：首包 SYN+ACK（无前置 SYN）→ dst 为客户端
	writePcap(t, filepath.Join(dir, "d1.pcap"),
		ipv4("10.2.0.2", "10.2.0.1", 6, tcpSeg(80, 5000, 0x12, nil)),
		ipv4("10.2.0.1", "10.2.0.2", 6, tcpSeg(5000, 80, 0x02, nil)), // 晚到的 SYN 不再改
	)
	// 流2：TCP 载荷 GET → 请求方为客户端
	writePcap(t, filepath.Join(dir, "d2.pcap"),
		ipv4("10.3.0.1", "10.3.0.2", 6, tcpSeg(40000, 80, 0x18, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))),
	)
	// 流3：TCP 载荷 HTTP/1. 响应行 → 响应接收方为客户端
	writePcap(t, filepath.Join(dir, "d3.pcap"),
		ipv4("10.4.0.2", "10.4.0.1", 6, tcpSeg(80, 40000, 0x18, []byte("HTTP/1.1 200 OK\r\n\r\n"))),
	)
	// 流4：无任何信号 → 首包 src 为客户端
	writePcap(t, filepath.Join(dir, "d4.pcap"),
		ipv4("10.5.0.9", "10.5.0.8", 17, udpSeg(9, 10)),
	)
	flows := runDT200(t, dir)
	if len(flows) != 4 {
		t.Fatalf("want 4 flows, got %v", flows)
	}
	got := map[string]flowOut{}
	for _, f := range flows {
		got[f["pcap"].(string)] = f
	}
	if got["d1.pcap"]["srcIp"] != "10.2.0.1" {
		t.Fatalf("SYN+ACK: receiver should be client, got %v", got["d1.pcap"])
	}
	if got["d2.pcap"]["srcIp"] != "10.3.0.1" {
		t.Fatalf("GET: sender should be client, got %v", got["d2.pcap"])
	}
	if got["d3.pcap"]["srcIp"] != "10.4.0.1" {
		t.Fatalf("HTTP resp: receiver should be client, got %v", got["d3.pcap"])
	}
	if got["d4.pcap"]["srcIp"] != "10.5.0.9" {
		t.Fatalf("default: first src should be client, got %v", got["d4.pcap"])
	}
}

// 目录递归 + pcap 字段取 basename
func TestDT200RecursiveWalk(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	os.MkdirAll(sub, 0o755)
	writePcap(t, filepath.Join(sub, "deep.pcap"),
		ipv4("10.6.0.1", "10.6.0.2", 17, udpSeg(1, 2)))
	flows := runDT200(t, dir)
	if len(flows) != 1 || flows[0]["pcap"] != "deep.pcap" {
		t.Fatalf("recursive walk wrong: %v", flows)
	}
}

// 坏 pcap 跳过（不中断其他文件）；记录体截断 → 停止解析该文件（保留已解析流）
func TestDT200BadPcapSkipped(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.pcap"), []byte("not a pcap at all"), 0o644)
	writePcap(t, filepath.Join(dir, "good.pcap"),
		ipv4("10.7.0.1", "10.7.0.2", 17, udpSeg(3, 4)))
	// 截断：最后一条记录体不完整
	var buf bytes.Buffer
	buf.Write(pcapGlobal())
	buf.Write(pcapRecord(ipv4("10.8.0.1", "10.8.0.2", 17, udpSeg(5, 6)))) // 完整
	buf.Write(pcapRecord(ipv4("10.8.0.3", "10.8.0.4", 17, udpSeg(7, 8)))) // 被截断
	trunc := buf.Bytes()
	os.WriteFile(filepath.Join(dir, "trunc.pcap"), trunc[:len(trunc)-3], 0o644)

	flows := runDT200(t, dir)
	if len(flows) != 2 {
		t.Fatalf("want 2 flows (good + truncated-partial), got %v", flows)
	}
	// 路径不存在/非目录 → 空数组
	if out := runDT200(t, filepath.Join(dir, "nope")); len(out) != 0 {
		t.Fatalf("missing dir want empty, got %v", out)
	}
}

// 字典序流键 quirk：端口 9 与 10 按 string 排序（"10" < "9"），
// 客户端判定不受影响，但同 ip 对角时的 src/dest 输出须与 Python 一致
func TestDT200LexicographicFlowKey(t *testing.T) {
	dir := t.TempDir()
	// 同 ip 不同端口：canon = sort([("h1","9"),("h1","10")]) → "10" 在前
	writePcap(t, filepath.Join(dir, "lex.pcap"),
		ipv4("10.9.0.9", "10.9.0.9", 17, udpSeg(9, 10)),
	)
	flows := runDT200(t, dir)
	if len(flows) != 1 {
		t.Fatalf("want 1 flow: %v", flows)
	}
	// 首包 src=(10.9.0.9,"9")；sorted 后 ("10.9.0.9","10") < ("10.9.0.9","9")，
	// client=首包src=("..","9") != first_src=(sorted 后的 "..","10")?
	// Python: first_src=首包(src,dst)=("9"侧? no—first_src=src_tuple of 首包)…直接对照:
	// first_src=("10.9.0.9","9"), first_dst=("10.9.0.9","10")
	// canonical=sorted→[("10.9.0.9","10"),("10.9.0.9","9")]；client=first_src=("..","9")
	// 输出: client==first_src → src=first_src → srcPort=9
	if flows[0]["srcPort"] != "9" || flows[0]["destPort"] != "10" {
		t.Fatalf("lexicographic key flow wrong: %v", flows[0])
	}
}

// IHL 越界防护：截断帧 IHL=15（>实际长度）不得 panic（Python payload[ihl:] 得 b""）
func TestDT200IHLBoundGuard(t *testing.T) {
	dir := t.TempDir()
	p := make([]byte, 20) // 仅 IP 头位置，IHL 字段声明 15*4=60B
	p[0] = 0x4F           // v4, IHL=15
	p[9] = 6              // TCP
	ip := ipv4("10.9.9.1", "10.9.9.2", 6, nil)
	copy(ip[14:], p) // 覆盖 IP 头为 IHL=15 版本
	writePcap(t, filepath.Join(dir, "ihl.pcap"), ip)
	flows := runDT200(t, dir) // 不 panic 即通过（trans 空 → TCP 跳过）
	if len(flows) != 0 {
		t.Fatalf("ihl-truncated packet should yield no flow: %v", flows)
	}
}

// 多流输出顺序确定（Python dict 插入序）
func TestDT200OrderDeterministic(t *testing.T) {
	dir := t.TempDir()
	writePcap(t, filepath.Join(dir, "ord.pcap"),
		ipv4("10.10.0.1", "10.10.0.2", 17, udpSeg(1, 2)),
		ipv4("10.10.0.3", "10.10.0.4", 17, udpSeg(3, 4)),
		ipv4("10.10.0.5", "10.10.0.6", 17, udpSeg(5, 6)),
	)
	first := runDT200(t, dir)
	for i := 0; i < 10; i++ {
		again := runDT200(t, dir)
		for j := range again {
			if again[j]["srcIp"] != first[j]["srcIp"] {
				t.Fatalf("order unstable at %d: %v vs %v", j, first[j], again[j])
			}
		}
	}
}

// dt200 payload 严格性：未知键/缺 pcap_dir → 断连（Python **data TypeError）
func TestDT200StrictPayload(t *testing.T) {
	if _, err := runDT(t, 200, []byte(`{"pcap_dir":"/tmp","extra":1}`)); err == nil {
		t.Fatal("unknown key must disconnect")
	}
	if _, err := runDT(t, 200, []byte(`{}`)); err == nil {
		t.Fatal("missing pcap_dir must disconnect")
	}
}

// UDP 载荷 "GET " 不触发 HTTP 方向信号（仅 proto==6 才查）；HTTP 信号先到即锁定
func TestDT200DirectionLockSemantics(t *testing.T) {
	dir := t.TempDir()
	writePcap(t, filepath.Join(dir, "lock.pcap"),
		ipv4("10.11.0.1", "10.11.0.2", 17, udpSeg(1, 2)), // 流A: 默认 src=客户端
		ipv4("10.11.0.3", "10.11.0.4", 6, tcpSeg(5000, 80, 0x18, []byte("GET / HTTP/1.1\r\n\r\n"))), // 先锁 .3
		ipv4("10.11.0.4", "10.11.0.3", 6, tcpSeg(80, 5000, 0x02, nil)), // 后到 SYN 不改
	)
	flows := runDT200(t, dir)
	if len(flows) != 2 {
		t.Fatalf("want 2 flows, got %v", flows)
	}
	for _, f := range flows {
		if f["protoType"] == "2" && f["srcIp"] != "10.11.0.1" {
			t.Fatalf("udp default direction wrong: %v", f)
		}
		if f["protoType"] == "1" && f["srcIp"] != "10.11.0.3" {
			t.Fatalf("HTTP signal must lock before late SYN: %v", f)
		}
	}
}
