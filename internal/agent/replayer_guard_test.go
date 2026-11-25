package agent

import (
	"encoding/binary"
	"testing"
)

func mkEth(pktLen int) []byte { return make([]byte, pktLen) }

func mkV4TCPFull() []byte {
	p := make([]byte, 14+20+20)
	p[12], p[13] = 0x08, 0x00
	ip := p[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 40)
	ip[9] = 6
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(ip[20:], 1234)
	binary.BigEndian.PutUint16(ip[22:], 80)
	return p
}

func mkVLAN(p []byte, vid uint16) []byte {
	out := make([]byte, 0, len(p)+4)
	out = append(out, p[:12]...)
	var t [4]byte
	binary.BigEndian.PutUint16(t[:2], 0x8100)
	binary.BigEndian.PutUint16(t[2:], vid)
	out = append(out, t[:]...)
	out = append(out, p[12:]...)
	return out
}

func s3(v string) *string { return &v }
func u3(v uint16) *uint16 { return &v }

// A3-1：VLAN 包 IP 改写生效
func TestA3VLANIPRewrite(t *testing.T) {
	pkt := mkVLAN(mkV4TCPFull(), 100)
	out := buildModifiedPacket(pkt, s3("192.168.1.1"), nil, nil, nil)
	if out == nil {
		t.Fatal("VLAN 包 IP 改写返回 nil（N11 回归）")
	}
	// 剥 VLAN 后返回 54B（= 14 eth + 40 IP/TCP）；调用方 addOrModifyVLAN 再按方向加回标签
	if len(out) != 54 {
		t.Fatalf("长度 %d != 54（剥标签后）", len(out))
	}
	// 剥 VLAN 后 IP 头在 offset 14
	if out[14+12] != 192 || out[14+13] != 168 || out[14+16] != 10 {
		t.Fatalf("源 IP 未改写: % x", out[14+12:14+16])
	}
}

// A3-2：VLAN 包仅端口改写生效（R3 实测返回 nil 的场景）
func TestA3VLANPortOnly(t *testing.T) {
	pkt := mkVLAN(mkV4TCPFull(), 100)
	out := buildModifiedPacket(pkt, nil, nil, u3(9999), nil)
	if out == nil {
		t.Fatal("VLAN 包仅端口改写返回 nil（N11 回归）")
	}
	got := binary.BigEndian.Uint16(out[14+20:])
	if got != 9999 {
		t.Fatalf("sport=%d != 9999", got)
	}
}

// A3-3：短包不 panic（N20 面全部覆盖）
func TestA3ShortPacketsNoPanic(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		src  *string
	}{
		{"14B 空", mkEth(14), s3("1.2.3.4")},
		{"15B 0x45", append(mkEth(14), 0x45), s3("1.2.3.4")},
		{"v4 payload 10B", append(mkEth(14), make([]byte, 10)...), s3("1.2.3.4")},
		{"v4 payload 19B", append(mkEth(14), make([]byte, 19)...), s3("1.2.3.4")},
		{"v6 payload 10B", append(mkEth(14), 0x60), s3("fd00::1")},
		{"v6 payload 39B", append(mkEth(14), make([]byte, 39)...), s3("fd00::1")},
		{"VLAN 短标签", append(mkEth(14), 0x81, 0x00, 0x00), s3("1.2.3.4")},
		{"空帧", nil, s3("1.2.3.4")},
		{"13B", mkEth(13), s3("1.2.3.4")},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s PANIC: %v", c.name, r)
				}
			}()
			out := buildModifiedPacket(c.pkt, c.src, nil, nil, nil)
			t.Logf("%s → out=%v（nil=原样发送）", c.name, out != nil)
		}()
	}
}

// A3-4：无 VLAN 正常改写不受影响（回归保护）
func TestA3PlainStillWorks(t *testing.T) {
	pkt := mkV4TCPFull()
	out := buildModifiedPacket(pkt, s3("192.168.1.1"), nil, nil, nil)
	if out == nil {
		t.Fatal("普通 v4 包改写失效")
	}
	if out[14+12] != 192 {
		t.Fatalf("源 IP 未改写")
	}
}
