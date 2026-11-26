package ipdb

import (
	"net/netip"
	"testing"
)

// 边界：全地址空间、最大区间、v4/v6 混合
func TestRangeEdgeCases(t *testing.T) {
	// 全 0 到全 1（v4 全空间）——Next() 到 invalid 停止
	lo := netip.AddrFrom4([4]byte{})
	hi := netip.AddrFrom4([4]byte{0xFF, 0xFF, 0xFF, 0xFF})
	ps := rangeToPrefixes(lo, hi)
	if len(ps) != 1 || ps[0].Bits() != 0 {
		t.Fatalf("全空间应是一个 /0: %v", ps)
	}
	// 单地址边界 255.255.255.255
	ps = rangeToPrefixes(hi, hi)
	if len(ps) != 1 || ps[0].String() != "255.255.255.255/32" {
		t.Fatalf("尾地址: %v", ps)
	}
	// 0.0.0.0 单地址
	ps = rangeToPrefixes(lo, lo)
	if len(ps) != 1 || ps[0].String() != "0.0.0.0/32" {
		t.Fatalf("首地址: %v", ps)
	}
	// v6 全空间
	lo6 := netip.MustParseAddr("::")
	hi6 := netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	ps = rangeToPrefixes(lo6, hi6)
	if len(ps) != 1 || ps[0].Bits() != 0 {
		t.Fatalf("v6 全空间: %v", ps)
	}
}
