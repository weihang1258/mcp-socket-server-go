package ipdb

import (
	"net/netip"
	"testing"
)

// v4-mapped 查询地址（::ffff:x.x.x.x）必须按 v4 判定：agent 双栈抓包
// 有意回 mapped 串（pcapflow.go），ip_lookup 也可能收到 mapped 字面量。
func TestContainsV4Mapped(t *testing.T) {
	s := NewSnapshot(ParseFile("1000|90134|20.1.1.1|20.1.1.20\n"), "sha")
	if !s.Contains(netip.MustParseAddr("::ffff:20.1.1.5")) {
		t.Fatal("mapped 命中失败")
	}
	if !s.Contains(netip.MustParseAddr("20.1.1.5")) {
		t.Fatal("plain v4 命中失败")
	}
	if s.Contains(netip.MustParseAddr("::ffff:20.1.1.21")) {
		t.Fatal("mapped 区间外误命中")
	}
	// 真映射 v6（非 mapped）不受影响
	s6 := NewSnapshot(ParseFile("1000|90134|2E02::|2E02::ff\n"), "sha")
	if !s6.Contains(netip.MustParseAddr("2e02::50")) {
		t.Fatal("v6 命中失败")
	}
}
