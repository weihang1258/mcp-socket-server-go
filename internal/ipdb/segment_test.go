package ipdb

import (
	"net/netip"
	"testing"
)

func must4(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a.Unmap()
}

// 现场四格式解析
func TestParseLineFormats(t *testing.T) {
	cases := []struct {
		name, line string
		lo, hi     string // 期望区间；hi==lo 即单 IP
	}{
		{"house", "1000|90134|20.1.1.1|20.255.255.254", "20.1.1.1", "20.255.255.254"},
		{"oversea", "108.138.7.71|108.138.7.71|跨境|测试1", "108.138.7.71", "108.138.7.71"},
		{"zcip 单IP", "172.31.139.140", "172.31.139.140", "172.31.139.140"},
		{"zcip 带空白", "  172.31.139.140  ", "172.31.139.140", "172.31.139.140"},
		{"IPv6 全0展开", "1000|90134|2E02:0000:0000:0000:0000:0000:0000:0001|2E02:0000:0000:0000:0000:0000:0000:00FF",
			"2e02::1", "2e02::ff"},
		{"起止颠倒", "5|x|10.0.0.2|10.0.0.1", "10.0.0.1", "10.0.0.2"},
	}
	for _, c := range cases {
		seg, ok := parseLine(c.line)
		if !ok {
			t.Fatalf("%s: 未解析出段", c.name)
		}
		if seg.Start.String() != c.lo || seg.End.String() != c.hi {
			t.Fatalf("%s: got %s-%s want %s-%s", c.name, seg.Start, seg.End, c.lo, c.hi)
		}
	}
}

// 注释/脏行跳过
func TestParseFileSkips(t *testing.T) {
	content := `################
//time:2026-11-20 16:45:03|ver:9|desc:house_ipsegs.txt|
1000|90134|20.1.1.1|20.255.255.254

1001|90135|192.168.1.1|192.168.1.1
//POLICY_FILE_END
脏行没有IP
#注释`
	segs := ParseFile(content)
	if len(segs) != 2 {
		t.Fatalf("应解析出 2 段，got %d: %v", len(segs), segs)
	}
	if segs[0].Start.String() != "20.1.1.1" || segs[1].End.String() != "192.168.1.1" {
		t.Fatalf("内容不符: %v", segs)
	}
}

// 区间转前缀：经典边界
func TestRangeToPrefixes(t *testing.T) {
	cases := []struct {
		lo, hi string
		want   []string
	}{
		// 对齐整块 → 1 个前缀
		{"1.2.0.0", "1.2.255.255", []string{"1.2.0.0/16"}},
		{"10.0.0.0", "10.255.255.255", []string{"10.0.0.0/8"}},
		// 单 IP
		{"1.2.3.4", "1.2.3.4", []string{"1.2.3.4/32"}},
		// 非对齐 → 拆多块（1..254 共 254 地址：7 段凑 127 + 7 段凑 127）
		{"20.1.1.1", "20.1.1.254", []string{"20.1.1.1/32", "20.1.1.2/31", "20.1.1.4/30", "20.1.1.8/29", "20.1.1.16/28", "20.1.1.32/27", "20.1.1.64/26", "20.1.1.128/26", "20.1.1.192/27", "20.1.1.224/28", "20.1.1.240/29", "20.1.1.248/30", "20.1.1.252/31", "20.1.1.254/32"}},
		// /24 内尾部
		{"192.168.1.1", "192.168.1.1", []string{"192.168.1.1/32"}},
		// IPv6（16 个地址恰一块）
		{"::200", "::20f", []string{"::200/124"}},
	}
	for _, c := range cases {
		got := rangeToPrefixes(must4(t, c.lo).Unmap(), must4(t, c.hi).Unmap())
		gotS := make([]string, len(got))
		for i, p := range got {
			gotS[i] = p.String()
		}
		if len(gotS) != len(c.want) {
			t.Fatalf("%s-%s: got %v want %v", c.lo, c.hi, gotS, c.want)
		}
		for i := range gotS {
			if gotS[i] != c.want[i] {
				t.Fatalf("%s-%s: [%d] got %s want %s", c.lo, c.hi, i, gotS[i], c.want[i])
			}
		}
	}
}

// 覆盖完整性：前缀集合并集恰好等于区间（不重不漏）——用首尾+抽样校验
func TestRangeToPrefixesCoverage(t *testing.T) {
	lo, hi := must4(t, "10.1.2.3"), must4(t, "10.5.6.7")
	ps := rangeToPrefixes(lo, hi)
	// lo 在集合内
	if !prefixesContain(ps, lo) {
		t.Fatal("lo 不在覆盖内")
	}
	if !prefixesContain(ps, hi) {
		t.Fatal("hi 不在覆盖内")
	}
	// 区间外不在
	if prefixesContain(ps, must4(t, "10.1.2.2")) || prefixesContain(ps, must4(t, "10.5.6.8")) {
		t.Fatal("覆盖越界")
	}
	// 中点抽样
	mid := must4(t, "10.3.100.200")
	if !prefixesContain(ps, mid) {
		t.Fatal("中点不在覆盖内")
	}
	// 前缀之间不相交（相邻可，重叠不可）
	for i := 0; i < len(ps); i++ {
		for j := i + 1; j < len(ps); j++ {
			if ps[i].Overlaps(ps[j]) {
				t.Fatalf("前缀重叠: %v vs %v", ps[i], ps[j])
			}
		}
	}
}

func prefixesContain(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// house 现场样例端到端
func TestHouseSampleEndToEnd(t *testing.T) {
	content := "1000|90134|20.1.1.1|20.255.255.254\n"
	segs := ParseFile(content)
	ps, skipped := SegsToPrefixes(segs)
	if skipped != 0 {
		t.Fatalf("意外跳过 %d", skipped)
	}
	if len(ps) < 10 {
		t.Fatalf("20.1.1.1-20.255.255.254 应拆出多段前缀，got %d", len(ps))
	}
	if !prefixesContain(ps, must4(t, "20.1.1.2")) {
		t.Fatal("20.1.1.2 应命中")
	}
	if prefixesContain(ps, must4(t, "20.0.0.1")) {
		t.Fatal("20.0.0.1 不应命中（区间前）")
	}
}

// R5-A4：ID 列恰为 IP 形态时必须取列 3/4，不能把 ID 段当真实区间
func TestParseLineIDColumnIsIP(t *testing.T) {
	seg, ok := parseLine("100.64.0.1|100.64.0.2|20.1.1.1|20.1.1.5")
	if !ok {
		t.Fatal("未解析")
	}
	if seg.Start.String() != "20.1.1.1" || seg.End.String() != "20.1.1.5" {
		t.Fatalf("4 列应取列 3/4: %s-%s", seg.Start, seg.End)
	}
	// 2 列 oversea 仍取列 1/2
	seg, ok = parseLine("108.138.7.71|108.138.7.71|跨境|测试1")
	if !ok || seg.Start.String() != "108.138.7.71" {
		t.Fatalf("带备注 4 列: %+v", seg)
	}
	seg, ok = parseLine("108.138.7.71|108.138.7.71")
	if !ok || seg.Start.String() != "108.138.7.71" || seg.End.String() != "108.138.7.71" {
		t.Fatalf("2 列 oversea: %+v", seg)
	}
	// house 数字 ID 仍正确
	seg, ok = parseLine("1000|90134|20.1.1.1|20.255.255.254")
	if !ok || seg.Start.String() != "20.1.1.1" {
		t.Fatalf("house: %+v", seg)
	}
	// 起止列脏时回退最左两个 IP
	seg, ok = parseLine("1|脏|20.1.1.1|20.1.1.5")
	if !ok || seg.Start.String() != "20.1.1.1" || seg.End.String() != "20.1.1.5" {
		t.Fatalf("回退: %+v", seg)
	}
}
