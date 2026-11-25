package ipdb

import (
	"net/netip"
	"strings"
	"testing"
)

func snap(t *testing.T, content string) *Snapshot {
	t.Helper()
	return NewSnapshot(ParseFile(content), "testsha")
}

// house 样例端到端四态
func TestSnapshotDirection(t *testing.T) {
	s := snap(t, "1000|90134|20.1.1.1|20.255.255.254\n1001|90135|192.168.1.1|192.168.1.1\n")
	cases := []struct{ src, dst, want string }{
		{"20.1.1.2", "8.8.8.8", "outbound"},
		{"8.8.8.8", "20.1.1.2", "inbound"},
		{"20.1.1.2", "192.168.1.1", "internal"},
		{"8.8.8.8", "1.1.1.1", "external"},
		{"192.168.1.1", "20.2.3.4", "internal"},
		{"20.0.0.1", "8.8.8.8", "external"}, // 区间前
		{"20.255.255.254", "8.8.8.8", "outbound"}, // 区间尾
		{"20.255.255.255", "8.8.8.8", "external"}, // 区间后
	}
	for _, c := range cases {
		got := s.Direction(netip.MustParseAddr(c.src), netip.MustParseAddr(c.dst))
		if got != c.want {
			t.Errorf("%s→%s: got %s want %s", c.src, c.dst, got, c.want)
		}
	}
}

// IPv6 段
func TestSnapshotIPv6(t *testing.T) {
	s := snap(t, "1000|90134|2E02:0000:0000:0000:0000:0000:0000:0001|2E02:0000:0000:0000:0000:0000:0000:00FF\n")
	if !s.Contains(netip.MustParseAddr("2e02::1")) {
		t.Fatal("2e02::1 应命中")
	}
	if !s.Contains(netip.MustParseAddr("2e02::ff")) {
		t.Fatal("2e02::ff 应命中")
	}
	if s.Contains(netip.MustParseAddr("2e02::100")) {
		t.Fatal("2e02::100 不应命中")
	}
	if s.Contains(netip.MustParseAddr("20.1.1.1")) {
		t.Fatal("v4 不应命中 v6 库")
	}
}

// 同地址多前缀（重叠段）二分回溯正确性
func TestSnapshotOverlappingPrefixes(t *testing.T) {
	// 10.0.0.0/8 与 10.1.0.0/16 与 10.1.2.0/24 重叠
	s := snap(t, "1|1|10.0.0.0|10.255.255.255\n2|2|10.1.0.0|10.1.255.255\n3|3|10.1.2.0|10.1.2.255\n")
	for _, ip := range []string{"10.1.2.3", "10.1.9.9", "10.1.200.1", "10.9.9.9", "10.0.1.1"} {
		if !s.Contains(netip.MustParseAddr(ip)) {
			t.Errorf("%s 应命中", ip)
		}
	}
	if s.Contains(netip.MustParseAddr("11.0.0.1")) {
		t.Error("11.0.0.1 不应命中")
	}
	if s.Contains(netip.MustParseAddr("9.255.255.255")) {
		t.Error("9.255.255.255 不应命中")
	}
}

// 无序插入（快照排序保证二分有效）
func TestSnapshotUnsortedInput(t *testing.T) {
	s := snap(t, "9|9|50.0.0.0|50.255.255.255\n1|1|10.0.0.0|10.0.0.255\n5|5|30.0.0.0|30.0.0.255\n")
	for _, ip := range []string{"10.0.0.1", "30.0.0.2", "50.1.2.3"} {
		if !s.Contains(netip.MustParseAddr(ip)) {
			t.Errorf("%s 应命中", ip)
		}
	}
	if s.Contains(netip.MustParseAddr("40.0.0.1")) {
		t.Error("40.0.0.1 不应命中")
	}
}

// Manager 原子替换 + 并发读写（-race）
func TestManagerAtomicSwap(t *testing.T) {
	m := NewManager()
	m.Set("/a", snap(t, "1|1|10.0.0.0|10.0.0.255\n"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			m.Set("/a", snap(t, "1|1|20.0.0.0|20.0.0.255\n"))
		}
	}()
	for i := 0; i < 500; i++ {
		s := m.Get("/a")
		if s == nil {
			t.Fatal("快照不应为 nil")
		}
		_ = s.Contains(netip.MustParseAddr("10.0.0.1"))
	}
	<-done
}

// 大库冒烟：5 万段加载 + 查询耗时
func TestSnapshotScale(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 50000; i++ {
		a := 10 + (i>>16)&0xFF
		b := (i >> 8) & 0xFF
		c := i & 0xFF
		sb.WriteString("1|1|" + itod(a) + "." + itod(b) + "." + itod(c) + ".0|" + itod(a) + "." + itod(b) + "." + itod(c) + ".255\n")
	}
	content := sb.String()
	s := NewSnapshot(ParseFile(content), "sha")
	if s.Entries != 50000 {
		t.Fatalf("entries=%d", s.Entries)
	}
	if !s.Contains(netip.MustParseAddr("10.1.2.7")) {
		t.Fatal("应命中")
	}
}

func itod(v int) string {
	if v == 0 {
		return "0"
	}
	d := []byte{}
	for v > 0 {
		d = append([]byte{byte('0' + v%10)}, d...)
		v /= 10
	}
	return string(d)
}
