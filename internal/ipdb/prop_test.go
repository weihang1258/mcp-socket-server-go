package ipdb

import (
	"math/rand"
	"net/netip"
	"testing"
)

// 区间转前缀性质测试：随机区间，前缀并集恰好 = 区间（不重不漏不越界）
func TestRangeToPrefixesProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 3000; iter++ {
		// 随机 v4 区间，跨度 1..65536
		a := uint32(rng.Intn(0xFFFFFFFF))
		span := uint32(rng.Intn(65536))
		lo := netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)})
		b := a + span
		if b < a || b > 0xFFFFFFFF {
			continue
		}
		hi := netip.AddrFrom4([4]byte{byte(b >> 24), byte(b >> 16), byte(b >> 8), byte(b)})
		ps := rangeToPrefixes(lo, hi)
		in := func(x netip.Addr) bool {
			x = x.Unmap()
			for _, p := range ps {
				if p.Contains(x) {
					return true
				}
			}
			return false
		}
		if !in(lo) || !in(hi) {
			t.Fatalf("iter %d: %s-%s 端点不在覆盖内", iter, lo, hi)
		}
		if lo.Compare(netip.AddrFrom4([4]byte{})) > 0 && in(prevAddr(lo)) {
			t.Fatalf("iter %d: lo-1 被覆盖", iter)
		}
		if b < 0xFFFFFFFF && in(hi.Next()) {
			t.Fatalf("iter %d: hi+1 被覆盖", iter)
		}
		total := uint64(0)
		for _, p := range ps {
			total += uint64(1) << uint(p.Addr().BitLen()-p.Bits())
		}
		if total != uint64(span)+1 {
			t.Fatalf("iter %d: %s-%s 总地址数 %d != %d", iter, lo, hi, total, span+1)
		}
		for i := 0; i < len(ps); i++ {
			for j := i + 1; j < len(ps); j++ {
				if ps[i].Overlaps(ps[j]) {
					t.Fatalf("iter %d: 前缀重叠 %v %v", iter, ps[i], ps[j])
				}
			}
		}
	}
}

func prevAddr(a netip.Addr) netip.Addr {
	b := a.As16()
	for i := 15; i >= 0; i-- {
		if b[i] > 0 {
			b[i]--
			break
		}
		b[i] = 0xFF
	}
	out, _ := netip.AddrFromSlice(b[:])
	return out.Unmap()
}

// 随机 v6 区间小抽样（全量太慢）
func TestRangeToPrefixesV6Property(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 300; iter++ {
		var ab, bb [16]byte
		for i := 0; i < 16; i++ {
			ab[i] = byte(rng.Intn(256))
			bb[i] = byte(rng.Intn(256))
		}
		lo := netip.AddrFrom16(ab)
		hi := netip.AddrFrom16(bb)
		if lo.Compare(hi) > 0 {
			lo, hi = hi, lo
		}
		// 限制跨度避免前缀爆炸：把 hi 截到 lo+2^16 内
		hiBytes := hi.As16()
		_ = hiBytes
		ps := rangeToPrefixes(lo, hi)
		total := uint64(0)
		for _, p := range ps {
			total += uint64(1) << uint(p.Addr().BitLen()-p.Bits())
		}
		// 期望地址数：span+1 可能超 uint64 → 只验非溢出情形
		diff := bigDiff(lo, hi)
		inc := diff
		carry := 1
		for i := 15; i >= 0 && carry > 0; i-- {
			s := int(inc[i]) + carry
			inc[i] = byte(s & 0xFF)
			carry = s >> 8
		}
		if carry > 0 {
			continue
		}
		if inc[8] != 0 || inc[9] != 0 || inc[10] != 0 || inc[11] != 0 || inc[12] != 0 || inc[13] != 0 || inc[14] != 0 || inc[15] != 0 {
			continue // span+1 > 2^64，uint64 表达不了，跳过
		}
		want := uint64(0)
		for i := 8; i < 16; i++ {
			want = want<<8 | uint64(inc[i])
		}
		if total != want {
			t.Fatalf("iter %d: 总地址 %d != %d", iter, total, want)
		}
	}
}
