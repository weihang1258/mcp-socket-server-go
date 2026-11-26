// Package ipdb 机房 IP 段库（设计 docs/dpi-ipdb-direction-design-2026-11-25.md 第九节修订版）：
// 路径直给、每份文件独立快照、宽容解析器、stdlib net/netip + 自写前缀树，0 协议改动。
//
// S1 解析层：把设备上的 ipsegs 文本文件解析成前缀集合。
//
// 现场四种格式（82 实测）：
//
//	house:   1000|90134|20.1.1.1|20.255.255.254        （前两列是 ID，列3/4 是起止）
//	oversea: 108.138.7.71|108.138.7.71|跨境|测试1        （列1/2 是起止）
//	zcip:    172.31.139.140                             （裸单 IP）
//	pcip:    同 house 格式
//
// 不按文件名猜格式——每行按 "|" 分列，取**最左的两个可解析 IP 列**作起止；
// 只有一个 IP 列视为单 IP 段。注释行（#、//、//POLICY_FILE_END、空行）跳过。
package ipdb

import (
	"net/netip"
	"strings"
)

// Seg 一条 IP 段（区间或单 IP）。
type Seg struct {
	Start netip.Addr // 闭区间起点
	End   netip.Addr // 闭区间终点（单 IP 段 Start==End）
	Raw   string     // 原始行（诊断用）
}

// ParseFile 宽容解析：逐行扫描，返回全部有效段。
// 跳过：空行、以 # 或 // 开头的注释、//POLICY_FILE_END 等标记行。
// 行内无任何可解析 IP 的行也跳过（不报错——现场文件混注释与脏行是常态）。
func ParseFile(content string) []Seg {
	var out []Seg
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if seg, ok := parseLine(line); ok {
			out = append(out, seg)
		}
	}
	return out
}

// parseLine 单行：按 | 或空白分列。
// 列数决定起止列（R5-A4：无脑取最左两个 IP 列，在 ID 列恰为 IP 形态时
// 会把真实区间错建成 ID 段）：
//   4+ 列（house/pcip：ID|ID|start|end|备注…）→ 取列 3/4；
//   2 列（oversea：start|end|备注…）→ 取列 1/2；
//   3 列 → 最左两个可解析 IP 列；1 列 → 裸单 IP。
// 起止列解析失败时回退到"最左两个可解析 IP 列"（容脏行）。
func parseLine(line string) (Seg, bool) {
	cols := strings.Split(line, "|")
	if len(cols) == 1 { // zcip：空白分隔也可能，兜底按字段切
		cols = strings.Fields(line)
	}
	parseCol := func(c string) (netip.Addr, bool) {
		a, err := netip.ParseAddr(strings.TrimSpace(c))
		if err != nil {
			return netip.Addr{}, false
		}
		return a.Unmap(), true
	}
	segFrom := func(a, b netip.Addr) (Seg, bool) {
		if a.Compare(b) > 0 {
			a, b = b, a
		}
		return Seg{Start: a, End: b, Raw: line}, true
	}
	if len(cols) >= 4 {
		lo, ok1 := parseCol(cols[2])
		hi, ok2 := parseCol(cols[3])
		if ok1 && ok2 {
			return segFrom(lo, hi)
		}
	} else if len(cols) == 2 {
		lo, ok1 := parseCol(cols[0])
		hi, ok2 := parseCol(cols[1])
		if ok1 && ok2 {
			return segFrom(lo, hi)
		}
	}
	// 3 列 / 固定列解析失败：回退最左两个可解析 IP 列
	var ips []netip.Addr
	for _, c := range cols {
		if a, ok := parseCol(c); ok {
			ips = append(ips, a)
			if len(ips) == 2 {
				break
			}
		}
	}
	switch len(ips) {
	case 1:
		return Seg{Start: ips[0], End: ips[0], Raw: line}, true
	case 2:
		return segFrom(ips[0], ips[1])
	}
	return Seg{}, false
}

// SegsToPrefixes 闭区间 → CIDR 前缀集合（标准算法，≤ 2×位数 个前缀）。
// v4 与 v6 都走同一逻辑（按 bits 位宽）。跨族段（理论上不该有）跳过。
func SegsToPrefixes(segs []Seg) ([]netip.Prefix, int) {
	var out []netip.Prefix
	skipped := 0
	for _, s := range segs {
		if !s.Start.IsValid() || !s.End.IsValid() || s.Start.Is4() != s.End.Is4() {
			skipped++
			continue
		}
		out = append(out, rangeToPrefixes(s.Start, s.End)...)
	}
	return out, skipped
}

// rangeToPrefixes [lo,hi] → 前缀集合。迭代实现：从 lo 起，每次取当前对齐的
// 最大块（低位零尾巴），剪掉超出 hi 的部分。
func rangeToPrefixes(lo, hi netip.Addr) []netip.Prefix {
	bits := lo.BitLen()
	var out []netip.Prefix
	for lo.Compare(hi) <= 0 {
		// 当前对齐块大小：lo 末尾连续 0 的个数（含 /bits 自身）
		maxLead := trailingZeros(lo)
		// 块大小受两个上限约束（取小）：
		//  a) 对齐：lo 末尾连续零 n → 最大 /（bits-n）
		//  b) 区间：2^(bits-size) 必须覆盖 hi-lo+1 个地址，即
		//     size <= bits - ceil(log2(span+1))（span = hi-lo）
		// 两个下限约束（取大）：size 越大块越小。
		//  a) 对齐：size >= bits-tz（lo 低 bits-size 位须全零）
		//  b) 覆盖：块地址数 2^(bits-size) <= span+1 → size >= bits-k
		size := bits - maxLead
		spanAddr := bigDiff(lo, hi)
		if lim := bits - addrCountFloorBits(spanAddr, bits); lim > size {
			size = lim
		}
		p, _ := lo.Prefix(size)
		out = append(out, p)
		// 跳到块尾之后
		next := lastAddr(p).Next()
		if !next.IsValid() { // 地址空间末尾
			break
		}
		lo = next
	}
	return out
}

// trailingZeros 地址末尾连续 0 的个数（对齐粒度）。全零地址返回满位宽。
func trailingZeros(a netip.Addr) int {
	b := a.As16()
	bits := a.BitLen()
	n := 0
	minIdx := 0
	if a.Is4() {
		minIdx = 12 // v4 有效位只有低 4 字节，高 12 字节恒 0 不计入
	}
	for i := len(b) - 1; i >= minIdx; i-- {
		byt := b[i]
		if byt == 0 {
			n += 8
			continue
		}
		for byt&1 == 0 {
			n++
			byt >>= 1
		}
		break
	}
	if n > bits {
		n = bits
	}
	return n
}

// bigDiff hi-lo（大端 16 字节）。仅内部使用（lo<=hi 同族）。
func bigDiff(lo, hi netip.Addr) [16]byte {
	var out [16]byte
	lb, hb := lo.As16(), hi.As16()
	carry := 0
	for i := 15; i >= 0; i-- {
		d := int(hb[i]) - int(lb[i]) - carry
		if d < 0 {
			d += 256
			carry = 1
		} else {
			carry = 0
		}
		out[i] = byte(d)
	}
	return out
}

// lastAddr 前缀的最后一个地址（广播地址）。
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As16()
	hostBits := p.Addr().BitLen() - p.Bits()
	for i := 15; i >= 0 && hostBits > 0; i-- {
		take := 8
		if hostBits < 8 {
			take = hostBits
		}
		a[i] |= byte(0xFF >> (8 - take))
		hostBits -= take
	}
	out, _ := netip.AddrFromSlice(a[:])
	if p.Addr().Is4() {
		out = out.Unmap()
	}
	return out
}

// addrCountFloorBits diff（hi-lo）→ floor(log2(diff+1))：从 lo 起连续不越界的
// 最大地址数为 2 的幂时取该幂（diff+1 恰 2^k），否则取更低一档。
// diff==0（lo==hi）→ 0（/bits 单地址）。
// diff+1 == 2^bits（全地址空间）时 16 字节加法溢出、carry 残留 → 返回满位宽，
// 让 lim 不再约束块大小（全空间恰是 /0 一块）。
func addrCountFloorBits(diff [16]byte, bits int) int {
	inc := diff
	carry := 1
	for i := 15; i >= 0 && carry > 0; i-- {
		s := int(inc[i]) + carry
		inc[i] = byte(s & 0xFF)
		carry = s >> 8
	}
	if carry > 0 { // diff+1 == 2^bits：全地址空间
		return bits
	}
	for i, byt := range inc {
		if byt != 0 {
			hb := 0
			for byt > 1 {
				byt >>= 1
				hb++
			}
			m := (15-i)*8 + hb // diff+1 的最高位编号 m：2^m <= diff+1 < 2^(m+1)
			// diff+1 恰 2^m（低 m 位全零）→ k=m；否则 k=m（2^m 个地址必然 <= diff+1）
			// 两种情况都取 m：2^m <= diff+1 恒成立 → 不越界。
			return m
		}
	}
	return 0
}
