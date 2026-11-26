package ipdb

import (
	"net/netip"
	"sort"
	"sync/atomic"
)

// Snapshot 不可变快照：加载新版本时构造全新 Snapshot，atomic.Pointer 原子替换。
// 读侧全程无锁（pcap 逐包判定每包一次查询，加锁是瓶颈）；旧快照交给 GC。
type Snapshot struct {
	v4 []netip.Prefix // radix 查询集合（排序后二分）
	v6 []netip.Prefix
	// 统计（建库时固化）
	Entries  int    // 原始段数
	Prefixes int    // 前缀数
	Skipped  int    // 建库时跳过的坏段（跨族/非法区间）
	SHA256   string // 源文件 sha256（重载跳过判据）
}

// NewSnapshot 由段集建快照。
func NewSnapshot(segs []Seg, sha256 string) *Snapshot {
	merged := mergeSegs(segs)
	ps, skipped := SegsToPrefixes(merged)
	s := &Snapshot{Entries: len(segs), SHA256: sha256, Skipped: skipped}
	s.splitFamilies(ps)
	return s
}

// mergeSegs 按 (Start,End) 排序后合并重叠/相邻段（同族）。
// 输出互不重叠——Contains 二分的前提。
func mergeSegs(segs []Seg) []Seg {
	if len(segs) < 2 {
		return segs
	}
	sorted := make([]Seg, len(segs))
	copy(sorted, segs)
	sort.Slice(sorted, func(i, j int) bool {
		if c := sorted[i].Start.Compare(sorted[j].Start); c != 0 {
			return c < 0
		}
		return sorted[i].End.Compare(sorted[j].End) < 0
	})
	out := sorted[:1]
	for _, s := range sorted[1:] {
		cur := &out[len(out)-1]
		if cur.Start.Is4() != s.Start.Is4() {
			out = append(out, s) // 跨族不合并
			continue
		}
		if cur.End.Compare(s.Start) >= 0 {
			if cur.End.Compare(s.End) < 0 {
				cur.End = s.End // 重叠：扩到更远的尾
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

func (s *Snapshot) splitFamilies(ps []netip.Prefix) {
	for _, p := range ps {
		if p.Addr().Is4() {
			s.v4 = append(s.v4, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()))
		} else {
			s.v6 = append(s.v6, p)
		}
	}
	// mergeSegs 按 start 排序 + 不重叠 → lastAddr 天然全序，无需再排
	s.Prefixes = len(s.v4) + len(s.v6)
}

// Contains 该地址是否在库内。
//
// 前缀集合来自「区间拆 CIDR」：单段内互不重叠，多段间可能重叠（源文件
// 同区间重复行）。建库时先按起止合并所有重叠/相邻段再拆前缀 → 合并后
// 互不重叠且 lastAddr 全序，Contains 用 sort.Search 二分（R5 复审实测
// 5 万前缀线性扫一次未命中 ~390µs，1 万对判定就是秒级 CPU）。
func (s *Snapshot) Contains(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.Is4() {
		a = a.Unmap()
		i := sort.Search(len(s.v4), func(i int) bool {
			return lastAddr(s.v4[i]).Compare(a) >= 0
		})
		return i < len(s.v4) && s.v4[i].Contains(a)
	}
	i := sort.Search(len(s.v6), func(i int) bool {
		return lastAddr(s.v6[i]).Compare(a) >= 0
	})
	return i < len(s.v6) && s.v6[i].Contains(a)
}

// Manager 每路径一库（设计修订：paths 直给，map[路径]*Snapshot）。
//
// ponytail: 库按路径全局唯一，不带 host 维度——多靶机同路径文件内容不同时，
// 后加载的覆盖先加载的（ip_lookup 无 host 概念，判定基准是最后一次加载）。
// 单靶机场景不受影响；多机差异化 IP 段出现时再把 key 扩成 host+path。
type Manager struct {
	libs atomic.Pointer[map[string]*Snapshot]
}

// NewManager 空管理器。
func NewManager() *Manager {
	m := &Manager{}
	m.libs.Store(&map[string]*Snapshot{})
	return m
}

// Set 原子替换一个路径的库（其余路径不动）。
func (m *Manager) Set(path string, snap *Snapshot) {
	cur := *m.libs.Load()
	next := make(map[string]*Snapshot, len(cur)+1)
	for k, v := range cur {
		next[k] = v
	}
	next[path] = snap
	m.libs.Store(&next)
}

// Get 读路径的库（无锁）；不存在返回 nil。
func (m *Manager) Get(path string) *Snapshot {
	return (*m.libs.Load())[path]
}

// Paths 当前已加载路径列表。
func (m *Manager) Paths() []string {
	cur := *m.libs.Load()
	out := make([]string, 0, len(cur))
	for k := range cur {
		out = append(out, k)
	}
	return out
}

// Direction (src,dst) 四态判定（相对指定库）。
func (s *Snapshot) Direction(src, dst netip.Addr) string {
	srcIn := s.Contains(src)
	dstIn := s.Contains(dst)
	switch {
	case srcIn && dstIn:
		return "internal"
	case srcIn:
		return "outbound"
	case dstIn:
		return "inbound"
	default:
		return "external"
	}
}
