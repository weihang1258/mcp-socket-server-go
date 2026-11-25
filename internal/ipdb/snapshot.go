package ipdb

import (
	"net/netip"
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
	SHA256   string // 源文件 sha256（重载跳过判据）
}

// NewSnapshot 由段集建快照。
func NewSnapshot(segs []Seg, sha256 string) *Snapshot {
	ps, skipped := SegsToPrefixes(segs)
	s := &Snapshot{Entries: len(segs), SHA256: sha256}
	s.splitFamilies(ps)
	_ = skipped // 跨族段已在 SegsToPrefixes 计入返回值；快照层只存有效部分
	return s
}

func (s *Snapshot) splitFamilies(ps []netip.Prefix) {
	for _, p := range ps {
		if p.Addr().Is4() {
			s.v4 = append(s.v4, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()))
		} else {
			s.v6 = append(s.v6, p)
		}
	}
	s.Prefixes = len(s.v4) + len(s.v6)
}

// Contains 该地址是否在库内。
//
// 查询结构不用显式 radix 树：前缀集合来自「区间拆 CIDR」，天然**互不重叠**
// （rangeToPrefixes 输出保证），且每段查询可化为「找任一前缀包含 a」。
// 5 万前缀线性扫是毫秒级、1 万对 IP 判定也就一次建库成本——按 ponytail 原则
// 先线性；若生产 house 文件涨到十万段量级再换 lastAddr 排序二分（ ponytail:
// 线性扫，10 万段以上换排序+二分）。
func (s *Snapshot) Contains(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.Is4() {
		a = a.Unmap()
		for i := range s.v4 {
			if s.v4[i].Contains(a) {
				return true
			}
		}
		return false
	}
	for i := range s.v6 {
		if s.v6[i].Contains(a) {
			return true
		}
	}
	return false
}

// Manager 每路径一库（设计修订：paths 直给，map[路径]*Snapshot）。
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
