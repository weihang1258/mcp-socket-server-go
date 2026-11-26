package ipdb

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// FileFetcher 读远端文件的抽象（mcpbridge.Client 满足；解耦避免 import cycle）。
type FileFetcher interface {
	DownloadFile(path string) ([]byte, error)
}

// Loader 从靶机拉 ipsegs 文件建库（S2 加载层）。
// 读文件走现成 dt3 下载（0 协议改动）；sha256 没变的文件跳过重建。
type Loader struct {
	mu    sync.Mutex
	mgr   *Manager
	cache map[string]string // path → 上次 sha256（跳过重建判据）
}

// NewLoader 空加载器。
func NewLoader() *Loader {
	return &Loader{mgr: NewManager(), cache: map[string]string{}}
}

// Manager 暴露查询侧（ip_lookup / pcap 流联动用）。
func (l *Loader) Manager() *Manager { return l.mgr }

// LoadResult 单路径加载结果。
type LoadResult struct {
	Path     string `json:"path"`
	Entries  int    `json:"entries"`
	Prefixes int    `json:"prefixes"`
	SHA256   string `json:"sha256"`
	Elapsed  int64  `json:"elapsed_ms"`
	Skipped  bool   `json:"skipped,omitempty"` // sha 未变，复用上一库
	Warning  string `json:"warning,omitempty"` // 建库时跳过了坏段
	Error    string `json:"error,omitempty"`
}

// Load 从靶机拉 paths 逐个建库。
// 下载/解析不持锁（R5-D3：锁跨远端 IO 会把全进程 ip_db_load 串行化到
// socket 超时量级），mu 只护 cache 查改与 Manager.Set 的原子替换。
func (l *Loader) Load(c FileFetcher, paths []string) []LoadResult {
	out := make([]LoadResult, 0, len(paths))
	for _, p := range paths {
		out = append(out, l.loadOne(c, p))
	}
	return out
}

func (l *Loader) loadOne(c FileFetcher, path string) LoadResult {
	t0 := time.Now()
	res := LoadResult{Path: path}
	content, err := c.DownloadFile(path) // 无锁：远端 IO
	if err != nil {
		res.Error = fmt.Sprintf("读取文件失败: %v", err)
		return res
	}
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])
	res.SHA256 = sha
	// cache 查与 mgr.Get 必须在同一 mu 区间：Get 放锁外的话，另一 goroutine
	// 的 Set 可在两步之间替换该路径快照 → skipped=true 却报另一份内容的
	// 统计（R5-A5）。Manager.Get 自身原子，但「sha 未变」与「库未变」要一致。
	l.mu.Lock()
	old, hadOld := l.cache[path]
	if hadOld && old == sha {
		if cur := l.mgr.Get(path); cur != nil {
			l.mu.Unlock()
			res.Skipped = true
			res.Entries = cur.Entries
			res.Prefixes = cur.Prefixes
			res.Elapsed = time.Since(t0).Milliseconds()
			return res
		}
	}
	l.mu.Unlock()
	segs := ParseFile(string(content))
	snap := NewSnapshot(segs, sha) // 无锁：纯 CPU
	l.mu.Lock()
	l.mgr.Set(path, snap)
	l.cache[path] = sha
	l.mu.Unlock()
	res.Entries = snap.Entries
	res.Prefixes = snap.Prefixes
	res.Elapsed = time.Since(t0).Milliseconds()
	if snap.Skipped > 0 {
		res.Warning = fmt.Sprintf("%d 段解析失败被跳过（跨族/非法区间）", snap.Skipped)
	}
	log.Printf("ipdb 已加载 %s：%d 段 → %d 前缀（跳过 %d，sha %s…）", path, snap.Entries, snap.Prefixes, snap.Skipped, sha[:12])
	return res
}
