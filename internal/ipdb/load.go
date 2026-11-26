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
func (l *Loader) Load(c FileFetcher, paths []string) []LoadResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LoadResult, 0, len(paths))
	for _, p := range paths {
		r := l.loadOne(c, p)
		out = append(out, r)
	}
	return out
}

func (l *Loader) loadOne(c FileFetcher, path string) LoadResult {
	t0 := time.Now()
	res := LoadResult{Path: path}
	content, err := c.DownloadFile(path)
	if err != nil {
		res.Error = fmt.Sprintf("读取文件失败: %v", err)
		return res
	}
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])
	res.SHA256 = sha
	if old, ok := l.cache[path]; ok && old == sha {
		if cur := l.mgr.Get(path); cur != nil {
			res.Skipped = true
			res.Entries = cur.Entries
			res.Prefixes = cur.Prefixes
			res.Elapsed = time.Since(t0).Milliseconds()
			return res
		}
	}
	segs := ParseFile(string(content))
	snap := NewSnapshot(segs, sha)
	l.mgr.Set(path, snap)
	l.cache[path] = sha
	res.Entries = snap.Entries
	res.Prefixes = snap.Prefixes
	res.Elapsed = time.Since(t0).Milliseconds()
	if snap.Skipped > 0 {
		res.Warning = fmt.Sprintf("%d 段解析失败被跳过（跨族/非法区间）", snap.Skipped)
	}
	log.Printf("ipdb 已加载 %s：%d 段 → %d 前缀（跳过 %d，sha %s…）", path, snap.Entries, snap.Prefixes, snap.Skipped, sha[:12])
	return res
}
