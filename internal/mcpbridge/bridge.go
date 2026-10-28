// Package mcpbridge 复刻 mcp_socket_server（中央 MCP 桥，设计 §4/§5）。
package mcpbridge

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// ---- 锁（locks.py 移植）----

// Lk 锁类（LockClass）。
type Lk int

const (
	LkNone Lk = iota
	LkCapture
	LkFileIO
	LkShell
	LkBrowser
	LkSystem
	LkReplay
)

func (l Lk) String() string {
	switch l {
	case LkCapture:
		return "capture"
	case LkFileIO:
		return "file_io"
	case LkShell:
		return "shell"
	case LkBrowser:
		return "browser"
	case LkSystem:
		return "system"
	case LkReplay:
		return "replay"
	}
	return "none"
}

// LockConflict 冲突错误（B07：target 由 manager 回填文案）。
type LockConflict struct {
	Target string
	Class  Lk
	Key    string
}

func (e *LockConflict) Error() string {
	parts := []string{fmt.Sprintf("靶机 %s", e.Target), fmt.Sprintf("锁类 %s", e.Class)}
	if e.Key != "" {
		parts = append(parts, "key="+e.Key)
	}
	return strings.Join(parts, " ") + " 冲突"
}

type targetLock struct {
	mu        sync.Mutex
	captures  map[string]int // key(path) → 占用
	exclusive Lk
	exCount   int
}

// LockManager 全局锁管理（单例语义由上层持有）。
type LockManager struct {
	mu    sync.Mutex
	locks map[string]*targetLock
}

func NewLockManager() *LockManager {
	return &LockManager{locks: map[string]*targetLock{}}
}

func (m *LockManager) tl(target string) *targetLock {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.locks[target]
	if t == nil {
		t = &targetLock{captures: map[string]int{}}
		m.locks[target] = t
	}
	return t
}

// TryAcquire fail-fast；冲突返回 *LockConflict（文案已回填 target）。
func (m *LockManager) TryAcquire(target string, class Lk, key string) error {
	if class == LkNone {
		return nil
	}
	tl := m.tl(target)
	tl.mu.Lock()
	defer tl.mu.Unlock()
	k := key
	if class == LkCapture {
		if tl.exclusive != LkNone {
			return &LockConflict{Target: target, Class: class, Key: k}
		}
		if _, busy := tl.captures[k]; busy {
			return &LockConflict{Target: target, Class: class, Key: k}
		}
		tl.captures[k] = 1
		return nil
	}
	if tl.exclusive != LkNone {
		return &LockConflict{Target: target, Class: class}
	}
	if len(tl.captures) > 0 {
		keys := make([]string, 0, len(tl.captures))
		for kk := range tl.captures {
			keys = append(keys, kk)
		}
		return &LockConflict{Target: target, Class: class, Key: strings.Join(keys, ",")}
	}
	tl.exclusive = class
	tl.exCount++
	return nil
}

// Release 释放（幂等）。
func (m *LockManager) Release(target string, class Lk, key string) {
	if class == LkNone {
		return
	}
	m.mu.Lock()
	tl := m.locks[target]
	m.mu.Unlock()
	if tl == nil {
		return
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if class == LkCapture {
		delete(tl.captures, key)
		return
	}
	if tl.exclusive == class {
		tl.exCount--
		if tl.exCount <= 0 {
			tl.exclusive = LkNone
		}
	}
}

// Acquire 阻塞语义占位（当前调用方均 fail-fast）。
func (m *LockManager) Acquire(target string, class Lk, key string) error {
	return m.TryAcquire(target, class, key)
}

// HasActive 靶机是否有任何活跃锁。
func (m *LockManager) HasActive(target string) bool {
	m.mu.Lock()
	tl := m.locks[target]
	m.mu.Unlock()
	if tl == nil {
		return false
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return len(tl.captures) > 0 || tl.exclusive != LkNone
}

// ReleaseTarget 安全释放（吞异常）。
func (m *LockManager) ReleaseTarget(target string, class Lk, key string) {
	m.Release(target, class, key)
}

// ---- 注册表（registry.py 移植）----

type Registry struct {
	mu   sync.Mutex
	conn *sql.DB
}

func OpenRegistry(dbPath string) (*Registry, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1) // 单写连接（§11 并发条目）
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(`CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 9000,
		tags TEXT NOT NULL DEFAULT '[]',
		note TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		listen_liveness INTEGER NOT NULL DEFAULT 0,
		UNIQUE(host, port))`); err != nil {
		return nil, err
	}
	// 旧表迁移（v0.2.1 语义：缺列 ALTER）
	cols, err := listColumns(conn, "targets")
	if err == nil && !containsStr(cols, "listen_liveness") {
		if _, err := conn.Exec("ALTER TABLE targets ADD COLUMN listen_liveness INTEGER NOT NULL DEFAULT 0"); err != nil {
			return nil, err
		}
	}
	return &Registry{conn: conn}, nil
}

func listColumns(conn *sql.DB, table string) ([]string, error) {
	rows, err := conn.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// AddTarget INSERT OR IGNORE；返回 {"ok":bool}。
func (r *Registry) AddTarget(host string, port int, tags []string, note string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	tagsJSON, _ := json.Marshal(tags)
	if _, err := r.conn.Exec("INSERT OR IGNORE INTO targets (host, port, tags, note) VALUES (?,?,?,?)",
		host, port, string(tagsJSON), note); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true, "host": host, "port": port}
}

// RemoveTarget 行数为 0 → 靶机不存在。
func (r *Registry) RemoveTarget(host string, port int) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	res, err := r.conn.Exec("DELETE FROM targets WHERE host=? AND port=?", host, port)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return map[string]any{"ok": false, "error": "靶机不存在"}
	}
	return map[string]any{"ok": true}
}

// ListTargets 全量（created_at 序）。
func (r *Registry) ListTargets() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	rows, err := r.conn.Query("SELECT host, port, tags, note, created_at FROM targets ORDER BY created_at")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var host, tags, note, created string
		var port int
		if err := rows.Scan(&host, &port, &tags, &note, &created); err != nil {
			continue
		}
		var tagList []string
		json.Unmarshal([]byte(tags), &tagList)
		out = append(out, map[string]any{"host": host, "port": port, "tags": tagList, "note": note, "created_at": created})
	}
	return out
}

// Resolve @tag 展开 + host:port 拆分（首冒号后全数字才拆；fd00::5 不拆）。
func (r *Registry) Resolve(targets []string) []string {
	r.mu.Lock()
	rows, err := r.conn.Query("SELECT host, tags FROM targets")
	tagMap := map[string][]string{}
	if err == nil {
		for rows.Next() {
			var host, tags string
			if rows.Scan(&host, &tags) == nil {
				var tagList []string
				json.Unmarshal([]byte(tags), &tagList)
				for _, tg := range tagList {
					tagMap[tg] = append(tagMap[tg], host)
				}
			}
		}
		rows.Close()
	}
	r.mu.Unlock()

	var out []string
	for _, item := range targets {
		if strings.HasPrefix(item, "@") {
			out = append(out, tagMap[item[1:]]...)
			continue
		}
		// Python registry.py:107 语义：第一个冒号后的子串 isdigit 才拆
		if idx := strings.Index(item, ":"); idx >= 0 && isAllDigits(item[idx+1:]) {
			out = append(out, item[:idx])
			continue
		}
		out = append(out, item)
	}
	return out
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// SetListenLiveness / GetListenLiveness（B16）。
func (r *Registry) SetListenLiveness(host string, port int, alive bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := 0
	if alive {
		v = 1
	}
	r.conn.Exec("UPDATE targets SET listen_liveness=? WHERE host=? AND port=?", v, host, port)
}

func (r *Registry) GetListenLiveness(host string, port int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	var v int
	err := r.conn.QueryRow("SELECT listen_liveness FROM targets WHERE host=? AND port=?", host, port).Scan(&v)
	return err == nil && v != 0
}

func (r *Registry) Close() error { return r.conn.Close() }

// ---- 审计（audit.py 移植）----

type AuditEntry struct {
	Tool        string
	Params      map[string]any
	OkCount     int
	FailedCount int
	DurationMs  int
}

type Audit struct {
	mu   sync.Mutex
	conn *sql.DB
}

func OpenAudit(dbPath string, retentionDays int) (*Audit, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(`CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts TEXT NOT NULL,
		source_ip TEXT NOT NULL DEFAULT 'internal',
		tool TEXT NOT NULL,
		params TEXT NOT NULL DEFAULT '{}',
		ok_count INTEGER NOT NULL DEFAULT 0,
		failed_count INTEGER NOT NULL DEFAULT 0,
		outcomes TEXT NOT NULL DEFAULT '[]',
		duration_ms INTEGER NOT NULL DEFAULT 0)`); err != nil {
		return nil, err
	}
	if retentionDays > 0 {
		conn.Exec("DELETE FROM audit_log WHERE ts < datetime('now', ?)", fmt.Sprintf("-%d days", retentionDays))
	}
	return &Audit{conn: conn}, nil
}

// truncateParams 参数值字符串 >200 截断 + "..."（audit.py 同语义）。
func truncateParams(params map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range params {
		s := fmt.Sprint(v)
		if len(s) > 200 {
			out[k] = s[:200] + "..."
			continue
		}
		out[k] = v
	}
	return out
}

// Write 写一条审计。
func (a *Audit) Write(tool string, params map[string]any, outcomes []map[string]any, okCount, failedCount, durationMs int, sourceIP string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	pJSON, _ := json.Marshal(truncateParams(params))
	oJSON, _ := json.Marshal(outcomes)
	if sourceIP == "" {
		sourceIP = "internal"
	}
	a.conn.Exec("INSERT INTO audit_log (ts, source_ip, tool, params, ok_count, failed_count, outcomes, duration_ms)"+
		" VALUES (datetime('now'),?,?,?,?,?,?,?)", sourceIP, tool, string(pJSON), okCount, failedCount, string(oJSON), durationMs)
}

// LastEntry 测试辅助：最近一条。
func (a *Audit) LastEntry() *AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var tool, params string
	var okCount, failedCount, durationMs int
	err := a.conn.QueryRow("SELECT tool, params, ok_count, failed_count, duration_ms FROM audit_log ORDER BY id DESC LIMIT 1").
		Scan(&tool, &params, &okCount, &failedCount, &durationMs)
	if err != nil {
		return nil
	}
	var pMap map[string]any
	json.Unmarshal([]byte(params), &pMap)
	return &AuditEntry{Tool: tool, Params: pMap, OkCount: okCount, FailedCount: failedCount, DurationMs: durationMs}
}

func (a *Audit) Close() error { return a.conn.Close() }
