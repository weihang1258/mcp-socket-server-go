package mcpbridge

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---- locks：per-target 多模式锁 fail-fast（locks.py 移植）----

func TestLocksBasenames(t *testing.T) {
	m := NewLockManager()
	// SHELL 排他获取/释放
	m.Acquire("t1", LkShell, "")
	if err := m.TryAcquire("t1", LkBrowser, ""); err == nil {
		t.Fatal("exclusive conflict expected")
	}
	m.Release("t1", LkShell, "")
	m.TryAcquire("t1", LkBrowser, "") // 释放后可获
	m.Release("t1", LkBrowser, "")

	// CAPTURE 按 path 排他
	m.TryAcquire("t2", LkCapture, "/a.pcap")
	if err := m.TryAcquire("t2", LkCapture, "/a.pcap"); err == nil {
		t.Fatal("same path conflict")
	}
	m.TryAcquire("t2", LkCapture, "/b.pcap") // 不同 path 并行
	if err := m.TryAcquire("t2", LkShell, ""); err == nil {
		t.Fatal("shell vs captures conflict")
	}
	m.Release("t2", LkCapture, "/a.pcap")
	m.Release("t2", LkCapture, "/b.pcap")
	m.TryAcquire("t2", LkShell, "")
	m.Release("t2", LkShell, "")

	// 冲突文案回填 target（B07）
	err := func() (err error) {
		m.TryAcquire("host9", LkShell, "")
		defer m.Release("host9", LkShell, "")
		err = m.TryAcquire("host9", LkReplay, "")
		return
	}()
	if err == nil || !contains(err.Error(), "host9") {
		t.Fatalf("conflict msg must carry target: %v", err)
	}
	// has_active / release_target 静默兜底
	m.TryAcquire("t3", LkSystem, "")
	if !m.HasActive("t3") {
		t.Fatal("has_active true expected")
	}
	m.ReleaseTarget("t3", LkSystem, "")
	m.ReleaseTarget("t3", LkSystem, "") // 二次不炸
	if m.HasActive("t3") {
		t.Fatal("cleared")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexStr(s, sub) >= 0)
}

func indexStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ---- registry：SQLite + @tag 解析（registry.py 移植）----

func TestRegistryBasics(t *testing.T) {
	db := filepath.Join(t.TempDir(), "reg.db")
	r, err := OpenRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if resp := r.AddTarget("10.1.1.1", 9000, []string{"gpu", "lab"}, "note1"); !resp["ok"].(bool) {
		t.Fatalf("add: %v", resp)
	}
	r.AddTarget("10.1.1.2", 9000, []string{"lab"}, "")
	r.AddTarget("10.1.1.1", 9000, nil, "") // 重复 INSERT OR IGNORE

	// list
	tl := r.ListTargets()
	if len(tl) != 2 {
		t.Fatalf("list: %v", tl)
	}
	// @tag 展开
	if got := r.Resolve([]string{"@gpu"}); len(got) != 1 || got[0] != "10.1.1.1" {
		t.Fatalf("resolve @gpu: %v", got)
	}
	if got := r.Resolve([]string{"@lab"}); len(got) != 2 {
		t.Fatalf("resolve @lab: %v", got)
	}
	// unknown tag 静默跳过
	if got := r.Resolve([]string{"@nope", "10.9.9.9"}); len(got) != 1 || got[0] != "10.9.9.9" {
		t.Fatalf("unknown tag: %v", got)
	}
	// host:port 拆分（首冒号后全数字才拆；fd00::5 不拆——复审修正后的 quirk）
	if got := r.Resolve([]string{"host:9100"}); got[0] != "host" {
		t.Fatalf("host:port split: %v", got)
	}
	if got := r.Resolve([]string{"fd00::5"}); got[0] != "fd00::5" {
		t.Fatalf("v6 must not split: %v", got)
	}
	// remove
	if resp := r.RemoveTarget("10.1.1.2", 9000); !resp["ok"].(bool) {
		t.Fatal("remove")
	}
	if resp := r.RemoveTarget("10.1.1.2", 9000); resp["ok"].(bool) {
		t.Fatal("remove again must fail 靶机不存在")
	}
	// liveness
	r.SetListenLiveness("10.1.1.1", 9000, true)
	if !r.GetListenLiveness("10.1.1.1", 9000) {
		t.Fatal("liveness true")
	}
	r.SetListenLiveness("10.1.1.1", 9000, false)
	if r.GetListenLiveness("10.1.1.1", 9000) {
		t.Fatal("liveness false")
	}
}

// 持久化：重开同一 DB 数据仍在
func TestRegistryPersistence(t *testing.T) {
	db := filepath.Join(t.TempDir(), "reg.db")
	r1, _ := OpenRegistry(db)
	r1.AddTarget("10.2.2.2", 9100, []string{"x"}, "")
	r1.Close()
	r2, _ := OpenRegistry(db)
	defer r2.Close()
	if got := r2.ListTargets(); len(got) != 1 || got[0]["host"] != "10.2.2.2" {
		t.Fatalf("persist: %v", got)
	}
}

// ---- audit：SQLite 审计（audit.py 移植）----

func TestAuditWriteAndRetention(t *testing.T) {
	db := filepath.Join(t.TempDir(), "audit.db")
	a, err := OpenAudit(db, 90)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.Write("cmd_exec", map[string]any{"args": stringsRepeat("x", 300), "wait": true},
		[]map[string]any{{"target": "t1", "ok": true}},
		1, 0, 123, "internal")
	// 参数截断 200+...
	got := a.LastEntry()
	if got == nil || got.Tool != "cmd_exec" {
		t.Fatalf("last: %v", got)
	}
	args := got.Params["args"].(string)
	if len(args) != 203 || args[200:] != "..." {
		t.Fatalf("truncate 200+...: %q", args)
	}
	if got.OkCount != 1 || got.DurationMs != 123 {
		t.Fatalf("counts: %+v", got)
	}
	// retention=0 不清理
	if _, err := os.Stat(db); err != nil {
		t.Fatal(err)
	}
}

func stringsRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

// 并发写安全（-race 佐证）
func TestAuditConcurrent(t *testing.T) {
	db := filepath.Join(t.TempDir(), "audit2.db")
	a, _ := OpenAudit(db, 0)
	defer a.Close()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Write("tool", map[string]any{}, nil, 0, 0, 0, "internal")
		}()
	}
	wg.Wait()
}

// 默认 db_path 是 /var/lib/socketstack/mcp.db（§12#11 有意改成绝对路径），全新机器上
// 该目录不存在。Python 默认 ./mcp_socket_server.db 因 cwd 必存在而踩不到，Go 这条改动
// 把它变成硬崩（log.Fatalf "unable to open database file"）。Open 层须自建父目录。
func TestOpenRegistryCreatesMissingParentDir(t *testing.T) {
	db := filepath.Join(t.TempDir(), "a", "b", "fresh.db")
	r, err := OpenRegistry(db)
	if err != nil {
		t.Fatalf("父目录缺失时须自建: %v", err)
	}
	defer r.Close()
	if _, err := os.Stat(db); err != nil {
		t.Fatalf("db 文件未创建: %v", err)
	}
}

func TestOpenAuditCreatesMissingParentDir(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x", "y", "fresh.db")
	a, err := OpenAudit(db, 90)
	if err != nil {
		t.Fatalf("父目录缺失时须自建: %v", err)
	}
	defer a.Close()
	if _, err := os.Stat(db); err != nil {
		t.Fatalf("db 文件未创建: %v", err)
	}
}

// db_path 写成已存在的目录时，sqlite 只回 "unable to open database file:
// out of memory (14)"——完全看不出是配置写错了。须给出能读懂的错误。
func TestOpenRegistryRejectsDirectoryPath(t *testing.T) {
	dir := t.TempDir()
	_, err := OpenRegistry(dir)
	if err == nil {
		t.Fatal("db_path 指向目录须报错")
	}
	if strings.Contains(err.Error(), "out of memory") {
		t.Fatalf("错误信息须可读，不得是 sqlite 的 out of memory: %v", err)
	}
	if !strings.Contains(err.Error(), "目录") {
		t.Fatalf("错误信息须点明是目录: %v", err)
	}
}

func TestOpenAuditRejectsDirectoryPath(t *testing.T) {
	dir := t.TempDir()
	_, err := OpenAudit(dir, 90)
	if err == nil {
		t.Fatal("db_path 指向目录须报错")
	}
	if !strings.Contains(err.Error(), "目录") {
		t.Fatalf("错误信息须点明是目录: %v", err)
	}
}
