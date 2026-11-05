package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// /opt/socket/versions 只增不减：真机 25 个版本 389MB。每次升级都留一份，
// 长期跑下去会撑满磁盘。保留最近 N 个，其余删掉。
func TestPruneOldVersionsKeepsRecent(t *testing.T) {
	dir := t.TempDir()
	prevRoot := upgradeRoot
	defer func() { upgradeRoot = prevRoot }()
	upgradeRoot = dir

	for _, v := range []string{"1.0.0", "1.5.0", "1.9.0", "1.9.3", "1.9.4", "1.9.5"} {
		d := filepath.Join(dir, "versions", v)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "socket_server"), []byte("BIN"), 0o755)
	}

	if err := pruneOldVersions("1.9.5", 3); err != nil {
		t.Fatalf("pruneOldVersions: %v", err)
	}

	left, _ := os.ReadDir(filepath.Join(dir, "versions"))
	var names []string
	for _, e := range left {
		names = append(names, e.Name())
	}
	// 1.9.5（当前）+ 1.9.4 + 1.9.3 = 3 个
	if len(names) != 3 {
		t.Fatalf("应保留 3 个版本，实际 %d: %v", len(names), names)
	}
	for _, want := range []string{"1.9.5", "1.9.4", "1.9.3"} {
		if _, err := os.Stat(filepath.Join(dir, "versions", want)); err != nil {
			t.Fatalf("应保留 %s: %v", want, err)
		}
	}
}

// current 指向的版本永远不能删——删了服务就起不来了。
func TestPruneOldVersionsNeverDeletesCurrent(t *testing.T) {
	dir := t.TempDir()
	prevRoot := upgradeRoot
	defer func() { upgradeRoot = prevRoot }()
	upgradeRoot = dir

	// 只有 "1.0.0" 一个版本，但它是 current，且 keep=0（极端）
	d := filepath.Join(dir, "versions", "1.0.0")
	os.MkdirAll(d, 0o755)
	if err := pruneOldVersions("1.0.0", 0); err != nil {
		t.Fatalf("pruneOldVersions: %v", err)
	}
	if _, err := os.Stat(d); err != nil {
		t.Fatalf("current 版本绝不能被删: %v", err)
	}
}

// 启动时也要清理（v1.9.8）：验收发现首次 upgrade_run 不清理——执行 switchTo
// 的是升级前的旧进程（旧代码无 prune），切链+重启后没人再清。挂在启动路径后，
// 升级触发的自动重启就会带上这一步，一次 upgrade_run 即干净。
func TestPruneAtStartup(t *testing.T) {
	dir := t.TempDir()
	prevRoot, prevVer := upgradeRoot, Version
	defer func() { upgradeRoot, Version = prevRoot, prevVer }()
	upgradeRoot, Version = dir, "1.9.8"

	for _, v := range []string{"1.0.0", "1.5.0", "1.9.0", "1.9.7", "1.9.8"} {
		d := filepath.Join(dir, "versions", v)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "socket_server"), []byte("BIN"), 0o755)
	}

	PruneAtStartup()

	left, _ := os.ReadDir(filepath.Join(dir, "versions"))
	var names []string
	for _, e := range left {
		if e.Name() != "current" {
			names = append(names, e.Name())
		}
	}
	if len(names) != keepVersions {
		t.Fatalf("启动清理后应剩 %d 个版本，实际 %d: %v", keepVersions, len(names), names)
	}
	// 当前版本必须在
	if _, err := os.Stat(filepath.Join(dir, "versions", "1.9.8")); err != nil {
		t.Fatalf("当前版本必须保留: %v", err)
	}
}

// current 软链指向的版本永远不能删，即便它不是正在跑的版本、也不在最近 keep 内。
// 2026-11-02 本机实测：回滚后 current → 1.8.3（Python 版），起一个 v1.9.24 的
// agent 做验收，启动清理按 Version 保留最近 3 个，把 1.8.3 目录删掉 → 软链悬空，
// 下次 systemd 重启服务直接起不来。
func TestPruneOldVersionsNeverDeletesCurrentLinkTarget(t *testing.T) {
	dir := t.TempDir()
	prevRoot := upgradeRoot
	defer func() { upgradeRoot = prevRoot }()
	upgradeRoot = dir

	for _, v := range []string{"1.8.3", "1.9.21", "1.9.22", "1.9.23", "1.9.24"} {
		os.MkdirAll(filepath.Join(dir, "versions", v), 0o755)
	}
	if err := os.Symlink(filepath.Join(dir, "versions", "1.8.3"), filepath.Join(dir, "versions", "current")); err != nil {
		t.Fatalf("建软链: %v", err)
	}

	// 正在跑的是 1.9.24（回滚前的新版本），keep=2 → 1.8.3 本应被删
	if err := pruneOldVersions("1.9.24", 2); err != nil {
		t.Fatalf("pruneOldVersions: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "versions", "1.8.3")); err != nil {
		t.Fatalf("current 软链指向的版本绝不能被删: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "versions", "1.9.21")); err == nil {
		t.Fatalf("1.9.21 既非运行版本也非软链目标，应被清理")
	}
	// 软链必须仍然可达（悬空链 = 服务起不来）
	if _, err := os.Stat(filepath.Join(dir, "versions", "current", "socket_server")); err != nil &&
		!os.IsNotExist(err) {
		t.Fatalf("current 解析异常: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(dir, "versions", "current")); err != nil {
		t.Fatalf("current 软链丢失: %v", err)
	} else if filepath.Base(target) != "1.8.3" {
		t.Fatalf("current 指向被改写: %s", target)
	}
}
