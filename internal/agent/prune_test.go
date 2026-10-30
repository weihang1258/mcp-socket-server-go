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
