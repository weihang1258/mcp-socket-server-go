package svc

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 覆写 systemd 单元前必须留备份：写坏了没有回滚副本，只能重装。
func TestWriteUnitFileBacksUpExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.service")
	if err := os.WriteFile(path, []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := writeUnitFile(path, "NEW"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "NEW" {
		t.Fatalf("单元应被覆写为 NEW，实际 %q", data)
	}
	baks, _ := filepath.Glob(path + bakGlob)
	if len(baks) != 1 {
		t.Fatalf("覆写前须留 1 份备份，实际 %d 份: %v", len(baks), baks)
	}
	if b, _ := os.ReadFile(baks[0]); string(b) != "OLD" {
		t.Fatalf("备份内容应是旧单元 OLD，实际 %q", b)
	}
}

// 首次写入（文件不存在）不该造出空备份。
func TestWriteUnitFileNoBackupOnFirstWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.service")
	if _, err := writeUnitFile(path, "NEW"); err != nil {
		t.Fatal(err)
	}
	if baks, _ := filepath.Glob(path + bakGlob); len(baks) != 0 {
		t.Fatalf("首次写入不该有备份，实际 %v", baks)
	}
}

// 备份只保留最近 3 份，否则每次 install 都堆一个新文件。
func TestWriteUnitFileKeepsThreeBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.service")
	os.WriteFile(path, []byte("v0"), 0o644)
	for i := 0; i < 6; i++ {
		if _, err := writeUnitFile(path, "v"+string(rune('1'+i))); err != nil {
			t.Fatal(err)
		}
	}
	baks, _ := filepath.Glob(path + bakGlob)
	if len(baks) != maxUnitBackups {
		t.Fatalf("备份须只留 %d 份，实际 %d 份: %v", maxUnitBackups, len(baks), baks)
	}
}

// 内容没变就不备份也不写（EnsureUnitCorrect 每次启动都会走这里）。
func TestWriteUnitFileSkipsWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.service")
	os.WriteFile(path, []byte("same"), 0o644)
	if _, err := writeUnitFile(path, "same"); err != nil {
		t.Fatal(err)
	}
	if baks, _ := filepath.Glob(path + bakGlob); len(baks) != 0 {
		t.Fatalf("内容未变不该产生备份，实际 %v", baks)
	}
}

// 备份没建成（rename 失败）就不能覆写：否则「写坏可回滚」不成立，
// 而用户还以为有备份。这里用只读父目录制造 rename 失败。
func TestWriteUnitFileAbortsWhenBackupFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 无视目录权限，无法制造 rename 失败")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "x.service")
	if err := os.WriteFile(path, []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil { // 目录只读 → rename/write 全失败
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)

	_, err := writeUnitFile(path, "NEW")
	if err == nil {
		t.Fatal("备份失败时必须返回错误，不能静默覆写")
	}
	if data, _ := os.ReadFile(path); string(data) != "OLD" {
		t.Fatalf("备份失败后原文件须保持 OLD，实际 %q", data)
	}
}

// 存在但读不到的文件不能被当成「没有旧文件」直接覆写——那样是无备份冲掉内容。
// 断言必须是「原内容没被改动」，只断言 err != nil 太弱：WriteFile 自己也会因
// 权限失败而返回 error，把 guard 删掉测试照样绿。
func TestWriteUnitFileErrorsOnUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 无视文件权限")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "x.service")
	os.WriteFile(path, []byte("SECRET"), 0o644)
	// 只去掉读权限（保留写权限）：这样「无 guard 直接覆写」会真的成功，
	// 测试才能区分「有 guard」与「碰巧 WriteFile 也失败」。
	if err := os.Chmod(path, 0o200); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0o644)

	if _, err := writeUnitFile(path, "NEW"); err == nil {
		t.Fatal("读不到旧文件时应报错，不能当不存在直接覆写")
	}
	os.Chmod(path, 0o644)
	if data, _ := os.ReadFile(path); string(data) != "SECRET" {
		t.Fatalf("原内容须保持不变，实际 %q", data)
	}
}

// 备份名必须带稳定前缀，便于 Glob 与人工识别。
func TestBackupNameHasPrefix(t *testing.T) {
	if !strings.HasSuffix(bakGlob, "*") || !strings.HasPrefix(bakGlob, ".bak.") {
		t.Fatalf("bakGlob 形如 .bak.*，实际 %q", bakGlob)
	}
}

// 纳秒时间戳必须零填充到固定宽度，否则位数变化时字符串排序错乱、剪枝删错文件。
func TestBackupNameFixedWidth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.service")
	os.WriteFile(path, []byte("v0"), 0o644)
	// 极小与极大时间戳：宽度必须一致
	prev := timeNowFn
	defer func() { timeNowFn = prev }()
	for _, ns := range []int64{1, 999999999999999999} {
		timeNowFn = func() time.Time { return time.Unix(0, ns) }
		if _, err := writeUnitFile(path, "v"+strconv.FormatInt(ns, 10)); err != nil {
			t.Fatal(err)
		}
	}
	baks, _ := filepath.Glob(path + bakGlob)
	if len(baks) != 2 {
		t.Fatalf("应有 2 份备份，实际 %v", baks)
	}
	for _, b := range baks {
		stamp := strings.TrimPrefix(filepath.Base(b), filepath.Base(path)+bakPrefix)
		if len(stamp) != 19 {
			t.Fatalf("时间戳须零填充到 19 位，实际 %q（来自 %s）", stamp, b)
		}
	}
}

// 内容未变时 WriteUnit 不该 daemon-reload——EnsureUnitCorrect 每次启动都走这里。
// 用不可达的 PATH 让 systemctl 必然失败：只要它被调用，WriteUnit 就会返回错误。
func TestWriteUnitSkipsDaemonReloadWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.service")
	os.WriteFile(path, []byte("same"), 0o644)

	t.Setenv("PATH", dir) // 找不到 systemctl
	if err := WriteUnit(path, "same"); err != nil {
		t.Fatalf("内容未变不该触发 daemon-reload（找到了 systemctl）: %v", err)
	}
}
