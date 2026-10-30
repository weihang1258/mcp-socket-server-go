package agent

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// dt20 推送升级改 current 软链后只重启了 agent 单元。同机部署时 mcp 共享
// 同一个 current/socket_server，不一起重启就会继续跑旧二进制——与 install
// 那条路径同源（见 cmd/socketstack 的 mcp 漂移检测）。
func TestSwitchToRestartsMCPWhenActive(t *testing.T) {
	dir := t.TempDir()
	prevRoot, prevRestart := upgradeRoot, restartServiceFn
	prevMCPActive, prevMCPRestart := mcpActiveFn, mcpRestartFn
	defer func() {
		upgradeRoot, restartServiceFn = prevRoot, prevRestart
		mcpActiveFn, mcpRestartFn = prevMCPActive, prevMCPRestart
	}()
	upgradeRoot = dir
	restartServiceFn = func() error { return nil }

	version := "1.9.6"
	vdir := filepath.Join(dir, "versions", version)
	os.MkdirAll(vdir, 0o755)
	os.WriteFile(filepath.Join(vdir, "socket_server"), []byte("BIN"), 0o755)

	mcpActiveFn = func() bool { return true }
	var mcpRestarted atomic.Int32
	mcpRestartFn = func() error { mcpRestarted.Add(1); return nil }

	if !switchTo(version) {
		t.Fatal("switchTo 应成功")
	}
	if mcpRestarted.Load() != 1 {
		t.Fatalf("mcp 在跑时必须一并重启，实际 %d 次", mcpRestarted.Load())
	}
}

// mcp 未运行时不该去启动它（分机部署：靶机上没有 mcp 单元）。
func TestSwitchToLeavesInactiveMCPAlone(t *testing.T) {
	dir := t.TempDir()
	prevRoot, prevRestart := upgradeRoot, restartServiceFn
	prevMCPActive, prevMCPRestart := mcpActiveFn, mcpRestartFn
	defer func() {
		upgradeRoot, restartServiceFn = prevRoot, prevRestart
		mcpActiveFn, mcpRestartFn = prevMCPActive, prevMCPRestart
	}()
	upgradeRoot = dir
	restartServiceFn = func() error { return nil }

	version := "1.9.7"
	vdir := filepath.Join(dir, "versions", version)
	os.MkdirAll(vdir, 0o755)
	os.WriteFile(filepath.Join(vdir, "socket_server"), []byte("BIN"), 0o755)

	mcpActiveFn = func() bool { return false }
	var mcpRestarted atomic.Int32
	mcpRestartFn = func() error { mcpRestarted.Add(1); return nil }

	if !switchTo(version) {
		t.Fatal("switchTo 应成功")
	}
	if mcpRestarted.Load() != 0 {
		t.Fatalf("mcp 未运行不该被启动，实际 %d 次", mcpRestarted.Load())
	}
}
