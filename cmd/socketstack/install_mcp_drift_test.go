package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// install（不带 --with-mcp）时，若 mcp 单元正在跑被替换掉的旧 inode，必须顺手
// restart 它——只重启，不改 mcp 配置（用户可能是分机部署，不想让 install 碰 mcp）。
func TestInstallRestartsDriftedMCP(t *testing.T) {
	dir := t.TempDir()
	prevExe, prevDirs := exePathFn, svcEnsureDirs
	prevVersions, prevBin := svcVersionsDir, svcBinPath
	prevEnable, prevRestart := svcAgentEnable, svcAgentRestartFn
	prevMCPActive, prevMCPRestart := svcMCPActive, svcMCPRestartFn
	prevPID, prevExe2, prevInode, prevExec := mainPIDFn, procExeFn, statInodeFn, execStartPathFn
	defer func() {
		exePathFn, svcEnsureDirs = prevExe, prevDirs
		svcVersionsDir, svcBinPath = prevVersions, prevBin
		svcAgentEnable, svcAgentRestartFn = prevEnable, prevRestart
		svcMCPActive, svcMCPRestartFn = prevMCPActive, prevMCPRestart
		mainPIDFn, procExeFn, statInodeFn, execStartPathFn = prevPID, prevExe2, prevInode, prevExec
	}()
	svcVersionsDir = filepath.Join(dir, "versions")
	svcBinPath = filepath.Join(dir, "bin", "socketstack")
	os.MkdirAll(filepath.Dir(svcBinPath), 0o755)
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("BIN"), 0o755)
	exePathFn = func() (string, error) { return src, nil }
	svcEnsureDirs = func() error { return nil }
	svcAgentEnable = func() error { return nil }
	svcAgentRestartFn = func() error { return nil }
	svcMCPActive = func() bool { return true }
	execStartPathFn = func(string) string { return "" }
	// mcp 跑在已删除的 inode 上
	mainPIDFn = func(unit string) int {
		if unit == "socketstack-mcp" {
			return 77
		}
		return 0
	}
	procExeFn = func(pid int) string { return "/opt/socket/versions/current/socket_server (deleted)" }
	statInodeFn = func(string) uint64 { return 1 }
	var mcpRestarts atomic.Int32
	svcMCPRestartFn = func() error { mcpRestarts.Add(1); return nil }

	if err := installSelf(false); err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	if mcpRestarts.Load() != 1 {
		t.Fatalf("mcp 跑旧 inode 时须 restart 1 次，实际 %d", mcpRestarts.Load())
	}
}

// mcp 未运行 / 没有漂移时，install 不该动它。
func TestInstallLeavesHealthyMCPAlone(t *testing.T) {
	dir := t.TempDir()
	prevExe, prevDirs := exePathFn, svcEnsureDirs
	prevVersions, prevBin := svcVersionsDir, svcBinPath
	prevEnable, prevRestart := svcAgentEnable, svcAgentRestartFn
	prevMCPActive, prevMCPRestart := svcMCPActive, svcMCPRestartFn
	prevPID, prevExe2, prevInode, prevExec := mainPIDFn, procExeFn, statInodeFn, execStartPathFn
	defer func() {
		exePathFn, svcEnsureDirs = prevExe, prevDirs
		svcVersionsDir, svcBinPath = prevVersions, prevBin
		svcAgentEnable, svcAgentRestartFn = prevEnable, prevRestart
		svcMCPActive, svcMCPRestartFn = prevMCPActive, prevMCPRestart
		mainPIDFn, procExeFn, statInodeFn, execStartPathFn = prevPID, prevExe2, prevInode, prevExec
	}()
	svcVersionsDir = filepath.Join(dir, "versions")
	svcBinPath = filepath.Join(dir, "bin", "socketstack")
	os.MkdirAll(filepath.Dir(svcBinPath), 0o755)
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("BIN"), 0o755)
	exePathFn = func() (string, error) { return src, nil }
	svcEnsureDirs = func() error { return nil }
	svcAgentEnable = func() error { return nil }
	svcAgentRestartFn = func() error { return nil }
	svcMCPActive = func() bool { return false } // 未运行
	execStartPathFn = func(string) string { return "" }
	var mcpRestarts atomic.Int32
	svcMCPRestartFn = func() error { mcpRestarts.Add(1); return nil }

	if err := installSelf(false); err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	if mcpRestarts.Load() != 0 {
		t.Fatalf("mcp 未运行不该被启动，实际 restart %d 次", mcpRestarts.Load())
	}
}

// 重启后仍然漂移（单元 ExecStart 指向别处）时必须如实告警，不能说「已重启」了事。
func TestInstallWarnsWhenDriftPersistsAfterRestart(t *testing.T) {
	dir := t.TempDir()
	prevExe, prevDirs := exePathFn, svcEnsureDirs
	prevVersions, prevBin := svcVersionsDir, svcBinPath
	prevEnable, prevRestart := svcAgentEnable, svcAgentRestartFn
	prevMCPActive, prevMCPRestart := svcMCPActive, svcMCPRestartFn
	prevPID, prevExe2, prevInode, prevExec := mainPIDFn, procExeFn, statInodeFn, execStartPathFn
	defer func() {
		exePathFn, svcEnsureDirs = prevExe, prevDirs
		svcVersionsDir, svcBinPath = prevVersions, prevBin
		svcAgentEnable, svcAgentRestartFn = prevEnable, prevRestart
		svcMCPActive, svcMCPRestartFn = prevMCPActive, prevMCPRestart
		mainPIDFn, procExeFn, statInodeFn, execStartPathFn = prevPID, prevExe2, prevInode, prevExec
	}()
	svcVersionsDir = filepath.Join(dir, "versions")
	svcBinPath = filepath.Join(dir, "bin", "socketstack")
	os.MkdirAll(filepath.Dir(svcBinPath), 0o755)
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("BIN"), 0o755)
	exePathFn = func() (string, error) { return src, nil }
	svcEnsureDirs = func() error { return nil }
	svcAgentEnable = func() error { return nil }
	svcAgentRestartFn = func() error { return nil }
	svcMCPActive = func() bool { return true }
	// 无论重启多少次，进程始终跑已删除的旧文件
	mainPIDFn = func(unit string) int {
		if unit == "socketstack-mcp" {
			return 77
		}
		return 0
	}
	procExeFn = func(int) string { return "/x/socket_server (deleted)" }
	execStartPathFn = func(string) string { return "" }
	statInodeFn = func(string) uint64 { return 1 }
	var n int
	svcMCPRestartFn = func() error { n++; return nil }

	// 关键：重启本身返回 nil（systemctl 成功），但进程仍在旧 inode。
	// installSelf 必须复检并如实告警，不能因为 restart 没报错就宣布「已重启」。
	got := captureInstallOutput(t, func() {
		if err := installSelf(false); err != nil {
			t.Fatalf("installSelf: %v", err)
		}
	})
	if n != 1 {
		t.Fatalf("应尝试 restart 1 次，实际 %d", n)
	}
	if !strings.Contains(got, "已重启，但仍与磁盘二进制不一致") {
		t.Fatalf("重启后仍漂移时必须如实告警，实际输出:\n%s", got)
	}
}

// mcp active 且无漂移 → install 不该 restart 它。stubNoDrift 把 svcMCPActive
// 强制为 false，原来那条用例其实没覆盖到 else-if 的短路语义。
func TestInstallNoRestartWhenMCPHealthy(t *testing.T) {
	dir := t.TempDir()
	prevExe, prevDirs := exePathFn, svcEnsureDirs
	prevVersions, prevBin := svcVersionsDir, svcBinPath
	prevEnable, prevRestart := svcAgentEnable, svcAgentRestartFn
	prevMCPActive, prevMCPRestart := svcMCPActive, svcMCPRestartFn
	prevPID, prevExe2, prevInode, prevExec := mainPIDFn, procExeFn, statInodeFn, execStartPathFn
	defer func() {
		exePathFn, svcEnsureDirs = prevExe, prevDirs
		svcVersionsDir, svcBinPath = prevVersions, prevBin
		svcAgentEnable, svcAgentRestartFn = prevEnable, prevRestart
		svcMCPActive, svcMCPRestartFn = prevMCPActive, prevMCPRestart
		mainPIDFn, procExeFn, statInodeFn, execStartPathFn = prevPID, prevExe2, prevInode, prevExec
	}()
	svcVersionsDir = filepath.Join(dir, "versions")
	svcBinPath = filepath.Join(dir, "bin", "socketstack")
	os.MkdirAll(filepath.Dir(svcBinPath), 0o755)
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("BIN"), 0o755)
	exePathFn = func() (string, error) { return src, nil }
	svcEnsureDirs = func() error { return nil }
	svcAgentEnable = func() error { return nil }
	svcAgentRestartFn = func() error { return nil }
	svcMCPActive = func() bool { return true } // 在跑
	// 进程 exe 与磁盘 inode 一致 → 无漂移
	mainPIDFn = func(unit string) int {
		if unit == "socketstack-mcp" {
			return 77
		}
		return 0
	}
	procExeFn = func(int) string { return "/opt/socket/versions/current/socket_server" }
	execStartPathFn = func(string) string { return "" }
	statInodeFn = func(string) uint64 { return 5 } // 两边同 inode
	var n int
	svcMCPRestartFn = func() error { n++; return nil }

	if err := installSelf(false); err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	if n != 0 {
		t.Fatalf("mcp 健康时不该被重启，实际 %d 次", n)
	}
}
