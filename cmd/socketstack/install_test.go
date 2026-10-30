package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// install 只能落一份二进制：versions/<v>/socket_server 是真身，
// /usr/local/bin/socketstack 必须是指向 current/socket_server 的软链。
// 以前是两份独立拷贝（各 15MB），升级后两者会漂移——本机实测过
// 「/usr/local/bin 更新了、版本目录还是旧的」。
func TestInstallPlacesSingleBinaryAndSymlinksCLI(t *testing.T) {
	dir := t.TempDir()
	versions := filepath.Join(dir, "opt", "versions")
	binPath := filepath.Join(dir, "usr", "local", "bin", "socketstack")
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatal(err)
	}
	// 预置一份旧布局的真文件，验证会被换成软链
	if err := os.WriteFile(binPath, []byte("OLD-COPY"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "src-binary")
	if err := os.WriteFile(src, []byte("BIN"), 0o755); err != nil {
		t.Fatal(err)
	}

	prevVersions, prevBin, prevExe := svcVersionsDir, svcBinPath, exePathFn
	prevDirs, prevEnable, prevRestart := svcEnsureDirs, svcAgentEnable, svcAgentRestartFn
	defer func() {
		svcVersionsDir, svcBinPath, exePathFn = prevVersions, prevBin, prevExe
		svcEnsureDirs, svcAgentEnable, svcAgentRestartFn = prevDirs, prevEnable, prevRestart
	}()
	svcVersionsDir, svcBinPath = versions, binPath
	exePathFn = func() (string, error) { return src, nil }
	svcEnsureDirs = func() error { return os.MkdirAll(versions, 0o755) }
	var enabled atomic.Int32
	svcAgentEnable = func() error { enabled.Add(1); return nil }
	svcAgentRestartFn = func() error { return nil }

	if err := installSelf(false); err != nil {
		t.Fatalf("installSelf: %v", err)
	}

	versioned := filepath.Join(versions, currentVersion(), "socket_server")
	if data, err := os.ReadFile(versioned); err != nil || string(data) != "BIN" {
		t.Fatalf("版本目录应有二进制真身，实际 %q err=%v", data, err)
	}
	if fi, err := os.Lstat(binPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("/usr/local/bin 入口须是软链（不再存第二份二进制），实际 %v", fi.Mode())
	}
	target, err := os.Readlink(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Join(versions, "current", "socket_server") {
		t.Fatalf("入口应指向 current/socket_server，实际 %s", target)
	}
	if got, err := os.Readlink(filepath.Join(versions, "current")); err != nil || got != filepath.Join(versions, currentVersion()) {
		t.Fatalf("current 应指向 %s，实际 %s err=%v", currentVersion(), got, err)
	}
	if enabled.Load() != 1 {
		t.Fatalf("install 须启用 agent 单元 1 次，实际 %d", enabled.Load())
	}
}

// install 装完就该能直接用：`install` 之后 agent（以及 --with-mcp 时的 mcp）
// 都必须被重启，用户不用再敲第二条命令。
func TestInstallStartsServices(t *testing.T) {
	prev := []any{svcEnsureDirs, svcAgentEnable, svcAgentRestartFn, svcMCPInstall, svcMCPRestartFn, exePathFn, svcVersionsDir, svcBinPath}
	defer func() {
		svcEnsureDirs, svcAgentEnable = prev[0].(func() error), prev[1].(func() error)
		svcAgentRestartFn = prev[2].(func() error)
		svcMCPInstall, svcMCPRestartFn = prev[3].(func() error), prev[4].(func() error)
		exePathFn = prev[5].(func() (string, error))
		svcVersionsDir, svcBinPath = prev[6].(string), prev[7].(string)
	}()
	dir := t.TempDir()
	svcVersionsDir = filepath.Join(dir, "versions")
	svcBinPath = filepath.Join(dir, "bin", "socketstack")
	os.MkdirAll(filepath.Dir(svcBinPath), 0o755)
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("BIN"), 0o755)
	exePathFn = func() (string, error) { return src, nil }
	svcEnsureDirs = func() error { return os.MkdirAll(svcVersionsDir, 0o755) }
	svcAgentEnable = func() error { return nil }
	svcMCPInstall = func() error { return nil }
	var agentStarted, mcpStarted atomic.Int32
	svcAgentRestartFn = func() error { agentStarted.Add(1); return nil }
	svcMCPRestartFn = func() error { mcpStarted.Add(1); return nil }

	if err := installSelf(false); err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	if agentStarted.Load() != 1 || mcpStarted.Load() != 0 {
		t.Fatalf("不带 --with-mcp：agent 起步 1 次/mcp 0 次，实际 %d/%d", agentStarted.Load(), mcpStarted.Load())
	}

	agentStarted.Store(0)
	if err := installSelf(true); err != nil {
		t.Fatalf("installSelf --with-mcp: %v", err)
	}
	if agentStarted.Load() != 1 || mcpStarted.Load() != 1 {
		t.Fatalf("带 --with-mcp：agent/mcp 各起步 1 次，实际 %d/%d", agentStarted.Load(), mcpStarted.Load())
	}
}

// install 装完新二进制必须让它真正生效。只用 `start` 不够：单元本来就 active 时
// start 是空操作，进程继续跑被 rename 替换掉的旧 inode（真机实测 /proc/<pid>/exe
// 显示 "(deleted)"，日志停在装之前的时间）。必须 restart。
func TestInstallRestartsServices(t *testing.T) {
	dir := t.TempDir()

	prevExe, prevDirs := exePathFn, svcEnsureDirs
	prevVersions, prevBin := svcVersionsDir, svcBinPath
	prevEnable, prevRestart, prevStart := svcAgentEnable, svcAgentRestartFn, svcAgentStart
	prevMCPInst, prevMCPRestart, prevMCPStart := svcMCPInstall, svcMCPRestartFn, svcMCPStart
	defer func() {
		exePathFn, svcEnsureDirs = prevExe, prevDirs
		svcVersionsDir, svcBinPath = prevVersions, prevBin
		svcAgentEnable, svcAgentRestartFn, svcAgentStart = prevEnable, prevRestart, prevStart
		svcMCPInstall, svcMCPRestartFn, svcMCPStart = prevMCPInst, prevMCPRestart, prevMCPStart
	}()
	svcVersionsDir = filepath.Join(dir, "versions")
	svcBinPath = filepath.Join(dir, "bin", "socketstack")
	os.MkdirAll(filepath.Dir(svcBinPath), 0o755)
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("BIN"), 0o755)
	exePathFn = func() (string, error) { return src, nil }
	svcEnsureDirs = func() error { return nil }
	svcAgentEnable = func() error { return nil }
	svcMCPInstall = func() error { return nil }
	var restarted, started atomic.Int32
	svcAgentRestartFn = func() error { restarted.Add(1); return nil }
	svcAgentStart = func() error { started.Add(1); return nil }
	svcMCPRestartFn = func() error { return nil }
	svcMCPStart = func() error { return nil }

	if err := installSelf(false); err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	if restarted.Load() != 1 {
		t.Fatalf("agent 须 restart 1 次（start 对 active 单元是空操作），实际 restart=%d start=%d", restarted.Load(), started.Load())
	}
}

// status 一屏给出「程序在哪、日志在哪、跑没跑」——用户两次问的就是这些。
func TestStatusReportShowsPathsAndLogs(t *testing.T) {
	repo := statusReport()
	for _, want := range []string{
		"/opt/socket/versions/current/socket_server",
		"/usr/local/bin/socketstack",
		"/var/log/socket_server.log",
		"journalctl -u socketstack-mcp",
		"socket_server.service",
		"socketstack-mcp.service",
	} {
		if !strings.Contains(repo, want) {
			t.Fatalf("status 缺 %q:\n%s", want, repo)
		}
	}
}

// uninstall 必须清掉自己造的 PATH 入口软链，否则 /usr/local/bin/socketstack
// 悬空指向已删除的 current，用户敲 socketstack 得到「No such file or directory」。
func TestUninstallRemovesDanglingCLILink(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "socketstack")
	versions := filepath.Join(dir, "versions")
	os.MkdirAll(versions, 0o755)
	os.Symlink(filepath.Join(versions, "current", "socket_server"), binPath)

	prevBin, prevVersions := svcBinPath, svcVersionsDir
	prevMCPDis, prevAgentDis := svcMCPDisable, svcAgentDisable
	defer func() {
		svcBinPath, svcVersionsDir = prevBin, prevVersions
		svcMCPDisable, svcAgentDisable = prevMCPDis, prevAgentDis
	}()
	svcBinPath, svcVersionsDir = binPath, versions
	svcMCPDisable = func() error { return nil }
	svcAgentDisable = func() error { return nil }

	if err := uninstallSelf(); err != nil {
		t.Fatalf("uninstallSelf: %v", err)
	}
	if _, err := os.Lstat(binPath); !os.IsNotExist(err) {
		t.Fatalf("PATH 入口软链应被清掉，实际 err=%v", err)
	}
}

// 已在跑的机器上再 install 一次 = 覆盖升级：新二进制必须真的落到版本目录并成为
// current，否则「升级/覆盖修复」是假的（当前 current 已存在时 seedInitialVersion 早退，
// 会把新二进制悄悄丢掉）。同版本重装也要覆盖（修复损坏的二进制）。
func TestInstallOverwritesExistingVersion(t *testing.T) {
	dir := t.TempDir()
	versions := filepath.Join(dir, "versions")
	binPath := filepath.Join(dir, "bin", "socketstack")
	os.MkdirAll(filepath.Dir(binPath), 0o755)
	os.MkdirAll(versions, 0o755)

	// 旧部署：1.9.2 已在跑，current 指向它
	oldDir := filepath.Join(versions, "1.9.2")
	os.MkdirAll(oldDir, 0o755)
	os.WriteFile(filepath.Join(oldDir, "socket_server"), []byte("OLD"), 0o755)
	os.Symlink(oldDir, filepath.Join(versions, "current"))

	src := filepath.Join(dir, "new-binary")
	os.WriteFile(src, []byte("NEW"), 0o755)

	prevVersions, prevBin, prevExe := svcVersionsDir, svcBinPath, exePathFn
	prevDirs, prevEnable, prevRestart := svcEnsureDirs, svcAgentEnable, svcAgentRestartFn
	defer func() {
		svcVersionsDir, svcBinPath, exePathFn = prevVersions, prevBin, prevExe
		svcEnsureDirs, svcAgentEnable, svcAgentRestartFn = prevDirs, prevEnable, prevRestart
	}()
	svcVersionsDir, svcBinPath = versions, binPath
	exePathFn = func() (string, error) { return src, nil }
	svcEnsureDirs = func() error { return nil }
	svcAgentEnable = func() error { return nil }
	svcAgentRestartFn = func() error { return nil }

	if err := installSelf(false); err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(versions, "current", "socket_server"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "NEW" {
		t.Fatalf("覆盖安装须把新二进制装到 current，实际 %q", data)
	}
	if fi, err := os.Lstat(binPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("PATH 入口须是软链，实际 %v err=%v", fi.Mode(), err)
	}
}
