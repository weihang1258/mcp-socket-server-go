package main

import (
	"errors"
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
	stubNoDrift(t)
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
	prevDeps := installDeps
	defer func() {
		svcVersionsDir, svcBinPath, exePathFn = prevVersions, prevBin, prevExe
		svcEnsureDirs, svcAgentEnable, svcAgentRestartFn = prevDirs, prevEnable, prevRestart
		installDeps = prevDeps
	}()
	installDeps = func() []string { return nil }
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
	stubNoDrift(t)
	prev := []any{svcEnsureDirs, svcAgentEnable, svcAgentRestartFn, svcMCPInstall, svcMCPRestartFn, exePathFn, svcVersionsDir, svcBinPath, installDeps}
	defer func() {
		installDeps = prev[8].(func() []string)
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
	installDeps = func() []string { return nil }
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
	stubNoDrift(t)
	dir := t.TempDir()

	prevExe, prevDirs := exePathFn, svcEnsureDirs
	prevVersions, prevBin := svcVersionsDir, svcBinPath
	prevEnable, prevRestart, prevStart := svcAgentEnable, svcAgentRestartFn, svcAgentStart
	prevMCPInst, prevMCPRestart, prevMCPStart := svcMCPInstall, svcMCPRestartFn, svcMCPStart
	prevDeps := installDeps
	defer func() {
		exePathFn, svcEnsureDirs = prevExe, prevDirs
		svcVersionsDir, svcBinPath = prevVersions, prevBin
		svcAgentEnable, svcAgentRestartFn, svcAgentStart = prevEnable, prevRestart, prevStart
		svcMCPInstall, svcMCPRestartFn, svcMCPStart = prevMCPInst, prevMCPRestart, prevMCPStart
		installDeps = prevDeps
	}()
	installDeps = func() []string { return nil }
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
	prevLogrotate := svcLogrotatePath
	defer func() {
		svcBinPath, svcVersionsDir = prevBin, prevVersions
		svcMCPDisable, svcAgentDisable = prevMCPDis, prevAgentDis
		svcLogrotatePath = prevLogrotate
	}()
	svcBinPath, svcVersionsDir = binPath, versions
	svcMCPDisable = func() error { return nil }
	svcAgentDisable = func() error { return nil }
	// logrotate 是 install 落的副作用文件，uninstall 要收走；绝不能碰真的
	// /etc/logrotate.d/socketstack。
	logrotatePath := filepath.Join(dir, "socketstack")
	os.WriteFile(logrotatePath, []byte("x"), 0o644)
	svcLogrotatePath = logrotatePath

	if err := uninstallSelf(); err != nil {
		t.Fatalf("uninstallSelf: %v", err)
	}
	if _, err := os.Lstat(binPath); !os.IsNotExist(err) {
		t.Fatalf("PATH 入口软链应被清掉，实际 err=%v", err)
	}
	if _, err := os.Lstat(logrotatePath); !os.IsNotExist(err) {
		t.Fatalf("logrotate 配置应被清掉，实际 err=%v", err)
	}
}

// 已在跑的机器上再 install 一次 = 覆盖升级：新二进制必须真的落到版本目录并成为
// current，否则「升级/覆盖修复」是假的（当前 current 已存在时 seedInitialVersion 早退，
// 会把新二进制悄悄丢掉）。同版本重装也要覆盖（修复损坏的二进制）。
func TestInstallOverwritesExistingVersion(t *testing.T) {
	stubNoDrift(t)
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
	prevDeps := installDeps
	defer func() {
		svcVersionsDir, svcBinPath, exePathFn = prevVersions, prevBin, prevExe
		svcEnsureDirs, svcAgentEnable, svcAgentRestartFn = prevDirs, prevEnable, prevRestart
		installDeps = prevDeps
	}()
	installDeps = func() []string { return nil }
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

// install 必须做系统依赖的 best-effort 安装（Python install.sh 有这一段，
// Go 版最初漏移植：ethtool 缺失要等第一次抓包才知道，chromium 库缺失要等
// 第一次 boce 拨测才炸）。
func TestInstallRunsDependencyInstall(t *testing.T) {
	stubNoDrift(t)
	dir := t.TempDir()
	prevExe, prevDirs := exePathFn, svcEnsureDirs
	prevVersions, prevBin := svcVersionsDir, svcBinPath
	prevEnable, prevRestart, prevDeps := svcAgentEnable, svcAgentRestartFn, installDeps
	defer func() {
		exePathFn, svcEnsureDirs = prevExe, prevDirs
		svcVersionsDir, svcBinPath = prevVersions, prevBin
		svcAgentEnable, svcAgentRestartFn, installDeps = prevEnable, prevRestart, prevDeps
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
	var called atomic.Int32
	installDeps = func() []string { called.Add(1); return nil }

	if err := installSelf(false); err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	if called.Load() != 1 {
		t.Fatalf("install 须执行依赖安装 1 次，实际 %d", called.Load())
	}
}

// 依赖安装失败只告警，不能中断安装（best-effort 语义，对齐 Python install.sh）。
func TestInstallDepsFailureDoesNotAbort(t *testing.T) {
	stubNoDrift(t)
	dir := t.TempDir()
	prevExe, prevDirs := exePathFn, svcEnsureDirs
	prevVersions, prevBin := svcVersionsDir, svcBinPath
	prevEnable, prevRestart, prevDeps := svcAgentEnable, svcAgentRestartFn, installDeps
	defer func() {
		exePathFn, svcEnsureDirs = prevExe, prevDirs
		svcVersionsDir, svcBinPath = prevVersions, prevBin
		svcAgentEnable, svcAgentRestartFn, installDeps = prevEnable, prevRestart, prevDeps
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
	installDeps = func() []string { return []string{"装包失败"} }

	if err := installSelf(false); err != nil {
		t.Fatalf("依赖失败不应中断安装: %v", err)
	}
	if _, err := os.Stat(filepath.Join(svcVersionsDir, "current")); err != nil {
		t.Fatalf("依赖失败后 current 仍须建好: %v", err)
	}
}

// status 必须给出拨测依赖诊断：chromium 已下载但缺库时要列出缺哪些 .so、
// 并给出可直接复制的装包命令。未装 chromium 时不该报（首次 boce 才下载）。
func TestStatusReportsMissingChromiumLibs(t *testing.T) {
	dir := t.TempDir()
	chrome := filepath.Join(dir, "chrome")
	os.WriteFile(chrome, []byte("#!/bin/sh\n"), 0o755)
	// 伪造 ldd：让诊断函数走真实实现，但 chromium 路径与 ldd 都可控
	t.Setenv("SOCKETSTACK_TEST_CHROMIUM", chrome)

	prevLdd := lddFn
	lddFn = func(string) ([]byte, error) {
		return []byte("\tlibX11-xcb.so.1 => not found\n\tlibnss3.so => not found\n"), nil
	}
	defer func() { lddFn = prevLdd }()

	diag := chromiumDepsDiag()
	if !strings.Contains(diag, "libX11-xcb.so.1") || !strings.Contains(diag, "libnss3.so") {
		t.Fatalf("诊断须列出缺失库: %q", diag)
	}
	if !strings.Contains(diag, "install -y") {
		t.Fatalf("诊断须给出装包命令: %q", diag)
	}
}

// 未下载 chromium → 不报缺库（首次 boce 才会下载，此时报是噪音）。
func TestStatusSilentWhenChromiumAbsent(t *testing.T) {
	t.Setenv("SOCKETSTACK_TEST_CHROMIUM", filepath.Join(t.TempDir(), "nope"))
	prevLdd := lddFn
	lddFn = func(string) ([]byte, error) { t.Fatal("未装 chromium 不该跑 ldd"); return nil, nil }
	defer func() { lddFn = prevLdd }()
	if got := chromiumDepsDiag(); got != "" {
		t.Fatalf("未装 chromium 应返回空，实际 %q", got)
	}
}

// status 输出必须真的带上拨测依赖诊断。上一条用例只测 chromiumDepsDiag 本身，
// 把 statusReport 里的调用删掉它照样绿——那正是要防的回归。
func TestStatusReportIncludesChromiumDiag(t *testing.T) {
	dir := t.TempDir()
	chrome := filepath.Join(dir, "chrome")
	os.WriteFile(chrome, []byte("#!/bin/sh\n"), 0o755)
	t.Setenv("SOCKETSTACK_TEST_CHROMIUM", chrome)

	prevLdd := lddFn
	lddFn = func(string) ([]byte, error) {
		return []byte("\tlibX11-xcb.so.1 => not found\n"), nil
	}
	defer func() { lddFn = prevLdd }()

	repo := statusReport()
	if !strings.Contains(repo, "libX11-xcb.so.1") {
		t.Fatalf("status 输出须包含缺库诊断:\n%s", repo)
	}
	if !strings.Contains(repo, "拨测依赖") {
		t.Fatalf("status 输出须有拨测依赖小节:\n%s", repo)
	}
}

// stubNoDrift 隔离 inode 漂移检测：这些用例只关心 install 的其它行为，
// 不 stub 会打到真实 systemctl（本机真装了服务时行为不可控）。
func stubNoDrift(t *testing.T) {
	t.Helper()
	prevPID, prevExe, prevInode, prevExec := mainPIDFn, procExeFn, statInodeFn, execStartPathFn
	prevActive := svcMCPActive
	prevLogrotate := installLogrotate
	t.Cleanup(func() {
		mainPIDFn, procExeFn, statInodeFn, execStartPathFn = prevPID, prevExe, prevInode, prevExec
		svcMCPActive, installLogrotate = prevActive, prevLogrotate
	})
	installLogrotate = func() error { return nil } // 别碰真实 /etc/logrotate.d
	svcMCPActive = func() bool { return false }
	mainPIDFn = func(string) int { return 0 }
	procExeFn = func(int) string { return "" }
	statInodeFn = func(string) uint64 { return 0 }
	execStartPathFn = func(string) string { return "" }
}

// install 必须部署日志轮转：agent 长期持有日志 fd，不轮转会无限增长（真机 364MB）。
func TestInstallWritesLogrotate(t *testing.T) {
	dir := t.TempDir()
	stubNoDrift(t)
	prevExe, prevDirs := exePathFn, svcEnsureDirs
	prevVersions, prevBin := svcVersionsDir, svcBinPath
	prevEnable, prevRestart, prevDeps := svcAgentEnable, svcAgentRestartFn, installDeps
	prevLog := installLogrotate
	defer func() {
		exePathFn, svcEnsureDirs = prevExe, prevDirs
		svcVersionsDir, svcBinPath = prevVersions, prevBin
		svcAgentEnable, svcAgentRestartFn, installDeps = prevEnable, prevRestart, prevDeps
		installLogrotate = prevLog
	}()
	installDeps = func() []string { return nil }
	svcVersionsDir = filepath.Join(dir, "versions")
	svcBinPath = filepath.Join(dir, "bin", "socketstack")
	os.MkdirAll(filepath.Dir(svcBinPath), 0o755)
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("BIN"), 0o755)
	exePathFn = func() (string, error) { return src, nil }
	svcEnsureDirs = func() error { return nil }
	svcAgentEnable = func() error { return nil }
	svcAgentRestartFn = func() error { return nil }
	var n int
	installLogrotate = func() error { n++; return nil }

	if err := installSelf(false); err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	if n != 1 {
		t.Fatalf("install 须部署日志轮转 1 次，实际 %d", n)
	}
}

// 轮转配置失败只告警，不能中断安装。
func TestInstallLogrotateFailureDoesNotAbort(t *testing.T) {
	dir := t.TempDir()
	stubNoDrift(t)
	prevExe, prevDirs := exePathFn, svcEnsureDirs
	prevVersions, prevBin := svcVersionsDir, svcBinPath
	prevEnable, prevRestart, prevDeps := svcAgentEnable, svcAgentRestartFn, installDeps
	prevLog := installLogrotate
	defer func() {
		exePathFn, svcEnsureDirs = prevExe, prevDirs
		svcVersionsDir, svcBinPath = prevVersions, prevBin
		svcAgentEnable, svcAgentRestartFn, installDeps = prevEnable, prevRestart, prevDeps
		installLogrotate = prevLog
	}()
	installDeps = func() []string { return nil }
	svcVersionsDir = filepath.Join(dir, "versions")
	svcBinPath = filepath.Join(dir, "bin", "socketstack")
	os.MkdirAll(filepath.Dir(svcBinPath), 0o755)
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("BIN"), 0o755)
	exePathFn = func() (string, error) { return src, nil }
	svcEnsureDirs = func() error { return nil }
	svcAgentEnable = func() error { return nil }
	svcAgentRestartFn = func() error { return nil }
	installLogrotate = func() error { return errors.New("no perm") }

	if err := installSelf(false); err != nil {
		t.Fatalf("轮转失败不应中断安装: %v", err)
	}
}
