package main

import (
	"fmt"
	"strings"
	"testing"
)

// MCP 单元跑在被 rename 替换掉的旧二进制上时为 true。
//
// 真实故障：/usr/local/bin/socketstack 改成指向 current 的软链后，agent 与 mcp
// 共享同一个文件；install 用 rename 覆写时两者的旧 inode 一起变 "(deleted)"。
// agent 有 restart 所以没事，mcp 在不带 --with-mcp 的 install 里不动——于是
// status 显示 active + 新版本号，进程跑的却是旧代码。
func TestExeDeleted(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"/opt/socket/versions/1.9.4/socket_server", false},
		{"/opt/socket/versions/1.9.4/socket_server (deleted)", true},
		{"/usr/local/bin/socketstack (deleted)", true},
		{"", false}, // 读不到就不猜
	}
	for _, c := range cases {
		if got := exeDeleted(c.target); got != c.want {
			t.Errorf("exeDeleted(%q) = %v，期望 %v", c.target, got, c.want)
		}
	}
}

// 进程 inode 与磁盘上 current 指向的二进制不一致时报告漂移。
func TestBinaryDrift(t *testing.T) {
	if msg := binaryDrift(100, 100, "", "socketstack-mcp"); msg != "" {
		t.Fatalf("inode 一致不该报漂移，实际 %q", msg)
	}
	if msg := binaryDrift(0, 100, "", "socketstack-mcp"); msg != "" {
		t.Fatalf("inode 未知（0）不该猜，实际 %q", msg)
	}
	msg := binaryDrift(100, 200, "", "socketstack-mcp")
	if !strings.Contains(msg, "100") || !strings.Contains(msg, "200") {
		t.Fatalf("漂移说明须带上两个 inode，实际 %q", msg)
	}
	// exe 已被删除时，报错里要包含修复命令
	msg = binaryDrift(200, 200, "/x/socket_server (deleted)", "socketstack-mcp")
	if !strings.Contains(msg, "systemctl restart socketstack-mcp") {
		t.Fatalf("(deleted) 时须给出 restart 修复命令，实际 %q", msg)
	}
}

// status 必须把「mcp 在跑旧二进制」显示出来，否则用户完全看不出来。
// agent 不运行，确保命中的只能是 mcp 那一行。
func TestStatusReportWarnsOnMCPDrift(t *testing.T) {
	prevPID, prevExe, prevInode, prevExec := mainPIDFn, procExeFn, statInodeFn, execStartPathFn
	defer func() {
		mainPIDFn, procExeFn, statInodeFn, execStartPathFn = prevPID, prevExe, prevInode, prevExec
	}()

	mainPIDFn = func(unit string) int {
		if unit == "socketstack-mcp" {
			return 4242
		}
		return 0 // agent 未运行
	}
	procExeFn = func(pid int) string { return "/opt/socket/versions/current/socket_server (deleted)" }
	statInodeFn = func(string) uint64 { return 999 }
	execStartPathFn = func(string) string { return "" } // 回退到 current 路径

	repo := statusReport()
	if !strings.Contains(repo, "socketstack-mcp") || !strings.Contains(repo, "已删除") {
		t.Fatalf("status 须对 mcp 已删除的 inode 告警:\n%s", repo)
	}
}

// 进程与磁盘一致时不产生噪音。
func TestStatusReportSilentOnNoDrift(t *testing.T) {
	prevPID, prevExe, prevInode, prevExec := mainPIDFn, procExeFn, statInodeFn, execStartPathFn
	defer func() {
		mainPIDFn, procExeFn, statInodeFn, execStartPathFn = prevPID, prevExe, prevInode, prevExec
	}()

	mainPIDFn = func(unit string) int { return 0 } // 单元未运行
	execStartPathFn = func(string) string { return "" }
	repo := statusReport()
	if strings.Contains(repo, "已删除的旧二进制") {
		t.Fatalf("单元未运行不该报漂移:\n%s", repo)
	}
}

// 非 root 时读不到别的进程的 /proc/<pid>/exe，不能静默当作「一切正常」——
// 那会让用户以为检测过了。
func TestUnitDriftWarnsWhenUnreadable(t *testing.T) {
	prevPID, prevExe := mainPIDFn, procExeFn
	defer func() { mainPIDFn, procExeFn = prevPID, prevExe }()
	mainPIDFn = func(string) int { return 4242 }
	procExeFn = func(int) string { return "" } // 无权限

	msg := unitDrift("socketstack-mcp", "/x/socket_server")
	if !strings.Contains(msg, "root") {
		t.Fatalf("无权限时须提示需 root，实际 %q", msg)
	}
}

// 比对基准优先用单元真实的 ExecStart：老机器上残留的旧 ExecStart 指向别的
// 路径时，硬编码 current 会误报漂移，而且 restart 修不好。
func TestUnitDriftUsesExecStartPath(t *testing.T) {
	prevPID, prevExe, prevInode, prevExec := mainPIDFn, procExeFn, statInodeFn, execStartPathFn
	defer func() {
		mainPIDFn, procExeFn, statInodeFn, execStartPathFn = prevPID, prevExe, prevInode, prevExec
	}()
	mainPIDFn = func(string) int { return 4242 }
	procExeFn = func(int) string { return "/opt/socket/socket_server" }
	prevExec = func(string) string { return "/opt/socket/socket_server" }
	execStartPathFn = prevExec
	// 按路径返回不同 inode：进程与 ExecStart 一致 → 不报
	statInodeFn = func(p string) uint64 {
		if p == "/opt/socket/socket_server" {
			return 7
		}
		return 99 // current 下是另一个文件
	}

	if msg := unitDrift("socket_server", "/opt/socket/versions/current/socket_server"); msg != "" {
		t.Fatalf("进程与单元 ExecStart 一致时不该报漂移，实际 %q", msg)
	}
}

// 解析 systemctl show -p ExecStart 的输出取可执行文件路径。
func TestParseExecStartPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`{ path=/opt/socket/versions/current/socket_server ; argv[]=/opt/socket/versions/current/socket_server serve ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`,
			"/opt/socket/versions/current/socket_server"},
		{"", ""},
		{"garbage", ""},
	}
	for _, c := range cases {
		if got := parseExecStartPath(c.in); got != c.want {
			t.Errorf("parseExecStartPath(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// mainPID 查询失败时要降级解析普通输出（老 systemd 没有 --value）。
func TestParseMainPIDFallback(t *testing.T) {
	if got := parseMainPID("0"); got != 0 {
		t.Errorf("parseMainPID(0) = %d，期望 0", got)
	}
	if got := parseMainPID("1234"); got != 1234 {
		t.Errorf("parseMainPID(1234) = %d，期望 1234", got)
	}
	if got := parseMainPID("MainPID=5678\n"); got != 5678 {
		t.Errorf("降级解析 MainPID= 形式失败，实际 %d", got)
	}
	if got := parseMainPID(""); got != 0 {
		t.Errorf("空输入应为 0，实际 %d", got)
	}
}

// --value 在 systemd <230 上会失败；此时必须降级到不带 --value 的形式，
// 否则整个漂移检测静默失效。
func TestMainPIDFallsBackWithoutValueFlag(t *testing.T) {
	prev := systemctlShowFn
	defer func() { systemctlShowFn = prev }()

	// 模拟老 systemd：带 --value 报错，不带时给 "MainPID=4321"
	systemctlShowFn = func(unit, prop string, valueOnly bool) (string, error) {
		if valueOnly {
			return "", fmt.Errorf("unknown option --value")
		}
		return "MainPID=4321\n", nil
	}
	if got := mainPIDFn("socketstack-mcp"); got != 4321 {
		t.Fatalf("--value 不支持时须降级解析，实际 PID=%d", got)
	}
}

// 两种形式都失败 → 0（未运行），不 panic。
func TestMainPIDZeroWhenBothFail(t *testing.T) {
	prev := systemctlShowFn
	defer func() { systemctlShowFn = prev }()
	systemctlShowFn = func(string, string, bool) (string, error) { return "", fmt.Errorf("boom") }
	if got := mainPIDFn("nope"); got != 0 {
		t.Fatalf("查询失败应返回 0，实际 %d", got)
	}
}
