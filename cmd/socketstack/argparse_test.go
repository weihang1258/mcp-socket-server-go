package main

import "testing"

// uninstall 比 install 更不能忽略参数：卸载会 disable 两个单元、删 current 软链、
// 删 PATH 入口。`socketstack uninstall --help` 必须只打用法，绝不执行卸载。
func TestParseNoArgCommand(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{nil, "run"},
		{[]string{"-h"}, "help"},
		{[]string{"--help"}, "help"},
		{[]string{"help"}, "help"},
		{[]string{"--force"}, "unknown"},
		{[]string{"-y"}, "unknown"},
	}
	for _, c := range cases {
		if got := parseNoArgCommand(c.args); got != c.want {
			t.Errorf("parseNoArgCommand(%q) = %q，期望 %q", c.args, got, c.want)
		}
	}
}

// mcp 子命令：`--help` 不能掉进默认的 stdio 模式（那会阻塞住，看起来像卡死）。
func TestMCPHelpDoesNotFallThroughToStdio(t *testing.T) {
	for _, a := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		if act := mcpAction(a); act != "help" {
			t.Fatalf("mcp %q 应判为 help，实际 %q", a, act)
		}
	}
	if act := mcpAction(nil); act != "stdio" {
		t.Fatalf("mcp 无参数应为 stdio，实际 %q", act)
	}
	if act := mcpAction([]string{"serve"}); act != "serve" {
		t.Fatalf("mcp serve 应为 serve，实际 %q", act)
	}
}

// withStubs 替换 installSelf/uninstallSelf/exitFn，返回调用计数。
func withStubs(t *testing.T) (installs, uninstalls *int, exits *[]int) {
	t.Helper()
	pi, pu, pe := installSelfFn, uninstallSelfFn, exitFn
	i, u := 0, 0
	var e []int
	installSelfFn = func(bool) error { i++; return nil }
	uninstallSelfFn = func() error { u++; return nil }
	exitFn = func(code int) { e = append(e, code) }
	t.Cleanup(func() { installSelfFn, uninstallSelfFn, exitFn = pi, pu, pe })
	return &i, &u, &e
}

// `install --help` 绝不能触发安装（真机曾因此重启服务两次）。
func TestRunInstallHelpDoesNotInstall(t *testing.T) {
	installs, _, exits := withStubs(t)
	runInstall([]string{"--help"})
	if *installs != 0 {
		t.Fatalf("install --help 不得执行安装，实际 %d 次", *installs)
	}
	if len(*exits) != 0 {
		t.Fatalf("help 应正常退出（0），不该走 exitFn，实际 %v", *exits)
	}
}

// `install --bogus` 必须拦下，退出码 2，且不安装。
func TestRunInstallUnknownArgRejected(t *testing.T) {
	installs, _, exits := withStubs(t)
	runInstall([]string{"--bogus"})
	if *installs != 0 {
		t.Fatalf("未知参数不得执行安装，实际 %d 次", *installs)
	}
	if len(*exits) != 1 || (*exits)[0] != 2 {
		t.Fatalf("未知参数应以 2 退出，实际 %v", *exits)
	}
}

// `uninstall --help` 绝不能卸载——误执行会 disable 单元并删 current 软链。
func TestRunUninstallHelpDoesNotUninstall(t *testing.T) {
	_, uninstalls, exits := withStubs(t)
	runUninstall([]string{"--help"})
	if *uninstalls != 0 {
		t.Fatalf("uninstall --help 不得执行卸载，实际 %d 次", *uninstalls)
	}
	if len(*exits) != 0 {
		t.Fatalf("help 应正常退出，实际 %v", *exits)
	}
}

// `uninstall --force` 必须拦下。
func TestRunUninstallUnknownArgRejected(t *testing.T) {
	_, uninstalls, exits := withStubs(t)
	runUninstall([]string{"--force"})
	if *uninstalls != 0 {
		t.Fatalf("未知参数不得执行卸载，实际 %d 次", *uninstalls)
	}
	if len(*exits) != 1 || (*exits)[0] != 2 {
		t.Fatalf("未知参数应以 2 退出，实际 %v", *exits)
	}
}

// 无参数时正常执行（确认 stub 路径本身可达，否则上面的「不执行」断言无意义）。
func TestRunInstallNoArgsInstalls(t *testing.T) {
	installs, _, _ := withStubs(t)
	runInstall(nil)
	if *installs != 1 {
		t.Fatalf("无参数应执行 1 次安装，实际 %d", *installs)
	}
}
