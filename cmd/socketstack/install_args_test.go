package main

import "testing"

// install 只认 --with-mcp。以前是「遍历参数挑出 --with-mcp，其余静默丢弃」，
// 于是 `socketstack install --help` 会真的执行安装并重启服务——真机 15:02、
// 20:14 各重启一次，正是客户端反馈「连接被断」的直接来源。
func TestParseInstallArgs(t *testing.T) {
	cases := []struct {
		args    []string
		withMCP bool
		act     string
	}{
		{nil, false, ""},
		{[]string{"--with-mcp"}, true, ""},
		{[]string{"-h"}, false, "help"},
		{[]string{"--help"}, false, "help"},
		{[]string{"help"}, false, "help"},
		{[]string{"--with-mcp", "--help"}, true, "help"}, // help 优先，不安装
		{[]string{"-y"}, false, "unknown"},               // 未知参数必须拦下
		{[]string{"--with-mcp", "--force"}, true, "unknown"},
	}
	for _, c := range cases {
		gotMCP, gotAct := parseInstallArgs(c.args)
		if gotMCP != c.withMCP || gotAct != c.act {
			t.Errorf("parseInstallArgs(%q) = (%v,%q)，期望 (%v,%q)",
				c.args, gotMCP, gotAct, c.withMCP, c.act)
		}
	}
}
