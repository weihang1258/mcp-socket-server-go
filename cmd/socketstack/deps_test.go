package main

import (
	"errors"
	"testing"
)

// deps 子命令严格解析（与 install/uninstall 同约定）：
//   deps install-browser  → 执行安装；成功静默，失败 exit 1
//   -h/--help/help        → 用法，exit 0
//   其它                  → 用法，exit 2
// 全程不触碰 install/uninstall 路径。
func TestRunDeps(t *testing.T) {
	prevFn, prevExit := installBrowserDepsFn, exitFn
	t.Cleanup(func() { installBrowserDepsFn, exitFn = prevFn, prevExit })

	var called int
	var lastErr error
	installBrowserDepsFn = func() error { called++; return lastErr }

	// exits 记录 exitFn 调用（注入实现不真退出，被测函数必须 return）。
	var exits []int
	exitFn = func(code int) { exits = append(exits, code) }

	t.Run("成功不退出", func(t *testing.T) {
		called, lastErr, exits = 0, nil, nil
		runDeps([]string{"install-browser"})
		if called != 1 || len(exits) != 0 {
			t.Fatalf("called=%d exits=%v", called, exits)
		}
	})
	t.Run("失败退出1", func(t *testing.T) {
		called, lastErr, exits = 0, errors.New("装包失败"), nil
		runDeps([]string{"install-browser"})
		if called != 1 || len(exits) != 1 || exits[0] != 1 {
			t.Fatalf("called=%d exits=%v", called, exits)
		}
	})
	t.Run("help退出0不执行", func(t *testing.T) {
		for _, a := range [][]string{{"-h"}, {"--help"}, {"help"}} {
			called, lastErr, exits = 0, nil, nil
			runDeps(a)
			if len(exits) != 0 || called != 0 {
				t.Fatalf("%v: exits=%v called=%d", a, exits, called)
			}
		}
	})
	t.Run("未知参数退出2不执行", func(t *testing.T) {
		for _, a := range [][]string{{"install"}, {}, {"install-browser", "extra"}, {"status"}} {
			called, lastErr, exits = 0, nil, nil
			runDeps(a)
			if len(exits) != 1 || exits[0] != 2 || called != 0 {
				t.Fatalf("%v: exits=%v called=%d", a, exits, called)
			}
		}
	})
}
