//go:build !windows

package agent

import "syscall"

// currentUmask 读取进程 umask（syscall.Umask 只能读改写回，短暂置 0 有竞态但测试串行足够）。
func currentUmask() int {
	old := syscall.Umask(0)
	syscall.Umask(old)
	return old
}
