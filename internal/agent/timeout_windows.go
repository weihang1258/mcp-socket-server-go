//go:build windows

package agent

import "os/exec"

// windows 无进程组语义（靶机侧恒为 Linux，此文件仅为跨平台编译）；
// 超时只杀直接子进程。
func setProcGroup(c *exec.Cmd) {}

func killProcGroup(pid int) bool {
	_ = pid
	return false
}

func procGroupAlive(pid int) bool {
	_ = pid
	return false
}
