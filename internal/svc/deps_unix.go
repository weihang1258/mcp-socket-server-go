//go:build !windows

package svc

import (
	"os/exec"
	"syscall"
)

// setProcGroup 让子进程自成进程组，超时能整组杀（否则只杀 sh，孙进程留活口）。
func setProcGroup(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
}
