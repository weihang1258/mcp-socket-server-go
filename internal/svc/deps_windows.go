//go:build windows

package svc

import "os/exec"

// setProcGroup Windows 下由 CommandContext 自带的 Job 语义接管，无需额外设置。
func setProcGroup(c *exec.Cmd) {}
