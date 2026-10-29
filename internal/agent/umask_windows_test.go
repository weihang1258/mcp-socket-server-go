//go:build windows

package agent

// currentUmask windows 无 umask 概念（Go 权限位被忽略），返回 0 使期望值为 0666。
func currentUmask() int { return 0 }
