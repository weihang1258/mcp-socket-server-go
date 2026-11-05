//go:build !windows

package agent

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// setProcGroup 让子进程带自己的进程组（方案 §6.2 第 2 条）：超时按 -pgid
// 整组杀，避免只杀 sh 把真正干活的孙进程留在设备上。
func setProcGroup(c *exec.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.Setpgid = true
}

// killProcGroup 先 SIGTERM 整组，2 秒后 SIGKILL 整组。
func killProcGroup(pgid int) {
	if pgid <= 0 {
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	timeSleep(2 * second())
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}

// procGroupAlive 进程组是否还有活口。用 /proc 逐进程看 pgrp，不看 kill(0)：
// 僵尸在 kill(0) 下仍算"存在"，但已经不再执行任何东西。Z 态按已死算。
// 孤儿被回收有微小延迟，故最多轮询 1 秒再下结论。
func procGroupAlive(pgid int) bool {
	if pgid <= 0 {
		return false
	}
	for i := 0; i < 10; i++ {
		if !scanPgrp(pgid) {
			return false
		}
		timeSleep(100 * timeMillisecond())
	}
	return scanPgrp(pgid)
}

// scanPgrp 扫 /proc 找 pgrp==pgid 且状态非 Z 的进程。
func scanPgrp(pgid int) bool {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return false // 读不到 /proc 就无法证明有活口：交给调用方的 verified 语义兜底
	}
	want := strconv.Itoa(pgid)
	for _, e := range ents {
		if !e.IsDir() || e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// 格式：pid (comm) S ppid pgrp ...；comm 可能含空格与括号，按最后一个 ')' 切。
		s := string(b)
		r := strings.LastIndex(s, ")")
		if r < 0 || r+2 >= len(s) {
			continue
		}
		f := strings.Fields(s[r+1:])
		if len(f) < 3 {
			continue
		}
		if f[0] == "Z" || f[0] == "X" {
			continue
		}
		if f[2] == want {
			return true
		}
	}
	return false
}
