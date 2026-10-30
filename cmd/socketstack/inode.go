package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// 进程 inode 探测。systemd 单元跑的是被 rename 替换掉的旧文件时，
// /proc/<pid>/exe 的 readlink 结果末尾带 " (deleted)"，或 stat 出来的 inode
// 与磁盘上 ExecStart 指向的不一致——这就是「status 显示新版本号、实际跑旧代码」。
var (
	mainPIDFn = func(unit string) int {
		// --value 是 systemd 230+；老版本（CentOS 7 的 219）会失败，
		// 降级解析普通的 "MainPID=123" 行，别让整个检测静默失效。
		out, err := systemctlShowFn(unit, "MainPID", true)
		if err == nil {
			return parseMainPID(out) // 0 = 未运行，不必再查
		}
		out, err = systemctlShowFn(unit, "MainPID", false)
		if err != nil {
			return 0
		}
		return parseMainPID(out)
	}
	procExeFn = func(pid int) string {
		target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
		if err != nil {
			return "" // 非 root 时读别人的进程会 EACCES
		}
		return target
	}
	statInodeFn = func(path string) uint64 {
		if path == "" {
			return 0
		}
		fi, err := os.Stat(path)
		if err != nil {
			return 0
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			return st.Ino
		}
		return 0
	}
	// execStartPathFn 取单元真实的 ExecStart 可执行路径（parse 失败返回 ""）。
	// 老机器上残留的旧 ExecStart 指向别处时，硬编码 current 会误报漂移。
	execStartPathFn = func(unit string) string {
		// 与 mainPIDFn 同构：老 systemd 没有 --value，降级重试一次。
		if out, err := systemctlShowFn(unit, "ExecStart", true); err == nil {
			if p := parseExecStartPath(out); p != "" {
				return p
			}
		}
		out, err := systemctlShowFn(unit, "ExecStart", false)
		if err != nil {
			return ""
		}
		return parseExecStartPath(out)
	}
)

// systemctlShowFn 测试注入点：systemctl show -p <property> [--value] <unit>。
var systemctlShowFn = func(unit, prop string, valueOnly bool) (string, error) {
	args := []string{"show", "-p", prop}
	if valueOnly {
		args = append(args, "--value")
	}
	args = append(args, unit)
	out, err := exec.Command("systemctl", args...).Output()
	return string(out), err
}

// parseMainPID 解析 "123" 或 "MainPID=123"，取不到返回 0。
func parseMainPID(s string) int {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '='); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	pid, _ := strconv.Atoi(s)
	return pid
}

// parseExecStartPath 从 systemctl 的 ExecStart 结构体里取 path= 的值。
// 形如 `{ path=/x/socket_server ; argv[]=... }`；解析失败返回 ""。
func parseExecStartPath(s string) string {
	i := strings.Index(s, "path=")
	if i < 0 {
		return ""
	}
	rest := s[i+len("path="):]
	if j := strings.Index(rest, " ;"); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// exeDeleted readlink 结果是否指向已删除的文件。
func exeDeleted(target string) bool {
	return strings.HasSuffix(target, " (deleted)")
}

// binaryDrift 比对进程 inode 与磁盘 inode；无漂移返回空串。
// exeTarget 已删除时直接报——此时 inode 比对会因路径不存在而失效。
func binaryDrift(procInode, diskInode uint64, exeTarget, unit string) string {
	if exeDeleted(exeTarget) {
		return fmt.Sprintf("  进程跑的是已删除的旧二进制（%s）\n  修复: systemctl restart %s", exeTarget, unit)
	}
	if procInode == 0 || diskInode == 0 || procInode == diskInode {
		return ""
	}
	return fmt.Sprintf("  进程 inode %d ≠ 磁盘 inode %d，跑的可能是旧二进制\n  修复: systemctl restart %s", procInode, diskInode, unit)
}

// unitDrift 某单元是否在跑与磁盘不一致的二进制。
// drifted 才是判断依据；msg 只用于打印（可能是「需 root」这类诊断，
// 那不是漂移——把它当漂移会让 install 去做无意义的重启）。
// binaryPath 是回退基准：单元 ExecStart 解析不出来时才用它。
func unitDrift(unit, binaryPath string) (drifted bool, msg string) {
	pid := mainPIDFn(unit)
	if pid == 0 {
		return false, "" // 未运行不算漂移
	}
	exe := procExeFn(pid)
	if exe == "" {
		// 非 root 读不到别人的 /proc/<pid>/exe。静默跳过会让用户以为检测过了，
		// 但这不是「在跑旧二进制」，只是查不到。
		return false, fmt.Sprintf("  需 root 才能检测 %s 的二进制漂移", unit)
	}
	if p := execStartPathFn(unit); p != "" {
		binaryPath = p
	}
	m := binaryDrift(statInodeFn(exe), statInodeFn(binaryPath), exe, unit)
	return m != "", m
}
