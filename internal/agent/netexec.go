package agent

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// execCmd 复刻 netutils.exec_cmd_subprocess 的 shell 分支（dt1/内部命令均走此路径）：
// - shell+字符串命令且 root 时剥裸 "sudo " 前缀（带选项/空命令不剥）
// - 清理 LD_LIBRARY_PATH（通用污染防护，保留；_PYI_*/_MEIPASS 为 PyInstaller 专有，Go 无）
// - 返回 {code, stdout, stderr}；执行本身异常 → code=-1
func execCmd(cmd string) (code int, stdout, stderr string) {
	if os.Geteuid() == 0 {
		cmd = stripSudoPrefix(cmd)
	}
	return execCmdWith(cmd, "", cleanEnv(os.Environ()), true)
}

// shellCmd /bin/sh -c 包装。
func shellCmd(cmd string, env []string) *exec.Cmd {
	c := exec.Command("/bin/sh", "-c", cmd)
	c.Env = env
	return c
}

// argvCmd argv 模式（env 清理同 shell 模式）。
func argvCmd(argv []string) *exec.Cmd {
	c := exec.Command(argv[0], argv[1:]...)
	c.Env = cleanEnv(os.Environ())
	return c
}

// stripSudoPrefix root 时剥裸 "sudo "（带 sudo 自身选项或空命令不剥，对齐 netutils）。
func stripSudoPrefix(s string) string {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "sudo ") && !strings.HasPrefix(t, "sudo\t") {
		return s
	}
	after := strings.TrimLeft(t[5:], " \t")
	if after == "" || strings.HasPrefix(after, "-") {
		return s
	}
	return after
}

// cleanEnv 移除 LD_LIBRARY_PATH（对齐 netutils._clean_subprocess_env 的通用部分）。
func cleanEnv(environ []string) []string {
	out := environ[:0]
	for _, kv := range environ {
		if strings.HasPrefix(kv, "LD_LIBRARY_PATH=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// execCmdArgs argv 模式执行（不经 shell）——对齐 Python shell=False 的注入防护
// （dt10 的 eth 来自客户端 payload，绝不能进 shell）。
func execCmdArgs(argv ...string) (code int, stdout, stderr string) {
	var stdoutBuf, stderrBuf bytes.Buffer
	c := argvCmd(argv)
	c.Stdout = &stdoutBuf
	c.Stderr = &stderrBuf
	err := c.Run()
	code = 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = processExitCode(ee) // 信号死亡 → -signum
		} else {
			return -1, "", err.Error()
		}
	}
	return code, stdoutBuf.String(), stderrBuf.String()
}

// routeinfo 复刻 netutils.routeinfo：原生读 /proc/net/route（route -n 的数据源），
// 输出同构（Destination 键控行字段 map）；读不到 → error（断连）。
func routeinfo() (map[string]map[string]any, error) {
	return nativeRouteInfo()
}

// ensureCommand 复刻 netutils.ensure_command：PATH 查找（不带 install_cmd 分支——dt18 不传）。
func ensureCommand(cmd, installCmd string) bool {
	if _, err := exec.LookPath(cmd); err == nil {
		return true
	}
	if installCmd != "" { // Python：裸 subprocess.run(install_cmd, shell=True)——全量继承环境（netutils.py:201，不经清理）
		execCmdWith(installCmd, "", os.Environ(), true)
		_, err := exec.LookPath(cmd)
		return err == nil
	}
	return false
}

// setMTU dt10 实现：ioctl 读当前 MTU，相等不动；不等则 ioctl 设置。
// 设置失败仅记日志（Python exec 吞错误 → sleep(5) → res null 同语义，网卡
// 状态以实际为准）；查询失败 = 原 ifconfig 缺失路径 → error → 断连。
func setMTU(eth string, value int) (set bool, err error) {
	cur, err := getMTUFn(eth)
	if err != nil {
		return false, fmt.Errorf("查询网卡 %s MTU 失败: %w", eth, err)
	}
	if cur == value {
		return false, nil
	}
	if serr := setMTUFn(eth, value); serr != nil {
		log.Printf("设置网卡 %s MTU=%d 失败(忽略): %v", eth, value, serr)
	}
	return true, nil
}
