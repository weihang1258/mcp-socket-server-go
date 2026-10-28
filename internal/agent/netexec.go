package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
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

// routeinfo 复刻 netutils.routeinfo：`route -n` 解析，非零退出/缺失 → error（断连）。
// 返回按 Destination 键控的行字段 map（Python defaultdict(zip(head, fields))）。
func routeinfo() (map[string]map[string]any, error) {
	code, stdout, stderr := execCmd("route -n")
	if code != 0 {
		return nil, fmt.Errorf("执行：route -n，返回：code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	res := map[string]map[string]any{}
	if len(lines) > 2 {
		head := strings.Fields(strings.TrimSpace(lines[1]))
		for _, line := range lines[2:] {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) == 0 {
				continue
			}
			row := map[string]any{}
			for i, h := range head {
				if h == "Destination" || i >= len(fields) {
					continue
				}
				row[h] = fields[i]
			}
			// key = Destination 字段值（首列）
			dest := fields[0]
			if len(head) > 0 && head[0] == "Destination" {
				res[dest] = row
			}
		}
	}
	return res, nil
}

// ensureCommand 复刻 netutils.ensure_command：PATH 查找（不带 install_cmd 分支——dt18 不传）。
func ensureCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

var (
	mtuNewRe = regexp.MustCompile(`(?i)\bmtu\s+(\d+)`) // 新式 "mtu 1500"
	mtuOldRe = regexp.MustCompile(`MTU:(\d+)`)         // 老式 "MTU:1500"
)

// setMTU 复刻 netutils.mtu：ifconfig 缺失 → error；解析当前 MTU（两种格式）；
// 与 value 相等不动；不等则 `ifconfig eth mtu value`（list-args 语义经 sh 传参拼接，
// eth/value 已按 Python 端解析为受控输入）。
func setMTU(eth string, value int) (set bool, err error) {
	if !ensureCommand("ifconfig") {
		return false, errors.New("请检查系统是否存在命令：ifconfig")
	}
	code, stdout, stderr := execCmdArgs("ifconfig", eth)
	if code != 0 {
		return false, fmt.Errorf("执行 ifconfig %s 失败: %s", eth, stderr)
	}
	cur := ""
	for _, line := range strings.Split(stdout, "\n") {
		if m := mtuNewRe.FindStringSubmatch(line); m != nil {
			cur = m[1]
			break
		}
		if m := mtuOldRe.FindStringSubmatch(line); m != nil {
			cur = m[1]
			break
		}
	}
	if cur == "" {
		return false, fmt.Errorf("无法从 ifconfig %s 输出中解析 mtu", eth)
	}
	if n, _ := strconv.Atoi(cur); n == value {
		return false, nil
	}
	// Python 以 list args 防注入：eth 原样进 argv，value 整数化。
	execCmdArgs("ifconfig", eth, "mtu", strconv.Itoa(value))
	return true, nil
}
