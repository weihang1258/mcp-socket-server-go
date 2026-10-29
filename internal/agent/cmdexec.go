package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// processExitCode 信号死亡的进程返回 -signum（对齐 Python subprocess returncode）。
func processExitCode(ee *exec.ExitError) int {
	if ws, ok := ee.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return -int(ws.Signal())
	}
	return ee.ExitCode()
}

// execExitError 退出码错误别名。
type execExitError = exec.ExitError

// cmdExec dt1（设计 §3）：
// - payload {"args","cwd?","env?","wait?"}；shell+字符串 → root 剥裸 sudo
// - env 键存在时**整替换**子进程环境（Python dict(os.environ if env is None else env)）
// - wait=false → 立即返回 None → json "null" 仍回 gzip 帧（quirk）
// - 响应 [4B i][gzip JSON {code,stdout,stderr}]；执行异常 → {code:-1,stderr:str(e)}
// pyTruthy Python 真值语义（wait/shell/use_run 数值/字符串/容器都按 Python 真值）。
func pyTruthy(raw json.RawMessage) bool {
	switch string(raw) {
	case "null", "false", "0":
		return false
	case "true":
		return true
	}
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return f != 0
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return str != ""
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		return len(arr) > 0
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		return len(obj) > 0
	}
	return false
}

// jsonTypeName Python 类型名（{code:-1} 兜底消息用）。
func jsonTypeName(raw json.RawMessage) string {
	switch string(raw) {
	case "null":
		return "NoneType"
	case "true", "false":
		return "bool"
	}
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		if strings.ContainsAny(string(raw), ".eE") { // Python float vs int
			return "float"
		}
		return "int"
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return "str"
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		return "list"
	}
	return "dict"
}

// badType Python exec_cmd_subprocess 内 TypeError → except 兜底帧（连接存活）。
func badType(msg string) ([]byte, error) { return errGzipFrame(-1, "", msg) }

func cmdExec(payload []byte) ([]byte, error) {
	var raw1 map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw1); err != nil {
		return nil, err // handlers 层 json.loads 异常 → 断连
	}
	if _, ok := raw1["args"]; !ok {
		return nil, errors.New("exec_cmd_subprocess() missing required argument: 'args'")
	}
	for k := range raw1 {
		switch k {
		case "args", "cwd", "env", "wait", "shell", "stdout", "stderr", "encoding", "use_run":
		default:
			return nil, fmt.Errorf("exec_cmd_subprocess() got unexpected keyword argument %q", k)
		}
	}
	// 值类型错误发生在 Python try 块内 → except 兜底 {code:-1,stderr}，连接存活（netutils.py:84）
	args, argsIsStr := raw1["args"], false
	var argsStr string
	var argv []string
	if string(args) == "null" {
		return badType("'NoneType' object is not iterable") // args=null
	}
	if err := json.Unmarshal(args, &argsStr); err == nil {
		argsIsStr = true
	} else {
		// Python Popen 只要求 args 可迭代：列表/dict 皆可（dict 迭代 keys，实测 code 0 真执行）
		var rawArr []json.RawMessage
		var rawObj map[string]json.RawMessage
		switch {
		case json.Unmarshal(args, &rawArr) == nil:
			for _, e := range rawArr { // 元素须逐条是字符串；null/数字 → Python TypeError
				if string(e) == "null" {
					return badType("expected str, bytes or os.PathLike object, not NoneType")
				}
				var s string
				if json.Unmarshal(e, &s) != nil {
					return badType("expected str, bytes or os.PathLike object, not " + jsonTypeName(e))
				}
				argv = append(argv, s)
			}
			if argv == nil {
				argv = []string{} // 保持非 nil 空切片，走"空列表"分支
			}
		case json.Unmarshal(args, &rawObj) == nil:
			keys := make([]string, 0, len(rawObj))
			for k := range rawObj {
				keys = append(keys, k)
			}
			sort.Strings(keys) // Python dict 插入序不可由 JSON 稳定还原；单键场景（真实用法）确定
			argv = keys
		default:
			return badType("'" + jsonTypeName(args) + "' object is not iterable") // args=5/true/5.5
		}
	}
	wait := true
	if r, ok := raw1["wait"]; ok {
		wait = pyTruthy(r)
	}
	shell := true // Python 默认 shell=True
	if r, ok := raw1["shell"]; ok {
		shell = pyTruthy(r)
	}
	useRun := false
	if r, ok := raw1["use_run"]; ok {
		useRun = pyTruthy(r)
	}
	// use_run 分支无视 wait：subprocess.run 阻塞 → {code,stdout,stderr}
	if useRun {
		wait = true
	}
	cwd := ""
	if r, ok := raw1["cwd"]; ok && string(r) != "null" {
		if err := json.Unmarshal(r, &cwd); err != nil {
			return badType("expected str, bytes or os.PathLike object, not " + jsonTypeName(r))
		}
	}
	env := cleanEnv(os.Environ())
	if r, ok := raw1["env"]; ok && string(r) != "null" {
		var em map[string]string
		if err := json.Unmarshal(r, &em); err != nil {
			return badType("env: expected dict, got " + jsonTypeName(r))
		}
		env = cleanEnv(envMapToSlice(em))
	}

	// 形态归一（Python subprocess 语义）：
	//   列表+shell: ['/bin/sh','-c'] + args（sh -c cmd 其余作 $0…）；空列表 → sh -c 缺参（code 2）
	//   列表+!shell: argv 直执行；空列表 → Popen([]) IndexError
	//   字符串+shell: sh -c（root 剥裸 sudo——仅此路径，netutils.py:67）
	//   字符串+!shell: 整串当可执行名 → 必 FileNotFoundError → {code:-1}
	switch {
	case argsIsStr && shell:
		if os.Geteuid() == 0 {
			argsStr = stripSudoPrefix(argsStr)
		}
		argv = []string{"sh", "-c", argsStr}
	case argsIsStr:
		argv = []string{argsStr}
	case len(argv) == 0 && shell:
		argv = []string{"sh", "-c"}
	case len(argv) == 0:
		return badType("list index out of range")
	case shell:
		argv = append([]string{"sh", "-c", argv[0]}, argv[1:]...)
	}

	var code int
	var stdout, stderr string
	if wait {
		code, stdout, stderr = execArgvWait(argv, cwd, env)
		return errGzipFrame(code, stdout, stderr)
	}
	// 异步：Start 不等（Python Popen 不 communicate → 返回 None）；
	// Start 失败 = Python Popen 抛异常 → except → {code:-1,...} gzip JSON（非 "null"）
	if code, _, stderr = execArgvStart(argv, cwd, env); code == -1 {
		return errGzipFrame(code, "", stderr) // 复审 F4：stderr 进 stderr 字段
	}
	return gzipFrame([]byte("null")), nil
}

// execArgvWait execCmdArgs 带工作目录/环境的 argv 变体（dt1 shell=false 路径）。
func execArgvWait(argv []string, cwd string, env []string) (int, string, string) {
	c := argvCmd(argv)
	c.Dir = cwd
	c.Env = env
	var stdoutBuf, stderrBuf bytes.Buffer
	c.Stdout = &stdoutBuf
	c.Stderr = &stderrBuf
	err := c.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = processExitCode(ee)
		} else {
			return -1, "", err.Error()
		}
	}
	return code, stdoutBuf.String(), stderrBuf.String()
}

// execArgvStart Popen 语义：只 Start 不等；失败 = Python Popen 异常 → {code:-1,stderr}。
func execArgvStart(argv []string, cwd string, env []string) (int, string, string) {
	c := argvCmd(argv)
	c.Dir = cwd
	c.Env = env
	c.Stdout = io.Discard // Python PIPE：输出进管道被丢弃，不得漏进 agent 终端/journal
	c.Stderr = io.Discard
	if err := c.Start(); err != nil {
		return -1, "", err.Error()
	}
	go func() { c.Wait() }() // 回收僵尸，不阻塞
	return 0, "", ""
}

// errGzipFrame [4B i][gzip JSON {code,stdout,stderr}]。
func errGzipFrame(code int, vals ...string) ([]byte, error) {
	var stdout, stderr string
	if len(vals) > 0 {
		stdout = vals[0]
	}
	if len(vals) > 1 {
		stderr = vals[1]
	}
	body, err := json.Marshal(struct {
		Code   int    `json:"code"`
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
	}{code, stdout, stderr})
	if err != nil {
		return nil, err
	}
	return gzipFrame(body), nil
}

func envMapToSlice(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

// execCmdWith execCmd 的 cwd/env/wait 全参版（dt1 用）。
func execCmdWith(cmd, cwd string, env []string, wait bool) (int, string, string) {
	c := shellCmd(cmd, env)
	if cwd != "" {
		c.Dir = cwd
	}
	if !wait {
		c.Stdout = io.Discard // Python PIPE：输出进管道被丢弃，不进 agent 日志
		c.Stderr = io.Discard
		if err := c.Start(); err != nil {
			return -1, "", err.Error()
		}
		go func() { c.Wait() }() // 防僵尸；语义对齐 Popen 不等待
		return 0, "", ""
	}
	var so, se bytes.Buffer
	c.Stdout = &so
	c.Stderr = &se
	err := c.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*execExitError); ok {
			code = processExitCode(ee) // 信号死亡 → -signum（Python subprocess 语义）
		} else {
			return -1, "", err.Error()
		}
	}
	return code, so.String(), se.String()
}

// gzipFrame [4B i][gzip body]（dt1 响应形态）。
func gzipFrame(body []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(body)
	zw.Close()
	out := make([]byte, 4+buf.Len())
	binary.LittleEndian.PutUint32(out, uint32(buf.Len()))
	copy(out[4:], buf.Bytes())
	return out
}

// unzipCmd dt15：unzip 可用性检查失败静默返回；list-args 防注入；
// cwd=dirname(file)；恒回 b"ok"（unzip 缺失/执行失败也不影响）。
func unzipCmd(payload []byte) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}
	var p struct {
		File   string `json:"file"`
		Outdir string `json:"outdir"`
		Passwd string `json:"passwd"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	overwrite := true
	if r, ok := raw["overwrite"]; ok {
		overwrite = pyTruthy(r) // Python truthiness：null → falsy 不加 -o（netutils.py:239）
	}
	if code, _, _ := execCmdArgs("unzip", "-v"); code != 0 { // Python 实跑 unzip -v 且要求 exit 0
		return []byte("ok"), nil // quirk：缺失/不可用静默返回，仍 ok
	}
	argv := []string{"unzip"}
	if overwrite {
		argv = append(argv, "-o")
	}
	if p.Passwd != "" {
		argv = append(argv, "-P", p.Passwd)
	}
	argv = append(argv, filepath.Base(p.File))
	if p.Outdir != "" {
		argv = append(argv, "-d", p.Outdir)
	}
	c := argvCmd(argv)
	c.Stdout = io.Discard // Python PIPE 收走，不进 agent 日志
	c.Stderr = io.Discard
	if dir := filepath.Dir(p.File); dir != "" && dir != "." {
		c.Dir = dir
	}
	c.Run()
	return []byte("ok"), nil
}
