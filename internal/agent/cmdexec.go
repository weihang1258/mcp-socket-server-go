package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
func cmdExec(payload []byte) ([]byte, error) {
	var p struct {
		Args string            `json:"args"`
		Cwd  string            `json:"cwd"`
		Env  map[string]string `json:"env"`
		Wait *bool             `json:"wait"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	wait := true
	if p.Wait != nil {
		wait = *p.Wait
	}

	args := p.Args
	if os.Geteuid() == 0 {
		args = stripSudoPrefix(args)
	}
	env := cleanEnv(os.Environ())
	if p.Env != nil {
		env = cleanEnv(envMapToSlice(p.Env))
	}

	var code int
	var stdout, stderr string
	if wait {
		code, stdout, stderr = execCmdWith(args, p.Cwd, env, true)
	} else {
		// 异步：Start 不等（Python Popen 不 communicate → 返回 None）；
		// Start 失败 = Python Popen 抛异常 → except → {code:-1,...} gzip JSON（非 "null"）
		if code, _, stderr = execCmdWith(args, p.Cwd, env, false); code == -1 {
			return errGzipFrame(code, stderr)
		}
		return gzipFrame([]byte("null")), nil
	}
	return errGzipFrame(code, stdout, stderr)
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
	var p struct {
		File      string `json:"file"`
		Outdir    string `json:"outdir"`
		Passwd    string `json:"passwd"`
		Overwrite *bool  `json:"overwrite"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	overwrite := true
	if p.Overwrite != nil {
		overwrite = *p.Overwrite
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
