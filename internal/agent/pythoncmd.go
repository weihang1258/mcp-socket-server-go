package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// dt16 python_cmd（netutils.py:253 的受限复刻）。
//
// Python 原版是 `eval(args[0])` 然后再对后续 arg 做 `eval("res."+arg)`，
// 等于在靶机上执行任意 Python——Go 没有解释器，也不可能照搬 eval。
// 但验收客户端 device/socket_linux.py 只用了两个极窄形态（全仓仅 3 处调用）：
//
//	python_cmd(f"os.popen('cd <dir>;find ./ -maxdepth 1 -name \"*.pcap\"|sort -V')", "read()")
//	python_cmd(f"os.popen('wget ...')", "read()")
//
// 2026-11-02 客户端实测：download_pcap 下载**目录**时走 listdir → dt16，
// Go 版此前不回任何字节 → 客户端 recv 永久阻塞（pcapdump 下载卡死、服务端无日志）。
// 因此按白名单支持 os.popen(<shell 字面量>) 及随后的 .read()/.readlines()/... 链，
// 其余表达式返回 error JSON（客户端 json 解析成功，不会挂死）。

var (
	rePyPopen     = regexp.MustCompile(`^os\.popen\(\s*(?:'([^']*)'|"([^"]*)")\s*\)$`)
	rePyChainCall = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\(\)(?:\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\(\))*$`)
	reChainSeg    = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\(\)`)
)

// pythonCmd dt16 响应：[4B i][gzip JSON]。整帧一次返回，客户端单次 recv 才能拿到长度。
func pythonCmd(payload []byte) ([]byte, error) {
	var args []string
	if err := json.Unmarshal(payload, &args); err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return pythonCmdJSON(map[string]string{"error": "python_cmd 缺少参数"})
	}
	res, err := pyEvalPopen(args[0])
	if err != nil {
		return pythonCmdJSON(map[string]string{"error": err.Error()})
	}
	for _, arg := range args[1:] {
		res, err = pyApplyChain(res, arg)
		if err != nil {
			return pythonCmdJSON(map[string]string{"error": err.Error()})
		}
	}
	return pythonCmdJSON(res)
}

func pythonCmdJSON(v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	out := make([]byte, 4+buf.Len())
	putInt32LE(out, int32(buf.Len()))
	copy(out[4:], buf.Bytes())
	return out, nil
}

func putInt32LE(b []byte, v int32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// pyEvalPopen 只认 os.popen('...') 字面量。
func pyEvalPopen(expr string) (any, error) {
	m := rePyPopen.FindStringSubmatch(strings.TrimSpace(expr))
	if m == nil {
		return nil, fmt.Errorf("不支持的 python 表达式（仅支持 os.popen('cmd')）: %s", truncate(expr, 120))
	}
	script := m[1]
	if script == "" {
		script = m[2]
	}
	// Python os.popen 走 /bin/sh -c，read() 返回全部 stdout 字符串（含结尾换行）。
	// Python os.popen 不抛异常：命令非 0 退出时 read() 仍返回已产生的 stdout。
	var stdout bytes.Buffer
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Stdout = &stdout
	_ = cmd.Run()
	return stdout.String(), nil
}

// pyApplyChain 支持 res.<name>() 链（read/readlines/strip/lstrip/rstrip/upper/lower/splitlines），
// 以及 "read().strip()" 这种在同一个参数里连写的多段链。
func pyApplyChain(res any, arg string) (any, error) {
	s, ok := res.(string)
	if !ok {
		return nil, fmt.Errorf("链式调用只支持字符串结果: %v", res)
	}
	arg = strings.TrimSpace(arg)
	if !rePyChainCall.MatchString(arg) {
		return nil, fmt.Errorf("不支持的链式调用（仅支持 res.xxx()）: %s", truncate(arg, 80))
	}
	for _, m := range reChainSeg.FindAllStringSubmatch(arg, -1) {
		var err error
		s, err = pyChainOne(s, m[1])
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func pyChainOne(s, name string) (string, error) {
	switch name {
	case "read":
		return s, nil
	case "strip":
		return strings.TrimSpace(s), nil
	case "lstrip":
		return strings.TrimLeft(s, " \t\r\n"), nil
	case "rstrip":
		return strings.TrimRight(s, " \t\r\n"), nil
	case "upper":
		return strings.ToUpper(s), nil
	case "lower":
		return strings.ToLower(s), nil
	default:
		// python_cmd 场景只用 read()/strip()；其余显式报错，避免误判成功
		return "", fmt.Errorf("不支持的链式方法: %s()", name)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
