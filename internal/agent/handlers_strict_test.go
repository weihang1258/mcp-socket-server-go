package agent

// Python **data 契约：未知键 → TypeError → do() 冒泡 → 断连无响应（handlers.py 各分支）。
// 本文件锁定各 dt 的键白名单与 dt1 的 exec_cmd_subprocess 全参语义（netutils.py:64-84）。

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// unknownKeyContract 各 dt 合法 payload + 注入未知键 → 必须返回 error（断连）。
// 注意 171/173 的键检查发生在"未运行"分支（Python 仅在构造/写文件时 **data 展开）。
func TestStrictKeysRejectUnknown(t *testing.T) {
	cs := &ConnState{}
	cases := []struct {
		name   string
		dt     int32
		valid  string
		poison string // 追加的未知键
	}{
		{"dt7 isfile", 7, `{"file":"/etc/hostname"}`, "extra"},
		{"dt8 isdir", 8, `{"dir":"/tmp"}`, "extra"},
		{"dt9 mkdir", 9, `{"dir":"/tmp"}`, "extra"},
		{"dt10 mtu", 10, `{"eth":"lo","value":1500}`, "extra"},
		{"dt15 unzip", 15, `{"file":"/tmp/x.zip"}`, "path"},
		{"dt18 ensure_command", 18, `{"cmd":"ls"}`, "extra"},
	}
	for _, c := range cases {
		var raw map[string]json.RawMessage
		json.Unmarshal([]byte(c.valid), &raw)
		raw[c.poison] = json.RawMessage(`1`)
		payload, _ := json.Marshal(raw)
		if _, err := Do(cs, c.dt, payload); err == nil {
			t.Errorf("%s: 未知键 %q 必须断连（Python TypeError）", c.name, c.poison)
		}
	}
}

// dt171/173：键检查仅在未运行分支（Python `if ss and ss.pid(): pass` 跳过展开）
func TestListenKeysCheckedOnlyWhenIdle(t *testing.T) {
	stopAllCapturesForTest()
	stopListenForTest()
	cs := &ConnState{}
	// 未运行 + 未知键 → TypeError 断连
	if _, err := Do(cs, 171, []byte(`{"host":null,"port":39013,"extra":1}`)); err == nil {
		t.Fatal("dt171 未运行时未知键必须断连")
	}
	// 173 未运行 → b"error"（不检查键——Python 先判 ss 再展开 **data）
	if resp, err := Do(cs, 173, []byte(`{"weird":1}`)); err != nil || string(resp) != "error" {
		t.Fatalf("dt173 未运行须 b\"error\" 无键检: resp=%q err=%v", resp, err)
	}
}

// dt18 install_cmd：which 失败 → shell 跑 install_cmd → 复查（设计 §2 dt18；netutils.py ensure_command）
func TestDT18InstallCmdInstalls(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "e2e-marker-cmd")
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+"/usr/bin:/bin")
	cs := &ConnState{}
	payload, _ := json.Marshal(map[string]string{
		"cmd":         "e2e-marker-cmd",
		"install_cmd": "cp /bin/true " + bin,
	})
	resp, err := Do(cs, 18, payload)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Res bool `json:"res"`
	}
	json.Unmarshal(resp, &r)
	if !r.Res {
		t.Fatalf("install_cmd 安装后复查须 true: %s", resp)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("install_cmd 未实际执行: %v", err)
	}
}

// dt1 全参语义（netutils.py:64-84）：shell/stdout/stderr/encoding/use_run 是合法键；
// shell=false + 列表 args → argv 直执行；use_run → 阻塞取结果
func TestDT1ShellFalseListArgs(t *testing.T) {
	cs := &ConnState{}
	payload := []byte(`{"args":["echo","hello_argv"],"shell":false}`)
	resp, err := Do(cs, 1, payload)
	if err != nil {
		t.Fatalf("shell=false 列表 args 是合法键: %v", err)
	}
	var r struct {
		Code   int    `json:"code"`
		Stdout string `json:"stdout"`
	}
	g := unwrapGzipResp(t, resp)
	json.Unmarshal(g, &r)
	if r.Code != 0 || r.Stdout != "hello_argv\n" {
		t.Fatalf("argv 执行: %+v", r)
	}
}

func TestDT1UseRunBlocks(t *testing.T) {
	cs := &ConnState{}
	resp, err := Do(cs, 1, []byte(`{"args":"echo hello_use_run","use_run":true,"wait":false}`))
	if err != nil {
		t.Fatal(err)
	}
	// Python use_run 分支无视 wait：subprocess.run 阻塞 → {code,stdout,stderr}（非 "null" 帧）
	var r struct {
		Code   int    `json:"code"`
		Stdout string `json:"stdout"`
	}
	g := unwrapGzipResp(t, resp)
	json.Unmarshal(g, &r)
	if r.Code != 0 || r.Stdout != "hello_use_run\n" {
		t.Fatalf("use_run 须阻塞返回结果: %+v", r)
	}
}

// 缺必需键/null 值 → TypeError 断连（Python **data 缺位置参数；审查 P1-3）
func TestRequiredKeysRejectMissing(t *testing.T) {
	cs := &ConnState{}
	cases := []struct {
		name string
		dt   int32
		body string
	}{
		{"dt7 空对象", 7, `{}`},
		{"dt7 null值", 7, `{"file":null}`},
		{"dt8 空对象", 8, `{}`},
		{"dt9 空对象", 9, `{}`},
		{"dt10 缺eth", 10, `{"value":1500}`},
		{"dt15 空对象", 15, `{}`},
		{"dt18 空对象", 18, `{}`},
	}
	for _, c := range cases {
		if _, err := Do(cs, c.dt, []byte(c.body)); err == nil {
			t.Errorf("%s: 缺必需键必须断连（Python TypeError）", c.name)
		}
	}
}

// dt1 值类型错误 → Python except 兜底 {code:-1} gzip 帧，连接存活（netutils.py:84；审查 P1-2）
func TestDT1TypeErrorsBounded(t *testing.T) {
	cs := &ConnState{}
	for name, body := range map[string]string{
		"args null": `{"args":null}`,
		"args 数字":   `{"args":5}`,
		"args 浮点":   `{"args":5.5}`,
		"args 布尔":   `{"args":true}`,
		"cwd 数字":    `{"args":"ls","cwd":5}`,
		"env 数字":    `{"args":"ls","env":5}`,
	} {
		resp, err := Do(cs, 1, []byte(body))
		if err != nil {
			t.Errorf("%s: 值类型错须兜底帧非断连: %v", name, err)
			continue
		}
		var r struct {
			Code   int    `json:"code"`
			Stderr string `json:"stderr"`
		}
		g := unwrapGzipResp(t, resp)
		json.Unmarshal(g, &r)
		if r.Code != -1 || r.Stderr == "" {
			t.Errorf("%s: 须 {code:-1,stderr非空}: %s", name, g)
		}
	}
}

// dt1 空列表：shell → sh 缺参 code 2；非 shell → IndexError {code:-1}（审查 P0-1）
func TestDT1EmptyArgsNoPanic(t *testing.T) {
	cs := &ConnState{}
	resp, err := Do(cs, 1, []byte(`{"args":[]}`))
	if err != nil {
		t.Fatalf("空列表 shell 路径不得断连: %v", err)
	}
	var r struct {
		Code int `json:"code"`
	}
	json.Unmarshal(unwrapGzipResp(t, resp), &r)
	if r.Code == 0 {
		t.Fatalf("sh -c 缺参须非零退出码: %s", unwrapGzipResp(t, resp))
	}
	resp, _ = Do(cs, 1, []byte(`{"args":[],"shell":false}`))
	json.Unmarshal(unwrapGzipResp(t, resp), &r)
	if r.Code != -1 {
		t.Fatalf("Popen([]) 须 IndexError 兜底: %s", unwrapGzipResp(t, resp))
	}
}

// dt1 shell=false + 字符串 → 整串当可执行名（必失败 {code:-1}，不经 shell；审查 P1-1）
func TestDT1ShellFalseStringIsLiteral(t *testing.T) {
	cs := &ConnState{}
	resp, err := Do(cs, 1, []byte(`{"args":"echo hello_literal","shell":false}`))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Code   int    `json:"code"`
		Stdout string `json:"stdout"`
	}
	json.Unmarshal(unwrapGzipResp(t, resp), &r)
	if r.Code == 0 || r.Stdout != "" {
		t.Fatalf("字符串+shell=false 须按可执行名失败: %+v", r)
	}
}

// dt1 wait 真值：数字 0/1、空串按 Python truthiness（审查 P1-2 同族）
func TestDT1PythonTruthiness(t *testing.T) {
	cs := &ConnState{}
	resp, err := Do(cs, 1, []byte(`{"args":"echo t1","wait":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(unwrapGzipResp(t, resp)) == "null" {
		t.Fatal("wait=1 须真值阻塞")
	}
	resp, _ = Do(cs, 1, []byte(`{"args":"echo t0","wait":0}`))
	if string(unwrapGzipResp(t, resp)) != "null" {
		t.Fatal("wait=0 须假值异步 null 帧")
	}
}

// dt173 非法 JSON 在 ss 判定之前 → 未运行也断连（handlers.py:409 json.loads 先行；审查 P2-2）
func TestDT173InvalidJSONDisconnects(t *testing.T) {
	stopListenForTest()
	cs := &ConnState{}
	if _, err := Do(cs, 173, []byte(`not-json`)); err == nil {
		t.Fatal("非法 JSON 须无条件断连")
	}
}

// dt15 overwrite:null → falsy 不加 -o（netutils.py:239 truthiness；审查 P2-5）
func TestDT15OverwriteNullFalsy(t *testing.T) {
	cs := &ConnState{}
	// 只验证不 panic 且回 ok（unzip 缺失/失败恒 ok）；-o 差异由实现内 truthiness 保证
	resp, err := Do(cs, 15, []byte(`{"file":"/tmp/no_such.zip","overwrite":null}`))
	if err != nil || string(resp) != "ok" {
		t.Fatalf("overwrite:null: resp=%q err=%v", resp, err)
	}
}

// dt171 已存活：payload 值/类型错误照常回 pid（Python 存活分支对 data 只 pass；审查 P2-3）
func TestListenAliveIgnoresPayloadTypes(t *testing.T) {
	resetListen(t)
	port := freePort(t)
	listenStartT(t, port)
	defer stopListenForTest()
	// 存活时坏类型 payload 不检查（Python 只 `pass`）
	resp, err := Do(&ConnState{}, 171, []byte(`{"port":"not-a-number","host":5}`))
	if err != nil {
		t.Fatalf("存活分支类型错不得断连: %v", err)
	}
	var m map[string]any
	if json.Unmarshal(resp, &m) != nil || m["pid"] == nil {
		t.Fatalf("存活分支须回 pid: %s", resp)
	}
	// 存活时未知键同样不检查
	if _, err := Do(&ConnState{}, 171, []byte(`{"weird":1}`)); err != nil {
		t.Fatalf("存活分支未知键不得断连: %v", err)
	}
}

// dt171 死实例分支：旧配置重启，payload 不展开（Python ss.start_server()；审查 P2-1）
func TestListenDeadInstanceRestartsOldConfig(t *testing.T) {
	resetListen(t)
	// 独立进程占住端口（shutdown 的 kill -9 清扫会杀占用者——不能用测试进程自身占位）
	blocker := exec.Command("python3", "-c",
		"import socket,time; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); print(s.getsockname()[1], flush=True); time.sleep(120)")
	stdout, _ := blocker.StdoutPipe()
	blocker.Start()
	defer func() {
		if blocker.Process != nil {
			blocker.Process.Kill()
		}
	}()
	var port int
	fmt.Fscan(bufio.NewReader(stdout), &port)
	if port == 0 {
		t.Fatal("占位进程未就绪")
	}
	if _, err := Do(&ConnState{}, 171, mustJSON(t, map[string]any{"host": "127.0.0.1", "port": port})); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	// 死实例 + 未知键 → Python 不展开 payload，照常重启（仍 bind 失败但不断连）
	resp, err := Do(&ConnState{}, 171, []byte(`{"weird":1}`))
	if err != nil {
		t.Fatalf("死实例分支 payload 不展开: %v", err)
	}
	var m map[string]any
	if json.Unmarshal(resp, &m) != nil || m["pid"] == nil {
		t.Fatalf("死实例重启须回 pid 结构: %s", resp)
	}
	stopListenForTest()
}

// dt131 缺省键对齐 boce() 签名（boce.py:460）：缺 mode → 封堵；缺 timeout → 3；
// 缺 count → 1；thread_count 校验仅封堵分支（审查 P0-2/P0-3/P1-1/P1-2）
func TestBoceDefaultsAndModeDispatch(t *testing.T) {
	cs := &ConnState{}
	// 缺 mode → 封堵路径（127.0.0.1:1 连接拒绝 → 全败，total=1）
	payload, _ := json.Marshal(map[string]any{"url": "http://127.0.0.1:1"})
	resp, err := Do(cs, 131, payload)
	if err != nil {
		t.Fatalf("缺 mode 走封堵不得断连: %v", err)
	}
	var m map[string]any
	json.Unmarshal(unwrapDT131(t, resp), &m)
	if m["total"] != float64(1) || m["fail"] != float64(1) {
		t.Fatalf("缺 mode 须封堵语义 total=1 fail=1: %v", m)
	}
	// 封堵 + thread_count=0 → ValueError 断连
	payload, _ = json.Marshal(map[string]any{"url": "http://127.0.0.1:1", "thread_count": 0})
	if _, err := Do(cs, 131, payload); err == nil {
		t.Fatal("封堵 thread_count=0 须断连")
	}
	// 封堵 + thread_count=-1 → 同样 ValueError（此前只查 "0" 字符串）
	payload, _ = json.Marshal(map[string]any{"url": "http://127.0.0.1:1", "thread_count": -1})
	if _, err := Do(cs, 131, payload); err == nil {
		t.Fatal("封堵 thread_count=-1 须断连")
	}
	// 显式 count=0 → range(0) 空 → total=0（此前误跑 1 次）
	payload, _ = json.Marshal(map[string]any{"url": "http://127.0.0.1:1", "count": 0})
	resp, err = Do(cs, 131, payload)
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(unwrapDT131(t, resp), &m)
	if m["total"] != float64(0) {
		t.Fatalf("count=0 须 total=0: %v", m)
	}
	// 浏览器模式 thread_count=-1 存而不读 → 正常回统计（chromium 环境变量注入）
	t.Setenv("SOCKETSTACK_TEST_CHROMIUM", effectiveChromium(""))
	if !chromiumUsable(effectiveChromium("")) {
		t.Skip("chromium 不存在")
	}
	payload, _ = json.Marshal(map[string]any{"url": "http://127.0.0.1:1", "count": 1, "timeout": 10, "mode": "弹窗", "thread_count": -1})
	resp, err = Do(cs, 131, payload)
	if err != nil {
		t.Fatalf("浏览器模式 thread_count 须被无视: %v", err)
	}
	json.Unmarshal(unwrapDT131(t, resp), &m)
	if m["total"] != float64(1) || m["fail"] != float64(1) {
		t.Fatalf("弹窗恒失败 total=1: %v", m)
	}
}

// dt1 args 是 dict → Python Popen 迭代 keys（python3 -I 实测：{}→code2，
// {"echo pwned":1}→code0 stdout="pwned"）；列表含 null/非串 → TypeError 兜底。
func TestDT1DictAndListElementSemantics(t *testing.T) {
	cs := &ConnState{}
	// 空 dict = 空序列 → sh -c 缺参 code 2（不得按 "dict not iterable" 兜底）
	resp, err := Do(cs, 1, []byte(`{"args":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Code   int    `json:"code"`
		Stdout string `json:"stdout"`
	}
	json.Unmarshal(unwrapGzipResp(t, resp), &r)
	if r.Code == 0 || r.Code == -1 {
		t.Fatalf("空 dict 须走 sh -c 缺参路径(非零非-1): %+v", r)
	}
	// 单键 dict → 真执行 key（Python dict 迭代语义）
	resp, _ = Do(cs, 1, []byte(`{"args":{"echo dict_keys":1}}`))
	json.Unmarshal(unwrapGzipResp(t, resp), &r)
	if r.Code != 0 || !strings.Contains(r.Stdout, "dict_keys") {
		t.Fatalf("dict 须迭代 keys 真执行: %+v", r)
	}
	// 列表元素 null / 数字 → TypeError 兜底（此前 null 被静默成 ""）
	for _, body := range []string{`{"args":["echo",null]}`, `{"args":[null]}`, `{"args":["echo",5]}`} {
		resp, err = Do(cs, 1, []byte(body))
		if err != nil {
			t.Fatalf("%s 须兜底帧非断连: %v", body, err)
		}
		json.Unmarshal(unwrapGzipResp(t, resp), &r)
		if r.Code != -1 {
			t.Errorf("%s: 须 TypeError 兜底 -1: %+v", body, r)
		}
	}
}

// dt131 显式 mode:"" ≠ 缺省 → Python pyppeteer 未知模式恒败（不得走封堵）
func TestBoceExplicitEmptyModeIsUnknown(t *testing.T) {
	cs := &ConnState{}
	payload := []byte(`{"url":"http://127.0.0.1:1","mode":"","count":1,"timeout":10}`)
	resp, err := Do(cs, 131, payload)
	if err != nil {
		t.Fatalf("显式空 mode 走未知模式(恒败)不得断连: %v", err)
	}
	var m map[string]any
	json.Unmarshal(unwrapDT131(t, resp), &m)
	if m["total"] != float64(1) || m["fail"] != float64(1) || m["success"] != float64(0) {
		t.Fatalf("显式 mode:\"\" 须未知模式全败: %v", m)
	}
}

// dt131 浏览器模式显式 chromium_path:"" → Python boce.py:475 ValueError 冒泡断连
// （预检 isfile("") 假会先下载失败；此处注入 ensure 成功以走到 mode 分派）
func TestBoceEmptyChromiumPathBrowerDisconnects(t *testing.T) {
	setEnsureChromium(func(string) bool { return true })
	t.Cleanup(func() { setEnsureChromium(nil) })
	cs := &ConnState{}
	for _, mode := range []string{"重定向", "弹窗", "未知模式"} {
		payload := []byte(`{"url":"http://127.0.0.1:1","count":1,"mode":"` + mode + `","chromium_path":""}`)
		if _, err := Do(cs, 131, payload); err == nil {
			t.Errorf("mode=%s + 空 chromium_path 须断连（Python ValueError）", mode)
		}
	}
	// 封堵模式不受此限（Python 只对非封堵检查）
	payload := []byte(`{"url":"http://127.0.0.1:1","count":1,"mode":"封堵","chromium_path":""}`)
	if _, err := Do(cs, 131, payload); err != nil {
		t.Fatalf("封堵模式空 chromium_path 不得断连: %v", err)
	}
}

// dt10 value:null → Python ifconfig eth mtu None 必败吞错 + sleep5，网卡不动
func TestDT10ValueNullNoMutation(t *testing.T) {
	cs := &ConnState{}
	before, _ := os.ReadFile("/sys/class/net/lo/mtu")
	start := time.Now()
	resp, err := Do(cs, 10, []byte(`{"eth":"lo","value":null}`))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Res any `json:"res"`
	}
	json.Unmarshal(resp, &r)
	if r.Res != nil {
		t.Fatalf("value:null 须 res null: %s", resp)
	}
	if time.Since(start) < 4*time.Second {
		t.Fatal("value:null 须 sleep5（Python int!=None 恒真走设置分支）")
	}
	after, _ := os.ReadFile("/sys/class/net/lo/mtu")
	if string(before) != string(after) {
		t.Fatalf("value:null 不得改动 MTU: %s→%s", before, after)
	}
}

// dt173 合法但非对象 JSON 未运行 → b"error"（Python json.loads 成功后直接判 ss）
func TestDT173NonObjectJSONIdle(t *testing.T) {
	stopListenForTest()
	cs := &ConnState{}
	resp, err := Do(cs, 173, []byte(`[1,2]`))
	if err != nil || string(resp) != "error" {
		t.Fatalf("非对象 JSON 未运行须 b\"error\": resp=%q err=%v", resp, err)
	}
}
