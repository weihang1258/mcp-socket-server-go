package agent

// Python **data 契约：未知键 → TypeError → do() 冒泡 → 断连无响应（handlers.py 各分支）。
// 本文件锁定各 dt 的键白名单与 dt1 的 exec_cmd_subprocess 全参语义（netutils.py:64-84）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
