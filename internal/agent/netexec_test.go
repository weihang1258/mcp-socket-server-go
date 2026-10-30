package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runDT(t *testing.T, dt int32, payload []byte) ([]byte, error) {
	t.Helper()
	cs := newConnState()
	return Do(cs, dt, payload)
}

// dt7 isfile：payload {"file": path} → {"res":bool}
func TestDT7Isfile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "a.txt")
	os.WriteFile(f, []byte("x"), 0o644)

	resp, err := runDT(t, 7, mustJSON(t, map[string]string{"file": f}))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != `{"res":true}` {
		t.Fatalf("existing file: %q", resp)
	}
	resp, _ = runDT(t, 7, mustJSON(t, map[string]string{"file": f + ".nope"}))
	if string(resp) != `{"res":false}` {
		t.Fatalf("missing file: %q", resp)
	}
}

// dt8 isdir：payload {"dir": path} → {"res":bool}
func TestDT8Isdir(t *testing.T) {
	d := t.TempDir()
	resp, _ := runDT(t, 8, mustJSON(t, map[string]string{"dir": d}))
	if string(resp) != `{"res":true}` {
		t.Fatalf("existing dir: %q", resp)
	}
	resp, _ = runDT(t, 8, mustJSON(t, map[string]string{"dir": d + "/nope"}))
	if string(resp) != `{"res":false}` {
		t.Fatalf("missing dir: %q", resp)
	}
}

// dt9 mkdir：os.makedirs 语义（递归）；返回 None → {"res":null}
func TestDT9Mkdir(t *testing.T) {
	d := filepath.Join(t.TempDir(), "a", "b", "c")
	resp, err := runDT(t, 9, mustJSON(t, map[string]string{"dir": d}))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != `{"res":null}` {
		t.Fatalf("want {\"res\":null}, got %q", resp)
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		t.Fatal("dir not created")
	}
}

// dt11 取字节数：payload {"path":...} → {"res":size}
func TestDT11Getsize(t *testing.T) {
	f := filepath.Join(t.TempDir(), "b.bin")
	os.WriteFile(f, []byte("12345"), 0o644)
	resp, err := runDT(t, 11, mustJSON(t, map[string]string{"path": f}))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != `{"res":5}` {
		t.Fatalf("want {\"res\":5}, got %q", resp)
	}
}

// dt18 ensure_command：PATH 上找得到 → true；找不到 → false
func TestDT18EnsureCommand(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("PATH", fake)
	resp, _ := runDT(t, 18, mustJSON(t, map[string]string{"cmd": "nosuchcmd-xyz"}))
	if string(resp) != `{"res":false}` {
		t.Fatalf("missing cmd: %q", resp)
	}
	os.WriteFile(filepath.Join(fake, "faketool"), []byte("#!/bin/sh\n"), 0o755)
	resp, _ = runDT(t, 18, mustJSON(t, map[string]string{"cmd": "faketool"}))
	if string(resp) != `{"res":true}` {
		t.Fatalf("existing cmd: %q", resp)
	}
}

// dt19 版本详情：纯本地；注入版本 == VERSION 时 has_upgrade=false
func TestDT19VersionDetail(t *testing.T) {
	resp, err := runDT(t, 19, nil)
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	if err := json.Unmarshal(resp, &info); err != nil {
		t.Fatal(err)
	}
	if info["version"] != Version || info["repo"] != Repo {
		t.Fatalf("version/repo wrong: %v", info)
	}
	if info["has_upgrade"] != false {
		t.Fatalf("has_upgrade want false (同源注入), got %v", info["has_upgrade"])
	}
	if _, ok := info["release_notes"]; !ok {
		t.Fatal("release_notes key missing")
	}
	if _, ok := info["latest_version"]; !ok {
		t.Fatal("latest_version key missing")
	}
}

// dt4 routeinfo：route -n 输出解析（2 行头 + 数据行 zip 到 Destination 键）
// dt4 routeinfo 原生实现：读 /proc/net/route（route -n 的数据源），
// 输出与 route -n 解析同构：外层按 Destination 键控，行含
// Gateway/Genmask/Flags/Metric/Ref/Use/Iface，值为 route -n 的文本格式
// （IP 点分、Flags 字母、Metric/Ref/Use 十进制）。fixture 抄自真机格式。
func TestDT4Routeinfo(t *testing.T) {
	fixture := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT   \n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0    \n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0    \n"
	p := filepath.Join(t.TempDir(), "route")
	os.WriteFile(p, []byte(fixture), 0o644)
	prev := routeTablePath
	routeTablePath = p
	t.Cleanup(func() { routeTablePath = prev })

	resp, err := runDT(t, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]map[string]any
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("dt4 resp not object-keyed-by-destination: %v (%q)", err, resp)
	}
	def := m["0.0.0.0"]
	if def == nil || def["Iface"] != "eth0" {
		t.Fatalf("default route wrong: %v", def)
	}
	// 值必须是 route -n 的文本格式（与旧实现逐字段一致，客户端契约）
	if def["Gateway"] != "192.168.1.1" || def["Flags"] != "UG" || def["Metric"] != "100" || def["Genmask"] != "0.0.0.0" {
		t.Fatalf("default route fields wrong: %v", def)
	}
	lan := m["192.168.1.0"]
	if lan == nil {
		t.Fatalf("second route missing: %v", m)
	}
	if lan["Genmask"] != "255.255.255.0" || lan["Flags"] != "U" || lan["Gateway"] != "0.0.0.0" {
		t.Fatalf("lan route fields wrong: %v", lan)
	}
}

// dt4：路由表读不到 → error → 断连（对齐 Python routeinfo() 异常冒泡）
func TestDT4RouteFailureErrors(t *testing.T) {
	prev := routeTablePath
	routeTablePath = filepath.Join(t.TempDir(), "not-exist")
	t.Cleanup(func() { routeTablePath = prev })
	if _, err := runDT(t, 4, nil); err == nil {
		t.Fatal("want error for unreadable route table")
	}
}

// /proc/net/route 十六进制字段解码（真机实测样例：网关 FE830C0A=10.12.131.254）
func TestRouteDecodeHelpers(t *testing.T) {
	if got := hexIP("FE830C0A"); got != "10.12.131.254" {
		t.Fatalf("hexIP(FE830C0A)=%q", got)
	}
	if got := hexIP("0101A8C0"); got != "192.168.1.1" {
		t.Fatalf("hexIP(0101A8C0)=%q", got)
	}
	if got := hexIP("00000000"); got != "0.0.0.0" {
		t.Fatalf("hexIP(00000000)=%q", got)
	}
	if got := hexIP("00FFFFFF"); got != "255.255.255.0" {
		t.Fatalf("hexIP(00FFFFFF)=%q", got)
	}
	if got := routeFlagLetters("0003"); got != "UG" {
		t.Fatalf("flags(0003)=%q", got)
	}
	if got := routeFlagLetters("0001"); got != "U" {
		t.Fatalf("flags(0001)=%q", got)
	}
}

// dt10 改 MTU（原生 ioctl）：值相等不设置；不等则调用设置并返回 {"res":null}。
// 设置失败仅记日志（Python exec 吞错语义），查询失败才断连。
func TestDT10MTU(t *testing.T) {
	prevGet, prevSet := getMTUFn, setMTUFn
	defer func() { getMTUFn, setMTUFn = prevGet, prevSet }()
	var setCalls []string
	getMTUFn = func(eth string) (int, error) {
		if eth != "eth0" {
			t.Errorf("getMTUFn eth=%q, want eth0", eth)
		}
		return 1500, nil
	}
	setMTUFn = func(eth string, mtu int) error {
		setCalls = append(setCalls, fmt.Sprintf("%s %d", eth, mtu))
		return nil
	}

	// 值相等 → 不调用设置
	payload, _ := json.Marshal(map[string]any{"eth": "eth0", "value": 1500})
	if _, err := runDT(t, 10, payload); err != nil {
		t.Fatal(err)
	}
	if len(setCalls) != 0 {
		t.Fatal("equal mtu must not invoke set")
	}

	// 值不等 → 设置 eth0 mtu 2000；返回 {"res":null}
	payload, _ = json.Marshal(map[string]any{"eth": "eth0", "value": 2000})
	resp, err := runDT(t, 10, payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != `{"res":null}` {
		t.Fatalf("want {\"res\":null}, got %q", resp)
	}
	if len(setCalls) != 1 || setCalls[0] != "eth0 2000" {
		t.Fatalf("set call wrong: %v", setCalls)
	}
}

// dt10 查询 MTU 失败（网卡不存在等）→ error → 断连（原 ifconfig 缺失同路径）
func TestDT10GetMTUError(t *testing.T) {
	prevGet := getMTUFn
	defer func() { getMTUFn = prevGet }()
	getMTUFn = func(string) (int, error) { return 0, errors.New("no such device") }
	payload, _ := json.Marshal(map[string]any{"eth": "eth9", "value": 1500})
	if _, err := runDT(t, 10, payload); err == nil {
		t.Fatal("want error for MTU query failure")
	}
}
