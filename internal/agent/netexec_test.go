package agent

import (
	"encoding/json"
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
func TestDT4Routeinfo(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("PATH", fake)
	route := `#!/bin/sh
echo "Kernel IP routing table"
echo "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface"
echo "0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 eth0"
echo "192.168.1.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0"
`
	os.WriteFile(filepath.Join(fake, "route"), []byte(route), 0o755)

	resp, err := runDT(t, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]map[string]any
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("dt4 resp not object-keyed-by-destination: %v (%q)", err, resp)
	}
	eth0 := m["0.0.0.0"]
	if eth0 == nil || eth0["Iface"] != "eth0" {
		t.Fatalf("default route wrong: %v", eth0)
	}
	if m["192.168.1.0"] == nil {
		t.Fatalf("second route missing: %v", m)
	}
}

// dt4：route -n 失败 → RuntimeError → 断连（Do 返回 error）
func TestDT4RouteFailureErrors(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("PATH", fake) // 无 route 命令
	if _, err := runDT(t, 4, nil); err == nil {
		t.Fatal("want error for missing route cmd")
	}
	// 命令存在但非零退出
	os.WriteFile(filepath.Join(fake, "route"), []byte("#!/bin/sh\nexit 3\n"), 0o755)
	if _, err := runDT(t, 4, nil); err == nil {
		t.Fatal("want error for route nonzero exit")
	}
}

// dt10 改 MTU：新式 "mtu 1500" 与老式 "MTU:1500" 两种解析；值相等不设置；
// 不等则执行 ifconfig eth mtu <value>（fake 记录调用）
func TestDT10MTU(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("PATH", fake)
	ifcfg := `#!/bin/sh
if [ "$2" = "mtu" ]; then echo "SET $@" >> '` + filepath.Join(fake, "calls") + `'; exit 0; fi
echo "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500"
echo "        inet 192.168.1.10  netmask 255.255.255.0"`
	os.WriteFile(filepath.Join(fake, "ifconfig"), []byte(ifcfg), 0o755)

	// 值相等 → 不调用设置
	payload, _ := json.Marshal(map[string]any{"eth": "eth0", "value": 1500})
	if _, err := runDT(t, 10, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(fake, "calls")); !os.IsNotExist(err) {
		t.Fatal("equal mtu must not invoke set")
	}

	// 值不等 → 调用 ifconfig eth0 mtu 2000；返回 {"res":null}
	payload, _ = json.Marshal(map[string]any{"eth": "eth0", "value": 2000})
	resp, err := runDT(t, 10, payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != `{"res":null}` {
		t.Fatalf("want {\"res\":null}, got %q", resp)
	}
	calls, _ := os.ReadFile(filepath.Join(fake, "calls"))
	if string(calls) != "SET eth0 mtu 2000\n" {
		t.Fatalf("set call wrong: %q", calls)
	}
}

// dt10 老式 MTU:1500 格式解析
func TestDT10MTUOldFormat(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("PATH", fake)
	os.WriteFile(filepath.Join(fake, "ifconfig"), []byte(`#!/bin/sh
echo "eth0      Link encap:Ethernet  HWaddr AA:BB  MTU:1500"
`), 0o755)
	payload, _ := json.Marshal(map[string]any{"eth": "eth0", "value": 1500})
	if _, err := runDT(t, 10, payload); err != nil {
		t.Fatalf("old-format parse failed: %v", err)
	}
}

// dt10 ifconfig 缺失 → RuntimeError → 断连
func TestDT10MissingIfconfig(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("PATH", fake)
	payload, _ := json.Marshal(map[string]any{"eth": "eth0", "value": 1500})
	if _, err := runDT(t, 10, payload); err == nil {
		t.Fatal("want error for missing ifconfig")
	}
}
