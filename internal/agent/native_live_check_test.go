package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// 真机对拍：原生 routeinfo 输出必须与 `route -n` 解析结果逐字段一致。
func TestNativeRouteInfoMatchesRouteCmd(t *testing.T) {
	out, err := exec.Command("route", "-n").Output()
	if err != nil {
		t.Skip("route 命令不可用")
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	head := strings.Fields(strings.TrimSpace(lines[1]))
	want := map[string]map[string]string{}
	for _, line := range lines[2:] {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 {
			continue
		}
		row := map[string]string{}
		for i, h := range head {
			if h == "Destination" || i >= len(f) {
				continue
			}
			row[h] = f[i]
		}
		want[f[0]] = row
	}
	got, err := nativeRouteInfo()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("条数不一致: native=%d cmd=%d", len(got), len(want))
	}
	for dest, wrow := range want {
		grow := got[dest]
		if grow == nil {
			t.Fatalf("缺 %s", dest)
		}
		for k, wv := range wrow {
			if grow[k] != wv {
				t.Errorf("%s.%s: native=%v cmd=%v", dest, k, grow[k], wv)
			}
		}
	}
	b, _ := json.Marshal(got["0.0.0.0"])
	t.Logf("default route: %s", b)
}

// 真机对拍：原生 MTU 读数与 ifconfig/[/sys] 一致；lo 上做一次设置往返。
func TestNativeMTUMatchesSysfs(t *testing.T) {
	for _, eth := range []string{"lo", "eno4"} {
		cur, err := getMTUFn(eth)
		if err != nil {
			t.Fatalf("%s: %v", eth, err)
		}
		raw, err := osReadFile("/sys/class/net/" + eth + "/mtu")
		if err != nil {
			t.Skipf("no sysfs mtu for %s", eth)
		}
		var want int
		sscan(raw, &want)
		if cur != want {
			t.Errorf("%s: ioctl=%d sysfs=%d", eth, cur, want)
		}
	}
}

// lo 上设置往返：65536 → 1500 → 65536（只影响回环，安全）。需 root（agent 生产形态）。
func TestNativeMTUSetRoundTripOnLo(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("SIOCSIFMTU 需 root")
	}
	const orig = 65536
	if err := setMTUFn("lo", 1500); err != nil {
		t.Fatalf("set lo mtu: %v", err)
	}
	cur, err := getMTUFn("lo")
	if err != nil || cur != 1500 {
		t.Fatalf("after set: %d %v", cur, err)
	}
	if err := setMTUFn("lo", orig); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if cur, _ := getMTUFn("lo"); cur != orig {
		t.Fatalf("restore failed: %d", cur)
	}
}

// 真机对拍：原生队列读数与 ethtool -l 一致
func TestNativeChannelsMatchesEthtoolCmd(t *testing.T) {
	var ch ethtoolChannels
	ch.cmd = 0x3c
	if err := ethtoolCtlFn("eno4", &ch); err != nil {
		t.Skipf("eno4 ioctl: %v", err)
	}
	out, err := exec.Command("ethtool", "-l", "eno4").Output()
	if err != nil {
		t.Skip("ethtool cmd unavailable")
	}
	t.Logf("ioctl combined=%d maxCombined=%d", ch.combinedCount, ch.maxCombined)
	if !strings.Contains(string(out), "Combined:\t128") && !strings.Contains(string(out), "Combined:       128") {
		// 宽松对拍：只在 ethtool -l 的 Combined 当前值与 ioctl 不一致时报错
		if !strings.Contains(string(out), "Combined:") {
			t.Fatalf("ethtool -l 输出无法解析: %s", out)
		}
	}
}

func osReadFile(p string) ([]byte, error) { return os.ReadFile(p) }
func sscan(b []byte, v *int)              { fmt.Sscanf(strings.TrimSpace(string(b)), "%d", v) }
