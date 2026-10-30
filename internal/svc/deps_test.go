package svc

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// install 必须 best-effort 装上系统依赖（ethtool / net-tools）。
// Python 版 install.sh 有这一段，Go 版漏移植：抓包配单队列要 ethtool、
// 拍错要 net-tools，缺了要等第一次抓包报错才发现。
func TestSystemDepPackages(t *testing.T) {
	got := systemDepPackages()
	joined := strings.Join(got, " ")
	for _, want := range []string{"ethtool", "net-tools"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("系统依赖应含 %s，实际 %v", want, got)
		}
	}
}

// chromium 运行期库：boce 拨测要的是这一串。真机实测缺 libX11-xcb.so.1 时
// boce_run 直接失败，只在 .so 名上留线索，装包要人工反查包名。
func TestChromiumDepPackages(t *testing.T) {
	got := ChromiumDepPackages()
	if len(got) == 0 {
		t.Fatal("chromium 依赖包列表不能为空")
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{"nss", "gtk3", "gbm"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("chromium 依赖应含 %s，实际：%s", want, joined)
		}
	}
}

// 包管理器命令按发行版拼：yum/dnf → yum 包名，apt-get → deb 包名。
// 两者包名不同（nss/nspr 两处都叫这个，但 gtk3 vs libgtk-3-0）。
func TestInstallDepsCommand(t *testing.T) {
	yum := InstallDepsCommand("/usr/bin/yum", []string{"ethtool", "gtk3"})
	if !strings.HasPrefix(yum, "yum install -y ") || !strings.Contains(yum, "gtk3") {
		t.Fatalf("yum 命令不对: %q", yum)
	}
	apt := InstallDepsCommand("/usr/bin/apt-get", []string{"ethtool", "libgtk-3-0"})
	if !strings.HasPrefix(apt, "apt-get install -y ") || !strings.Contains(apt, "libgtk-3-0") {
		t.Fatalf("apt 命令不对: %q", apt)
	}
	// 都没有 → 空命令（调用方只告警不中断）
	if got := InstallDepsCommand("", []string{"x"}); got != "" {
		t.Fatalf("无包管理器应返回空，实际 %q", got)
	}
}

// 缺库诊断：把 ldd 输出里的 .so 名提炼出来，并给出可复制的装包命令。
// 现在只报 ".so: cannot open shared object file"，装包还要人工反查包名。
func TestMissingLibsFromLdd(t *testing.T) {
	// ldd 输出形如：\tlibX11-xcb.so.1 => not found
	out := `	linux-vdso.so.1 (0x00007fff)
	libX11-xcb.so.1 => not found
	libnss3.so => not found
	libc.so.6 => /lib64/libc.so.6 (0x00007f)
`
	got := MissingLibsFromLdd(out)
	if len(got) != 2 || got[0] != "libX11-xcb.so.1" || got[1] != "libnss3.so" {
		t.Fatalf("缺库解析不对: %v", got)
	}
	if got := MissingLibsFromLdd(""); len(got) != 0 {
		t.Fatalf("空输出应无缺库，实际 %v", got)
	}
}

// 侦察包管理器存在性（install 里用来决定跑哪套包名）。
func TestDetectPkgManager(t *testing.T) {
	prev := lookPathFn
	defer func() { lookPathFn = prev }()
	lookPathFn = func(name string) (string, error) {
		if name == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", exec.ErrNotFound
	}
	if got := DetectPkgManager(); got != "/usr/bin/apt-get" {
		t.Fatalf("want apt-get, got %q", got)
	}
	lookPathFn = func(string) (string, error) { return "", exec.ErrNotFound }
	if got := DetectPkgManager(); got != "" {
		t.Fatalf("都没有应为空, got %q", got)
	}
}

// 包管理器卡住时 install 不能永久挂住：必须有超时并 kill 整个进程组
// （sh -c 会产生子进程，只 kill sh 会留下孤儿继续占 dpkg 锁）。
func TestRunWithTimeoutKillsHungCommand(t *testing.T) {
	start := time.Now()
	_, err := runWithTimeout("sleep 30", 200*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("超时必须返回错误")
	}
	if !strings.Contains(err.Error(), "超时") {
		t.Fatalf("错误须说明超时，实际: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("应在超时后立刻返回，实际耗时 %v", elapsed)
	}
}

// 正常命令照常返回输出。
func TestRunWithTimeoutNormalExit(t *testing.T) {
	out, err := runWithTimeout("echo hello", 5*time.Second)
	if err != nil || strings.TrimSpace(out) != "hello" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

// 验收实测：dpkg 锁被别的 apt 进程占着时，apt-get 会一直等锁，install
// 白等一轮后以「警告 + 退出码 0」收场——自动化无法判断依赖到底装没装。
// apt 走 DPkg::Lock::Timeout=0：拿不到锁立刻失败，fail-fast。
func TestInstallDepsCommandAptFailsFastOnLock(t *testing.T) {
	apt := InstallDepsCommand("/usr/bin/apt-get", []string{"ethtool"})
	if !strings.Contains(apt, "DPkg::Lock::Timeout=0") {
		t.Fatalf("apt 必须设置 DPkg::Lock::Timeout=0 立即失败而非无限等锁: %q", apt)
	}
	// yum/dnf 没有等锁问题，不该被塞 apt 专有参数
	yum := InstallDepsCommand("/usr/bin/yum", []string{"ethtool"})
	if strings.Contains(yum, "DPkg::Lock::Timeout") {
		t.Fatalf("yum 命令不该带 apt 专有参数: %q", yum)
	}
}
