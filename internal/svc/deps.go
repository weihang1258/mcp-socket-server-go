// Package svc 系统依赖管理（install 期 best-effort 安装）。
//
// Python 版 install.sh 有 `yum install -y ethtool net-tools` 这一段，Go 版
// 最初漏移植：抓包配单队列要 ethtool、排错要 net-tools，缺了要等第一次抓包
// 才报错。chromium 那串运行期库也一样——只在下游 boce 首次拨测时现场装，
// 内网装不上就只留一句 .so 名。
package svc

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// lookPathFn 测试注入点。
var lookPathFn = exec.LookPath

// detectPkgManager 返回包管理器绝对路径（yum 优先，对齐 Python 版分支顺序）。
func DetectPkgManager() string {
	for _, name := range []string{"yum", "dnf", "apt-get"} {
		if p, err := lookPathFn(name); err == nil {
			return p
		}
	}
	return ""
}

// systemDepPackages install 期的基础系统依赖。
func systemDepPackages() []string { return []string{"ethtool", "net-tools"} }

// chromiumDepPackages chromium 运行期库（boce 重定向拨测要）。
// 与 boce.go 首次拨测时的现场安装列表同源，这里提前到 install 期。
func ChromiumDepPackages() []string {
	if p, _ := lookPathFn("yum"); p != "" {
		return []string{
			"libX11", "libXcomposite", "libXcursor", "libXdamage", "libXext", "libXi",
			"libXtst", "cups-libs", "libXScrnSaver", "libXrandr", "GConf2", "atk", "gtk3",
			"pango", "at-spi2-atk", "libwayland-client", "libwayland-cursor", "libwayland-egl",
			"alsa-lib", "nss", "nspr", "libgbm", "libxshmfence",
		}
	}
	if p, _ := lookPathFn("dnf"); p != "" {
		return []string{
			"libX11", "libXcomposite", "libXcursor", "libXdamage", "libXext", "libXi",
			"libXtst", "cups-libs", "libXScrnSaver", "libXrandr", "GConf2", "atk", "gtk3",
			"pango", "at-spi2-atk", "libwayland-client", "libwayland-cursor", "libwayland-egl",
			"alsa-lib", "nss", "nspr", "libgbm", "libxshmfence",
		}
	}
	// apt
	return []string{
		"libx11-6", "libxcomposite1", "libxcursor1", "libxdamage1", "libxext6", "libxi6",
		"libxtst6", "libcups2", "libxss1", "libxrandr2", "libgconf-2-4", "libatk1.0-0",
		"libgtk-3-0", "libpango-1.0-0", "libpangocairo-1.0-0", "libwayland-client0",
		"libwayland-cursor0", "libasound2", "libnss3", "libnspr4", "libgbm1", "libxshmfence1",
	}
}

// installDepsCommand 按包管理器拼安装命令；无包管理器返回空串。
func InstallDepsCommand(pm string, pkgs []string) string {
	if pm == "" || len(pkgs) == 0 {
		return ""
	}
	base := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(pm, "/"),
		"/usr/bin/"), "/bin/"), "/usr/sbin/")
	verb := "install"
	return base + " " + verb + " -y " + strings.Join(pkgs, " ")
}

// missingLibsFromLdd 从 ldd 输出提炼未找到的 .so 名。
// 行形如 "	libX11-xcb.so.1 => not found"。
func MissingLibsFromLdd(out string) []string {
	var missing []string
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "=> not found") {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 0 {
			missing = append(missing, f[0])
		}
	}
	return missing
}

// depsInstallTimeout 单次装包的超时。没有它，包管理器卡在等锁/等网络时
// `install` 会永久挂住（Python install.sh 没设超时，但它是脚本，中断即可；
// 这里是用户等了半天不知道在干什么的 CLI）。
var depsInstallTimeout = 10 * time.Minute

// InstallDeps best-effort 安装系统依赖；失败仅告警不中断（对齐 Python install.sh）。
// 返回失败包的告警文案列表（由调用方打印），永不返回 error。
func InstallDeps() []string {
	var warns []string
	pm := DetectPkgManager()
	if pm == "" {
		return []string{"未找到 yum/dnf/apt-get，跳过系统依赖安装（不影响核心功能）"}
	}
	for _, set := range [][]string{systemDepPackages(), ChromiumDepPackages()} {
		cmd := InstallDepsCommand(pm, set)
		if cmd == "" {
			continue
		}
		if out, err := runWithTimeout(cmd, depsInstallTimeout); err != nil {
			warns = append(warns, "系统依赖安装未全部成功（不影响核心功能，可手动执行）: "+
				cmd+"; 原因: "+firstLine(err.Error())+"; 输出: "+firstLine(out))
		}
	}
	return warns
}

// runWithTimeout 跑 shell 命令带超时（超时 → kill 整个进程组）。
func runWithTimeout(cmd string, d time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	c.WaitDelay = 5 * time.Second
	out, err := c.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("安装超时（>%s）", d)
	}
	return string(out), err
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.TrimSpace(s)
}
