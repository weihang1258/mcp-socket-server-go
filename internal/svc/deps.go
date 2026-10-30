// Package svc 浏览器拨测依赖的按需安装。
//
// v1.9.7 起 install 完全不碰包管理器：route/ifconfig/ethtool 已由内核接口
// 原生实现（internal/agent netnative.go），chromium 运行库只服务浏览器拨测，
// 改由 `deps install-browser` 显式安装（失败即非 0 退出，不再静默吞掉）。
package svc

import (
	"context"
	"errors"
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
//
// apt 额外带 DPkg::Lock::Timeout=0：dpkg 锁被别的进程占着时，apt-get 默认会
// 一直等锁。真机实测 install 就这么白等一整轮，最后只留一句警告而退出码仍是 0，
// 自动化看不出依赖到底装没装。设 0 让它立刻失败，至少能马上告警。
func InstallDepsCommand(pm string, pkgs []string) string {
	if pm == "" || len(pkgs) == 0 {
		return ""
	}
	base := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(pm, "/"),
		"/usr/bin/"), "/bin/"), "/usr/sbin/")
	verb := "install"
	extra := ""
	if base == "apt-get" {
		extra = " -o DPkg::Lock::Timeout=0"
	}
	return base + " " + verb + " -y" + extra + " " + strings.Join(pkgs, " ")
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

// depsRunner 注入点（测试替换；生产 = runWithTimeout）。
var depsRunner = runWithTimeout

// InstallBrowserDeps 显式安装浏览器拨测（boce_run 浏览器模式）所需的
// chromium 运行库。只在用户主动执行 `deps install-browser` 时调用——
// 默认 install 完全不碰包管理器（抓包/回放/命令执行都用不着这串库）。
// 失败必须返回 error（CLI 非 0 退出）：用户主动要求的事，失败不该被
// 静默吞掉。
func InstallBrowserDeps() error {
	pm := DetectPkgManager()
	if pm == "" {
		return errors.New("未找到 yum/dnf/apt-get，无法自动安装；请手动安装 chromium 运行库")
	}
	cmd := InstallDepsCommand(pm, ChromiumDepPackages())
	out, err := depsRunner(cmd, depsInstallTimeout)
	if err != nil {
		return fmt.Errorf("浏览器依赖安装失败（%s）\n命令: %s\n输出: %s", firstLine(err.Error()), cmd, firstLine(out))
	}
	return nil
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
