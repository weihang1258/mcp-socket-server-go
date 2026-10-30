package agent

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
)

// SetupEnvironment serve 启动环境初始化（__init__.py setup_environment 移植）：
// 日志（显式 > SOCKET_SERVER_LOG > /var/log/socket_server.log；目录缺失跳过文件 handler）→
// rmem/wmem_max≥32MB → java PATH+JAVA_HOME（找到 java 才写，硬编码不校验存在）→
// 防火墙关闭命令组逐条。PLAYWRIGHT_BROWSERS_PATH 为 PyInstaller 专有，删除（§12#9）。

// logFileFor 日志路径优先级：显式 > env > 默认。
func logFileFor(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("SOCKET_SERVER_LOG"); p != "" {
		return p
	}
	return "/var/log/socket_server.log"
}

// SetupLogging 初始化文件日志（目录缺失跳过文件 handler 不崩）。
func SetupLogging(explicit string) {
	path := logFileFor(explicit)
	dir := filepathDir(path)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		log.Printf("日志目录 %s 不存在，仅输出到 stderr", dir)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	log.SetFlags(log.LstdFlags)
}

// setupFileLogging 把日志接到文件（对齐 Python setup_environment() 的
// 第一步 setup_logging()）。运维排障看的是 /var/log/socket_server.log；
// 不接这一步，Go 版日志只进 journald，文件停在上一任进程的最后一行。
// 独立成函数便于单测——SetupEnvironment 其余步骤有系统副作用。
func setupFileLogging() { setupLoggingFn("") }

// setupLoggingFn 注入点：测试用它确认 SetupEnvironment 真的接了文件日志。
var setupLoggingFn = SetupLogging

// SetupEnvironment 完整环境初始化（testMode 跳过系统副作用）。
func SetupEnvironment() {
	setupFileLogging()
	log.Printf("version:%s", Version)
	setupMachineEffects()
}

// setupMachineEffects 注入点（测试隔离真实系统副作用）。
var setupMachineEffects = func() { setupMachineEffectsImpl() }

// setupMachineEffectsImpl sysctl/java/防火墙等系统副作用。
func setupMachineEffectsImpl() {
	// net.core rmem/wmem_max ≥ 32MB（root 即时生效；失败仅 warn）
	for _, name := range []string{"/proc/sys/net/core/rmem_max", "/proc/sys/net/core/wmem_max"} {
		cur, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		var v int
		fmt.Sscanf(strings.TrimSpace(string(cur)), "%d", &v)
		if v >= 32*1024*1024 {
			continue
		}
		if err := os.WriteFile(name, []byte(fmt.Sprint(32*1024*1024)), 0o644); err != nil {
			log.Printf("调整 %s 失败（不影响服务，建议手动 sysctl -w）: %v", name, err)
		} else {
			log.Printf("已将 %s 调到 %d（降低抓包/发送缓冲丢包）", name, 32*1024*1024)
		}
	}
	// java：找到才前插 PATH 并硬编码 JAVA_HOME（不校验该路径存在）
	if out, err := exec.Command("/bin/sh", "-c", "dirname `find /usr/local/ -type f -name java|head -n 1`").Output(); err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			os.Setenv("PATH", p+":"+os.Getenv("PATH"))
			os.Setenv("JAVA_HOME", "/usr/local/jdk1.8.0_202")
		}
	}
	// 防火墙关闭命令组（逐条保留；root 下执行）
	cmds := []string{
		"systemctl stop firewalld 2>/dev/null || true",
		"systemctl disable firewalld 2>/dev/null || true",
		"iptables -F 2>/dev/null || true",
		"iptables -X 2>/dev/null || true",
		"iptables -Z 2>/dev/null || true",
		"ufw disable 2>/dev/null || true",
		"sed -i 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config 2>/dev/null || true",
		"setenforce 0 2>/dev/null || true",
	}
	for _, c := range cmds {
		log.Printf("%s", c)
		exec.Command("/bin/sh", "-c", c).Run()
	}
	log.Printf("env PATH=%s", os.Getenv("PATH"))
}

func filepathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "."
}
