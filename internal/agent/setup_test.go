package agent

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// serve 启动必须接上文件日志：Python setup_environment() 第一行就是
// setup_logging()，运维靠 /var/log/socket_server.log 排障。Go 版缺了这个调用，
// 日志只进 journald，日志文件停在上一任 Python 进程的最后一行。
func TestSetupEnvironmentWiresFileLogging(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "socket_server.log")
	t.Setenv("SOCKET_SERVER_LOG", logPath)

	prevOut := log.Writer()
	prevFlags := log.Flags()
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	// 只跑日志接线那一步（SetupEnvironment 其余步骤有系统副作用）
	setupFileLogging()
	log.Printf("MARKER-文件日志接线")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("日志文件未创建: %v", err)
	}
	if !strings.Contains(string(data), "MARKER-文件日志接线") {
		t.Fatalf("日志未写入文件:\n%s", data)
	}
}

// SetupEnvironment 必须真的调用日志接线（对齐 Python setup_environment 第一行）。
// 上一条用例只测 setupFileLogging 本身，删掉 SetupEnvironment 里的调用它照样绿。
func TestSetupEnvironmentCallsLogging(t *testing.T) {
	prevFn, prevMach := setupLoggingFn, setupMachineEffects
	var called atomic.Int32
	setupLoggingFn = func(string) { called.Add(1) }
	setupMachineEffects = func() {} // 隔离 sysctl/java/防火墙等真实副作用
	t.Cleanup(func() { setupLoggingFn, setupMachineEffects = prevFn, prevMach })

	SetupEnvironment()
	if called.Load() != 1 {
		t.Fatalf("SetupEnvironment 须调用日志接线 1 次，实际 %d", called.Load())
	}
}
