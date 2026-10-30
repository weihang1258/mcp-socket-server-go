package svc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P1-4：日志无轮转。实测 364MB（大头是 Python 时代的回放日志，Go 版只写了 81 行），
// 但不清历史 + 不加轮转，将来异常场景仍会无限增长。
// 保留策略（用户指定）：只留最近 7 天，超期归档直接删。
func TestLogrotateContent(t *testing.T) {
	c := LogrotateContent()
	for _, want := range []string{
		"/var/log/socket_server.log",
		"maxsize 60M",
		"daily",
		"maxage 7", // 超过 7 天的归档文件直接删除
		"rotate 7",
		"copytruncate", // agent 持有 fd 持续写，不能靠 rename
		"missingok",
		"notifempty",
		"compress",
	} {
		if !strings.Contains(c, want) {
			t.Fatalf("logrotate 配置缺 %q:\n%s", want, c)
		}
	}
}

// 日志路径必须与 agent 实际使用的路径一致（SOCKET_SERVER_LOG 可覆盖，
// 但默认值要对得上，否则配了等于没配）。
func TestLogrotatePathMatchesAgentDefault(t *testing.T) {
	if !strings.Contains(LogrotateContent(), AgentLogPath) {
		t.Fatalf("logrotate 配置须使用 agent 默认日志路径 %s", AgentLogPath)
	}
}

// 写配置到磁盘；父目录不存在时创建。
func TestInstallLogrotateWritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logrotate.d", "socketstack")
	if err := writeLogrotateConfig(path); err != nil {
		t.Fatalf("writeLogrotateConfig: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "/var/log/socket_server.log") {
		t.Fatalf("写入内容不对:\n%s", data)
	}
}

// 重复安装要幂等（内容相同不重写、不报错）。
func TestInstallLogrotateIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "socketstack")
	if err := writeLogrotateConfig(path); err != nil {
		t.Fatal(err)
	}
	fi1, _ := os.Stat(path)
	if err := writeLogrotateConfig(path); err != nil {
		t.Fatalf("第二次写入应成功: %v", err)
	}
	fi2, _ := os.Stat(path)
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Fatal("内容未变不该重写文件")
	}
}
