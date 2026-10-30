// 日志轮转（P1-4）。Python 版与 Go 版都没有轮转，真机日志涨到 364MB。
//
// 历史归因：那 364MB 里 2,157,560 / 2,158,148 行是 Python 时代写的（回放
// 开始/完成各 91 万行 + 发送失败 7.6 万行），Go 版只写了 81 行——Go 的回放
// 模块只在出错时打日志。所以这里加轮转是防将来，不是治现在的量。
//
// copytruncate 而非 create：agent 由 systemd 常驻并长期持有该 fd，rename
// 后它仍写旧 inode，必须就地截断。
//
// 已知取舍：copytruncate 在「拷贝完成到截断生效」之间写入的行会丢。agent 是
// 重日志源，这个窗口里丢几行并非不可能。彻底解决要 agent 支持 SIGUSR1 重开
// 日志后改 create + postrotate，那要改 agent 侧，暂不做。
package svc

import (
	"os"
	"path/filepath"
	"strings"
)

// AgentLogPath agent 默认日志路径（与 internal/agent 的默认值一致）。
// 单独定义是为了避免 svc → agent 的包依赖（agent 已依赖 svc）。
const AgentLogPath = "/var/log/socket_server.log"

// LogrotateConfigPath logrotate 配置落点。
const LogrotateConfigPath = "/etc/logrotate.d/socketstack"

// LogrotateContent 生成 logrotate 配置。
func LogrotateContent() string {
	return strings.Join([]string{
		AgentLogPath + " {",
		"    size 60M",
		"    rotate 5",
		"    copytruncate",
		"    missingok",
		"    notifempty",
		"    compress",
		"    delaycompress",
		"}",
		"",
	}, "\n")
}

// WriteLogrotate 安装日志轮转配置（内容未变不重写）。
func WriteLogrotate() error { return writeLogrotateConfig(LogrotateConfigPath) }

func writeLogrotateConfig(path string) error {
	content := LogrotateContent()
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}
