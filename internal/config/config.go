// Package config 合体 YAML 配置 + env 白名单覆盖（设计文档 §7）。
//
// 全部键有默认值：不写配置文件即可启动。env 覆盖仅白名单键：
// MCP_BIND_HOST/PORT、MCP_LOG_LEVEL（config loader 语义）、
// MCP_DEFAULT_TIMEOUT（mcpbridge socket_client 语义）、SOCKET_SERVER_LOG（agent 日志）。
// /opt/socket/config 的 autoupgrade=/http_port=/proxy= 三键由 agent 侧实时读取，
// 不进本结构（升级互操作，见设计 §7）。
package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Agent struct {
	TCPPort int    `yaml:"tcp_port"`
	LogFile string `yaml:"log_file"`
	// ChromiumPrefetch agent 启动时后台预取默认 chromium。默认 **false**：
	// 内网靶机连不上 npmmirror，无条件预取会让每次重启白跑一次 536MB 下载，
	// 而 Python 是「用到才触发」（handlers.py:263）。能上外网的部署可开启，
	// 以消除「首次 boce_run 被客户端 timeout+10 判死」。
	ChromiumPrefetch bool `yaml:"chromium_prefetch"`
}

type Bind struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type Pool struct {
	MaxConnPerTarget     int `yaml:"max_conn_per_target"`
	IdleTimeout          int `yaml:"idle_timeout"`
	BorrowTimeout        int `yaml:"borrow_timeout"`
	MaxGlobalConcurrency int `yaml:"max_global_concurrency"`
}

type MCP struct {
	Bind        Bind   `yaml:"bind"`
	DBPath      string `yaml:"db_path"`
	DownloadDir string `yaml:"download_dir"`
	Proxy       string `yaml:"proxy"`
	// UpgradeRepo upgrade_run 从这里下载靶机升级包（owner/repo）。
	// 默认 mcp-socket-server-go：Go 版二进制发在这个仓库；Python 仓库
	// （socket_server）最新只到 1.8.3，写死它会让 1.9.x 必然 404。
	UpgradeRepo string `yaml:"upgrade_repo"`
	// UpgradeMirror 下载基址前缀（如 https://gh-proxy.com/），空=直连 GitHub。
	// 内网机器靠它 + Proxy 两个手段之一出网。
	UpgradeMirror      string   `yaml:"upgrade_mirror"`
	LogLevel           string   `yaml:"log_level"`
	DefaultTimeout     int      `yaml:"default_timeout"`
	BehindProxy        bool     `yaml:"behind_proxy"`
	Pool               Pool     `yaml:"pool"`
	AuditRetentionDays int      `yaml:"audit_retention_days"`
	CmdExecWhitelist   []string `yaml:"cmd_exec_whitelist"`
}

type Config struct {
	Agent Agent `yaml:"agent"`
	MCP   MCP   `yaml:"mcp"`
}

func defaults() Config {
	return Config{
		Agent: Agent{
			TCPPort: 9000,
			LogFile: "/var/log/socket_server.log",
		},
		MCP: MCP{
			Bind:               Bind{Host: "0.0.0.0", Port: 9010},
			DBPath:             "/var/lib/socketstack/mcp.db",
			DownloadDir:        "/var/lib/socketstack/downloads",
			Proxy:              "",
			UpgradeRepo:        "weihang1258/mcp-socket-server-go",
			UpgradeMirror:      "",
			LogLevel:           "INFO",
			DefaultTimeout:     30,
			BehindProxy:        false,
			Pool:               Pool{MaxConnPerTarget: 5, IdleTimeout: 600, BorrowTimeout: 10, MaxGlobalConcurrency: 50},
			AuditRetentionDays: 90,
			CmdExecWhitelist:   []string{},
		},
	}
}

// misplacedKeys已知叶子键 → 所属段（顶层写错时 YAML 静默丢弃，不报错）。
// 真机中央曾因此 mirror/proxy 全部未生效，下载裸连 GitHub 失败（五轮验收）；
// 六轮验收补 agent 段（顶层 tcp_port → 仍监听 9000 零提示）。固定顺序遍历，
// 输出稳定。
var misplacedKeys = []struct{ key, section string }{
	{"tcp_port", "agent"}, {"log_file", "agent"}, {"chromium_prefetch", "agent"},
	{"proxy", "mcp"}, {"upgrade_repo", "mcp"}, {"upgrade_mirror", "mcp"},
	{"download_dir", "mcp"}, {"db_path", "mcp"}, {"log_level", "mcp"},
	{"default_timeout", "mcp"}, {"behind_proxy", "mcp"}, {"audit_retention_days", "mcp"},
	{"cmd_exec_whitelist", "mcp"}, {"bind", "mcp"}, {"pool", "mcp"},
}

// MisplacedKeys 检出「子键写在顶层」的配置错误，返回可直接打印的告警。
// 未知顶层键中只挑这些已知键名——通用未知键不告警（存量配置可能带自定义键，
// 全量严格模式会把无关机器炸掉）。畸形 YAML 返回 nil（与 Load 同语义）。
func MisplacedKeys(data []byte) []string {
	var top map[string]any
	if err := yaml.Unmarshal(data, &top); err != nil || top == nil {
		return nil
	}
	var warns []string
	for _, k := range misplacedKeys {
		if _, ok := top[k.key]; ok {
			warns = append(warns, fmt.Sprintf("配置键 %q 写在了顶层，不会生效——请移到 %s: 之下（如:\n  %s:\n    %s: ...）",
				k.key, k.section, k.section, k.key))
		}
	}
	return warns
}

// Load 读取 YAML（可省略/不存在则全默认），再应用 env 白名单覆盖。
func Load(path string) Config {
	cfg := defaults()
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			// yaml.Unmarshal 到局部再逐字段赋值，保持未覆盖键为默认（避免嵌套结构整体替换丢默认值）
			var over Config
			if err := yaml.Unmarshal(data, &over); err == nil {
				if over.Agent.TCPPort != 0 {
					cfg.Agent.TCPPort = over.Agent.TCPPort
				}
				if over.Agent.LogFile != "" {
					cfg.Agent.LogFile = over.Agent.LogFile
				}
				if over.Agent.ChromiumPrefetch {
					cfg.Agent.ChromiumPrefetch = true
				}
				if over.MCP.Bind.Host != "" {
					cfg.MCP.Bind.Host = over.MCP.Bind.Host
				}
				if over.MCP.Bind.Port != 0 {
					cfg.MCP.Bind.Port = over.MCP.Bind.Port
				}
				if over.MCP.DBPath != "" {
					cfg.MCP.DBPath = over.MCP.DBPath
				}
				if over.MCP.DownloadDir != "" {
					cfg.MCP.DownloadDir = over.MCP.DownloadDir
				}
				if over.MCP.Proxy != "" {
					cfg.MCP.Proxy = over.MCP.Proxy
				}
				if over.MCP.UpgradeRepo != "" {
					cfg.MCP.UpgradeRepo = over.MCP.UpgradeRepo
				}
				if over.MCP.UpgradeMirror != "" {
					cfg.MCP.UpgradeMirror = over.MCP.UpgradeMirror
				}
				if over.MCP.LogLevel != "" {
					cfg.MCP.LogLevel = over.MCP.LogLevel
				}
				if over.MCP.DefaultTimeout != 0 {
					cfg.MCP.DefaultTimeout = over.MCP.DefaultTimeout
				}
				if over.MCP.BehindProxy {
					cfg.MCP.BehindProxy = true
				}
				if over.MCP.Pool.MaxConnPerTarget != 0 {
					cfg.MCP.Pool.MaxConnPerTarget = over.MCP.Pool.MaxConnPerTarget
				}
				if over.MCP.Pool.IdleTimeout != 0 {
					cfg.MCP.Pool.IdleTimeout = over.MCP.Pool.IdleTimeout
				}
				if over.MCP.Pool.BorrowTimeout != 0 {
					cfg.MCP.Pool.BorrowTimeout = over.MCP.Pool.BorrowTimeout
				}
				if over.MCP.Pool.MaxGlobalConcurrency != 0 {
					cfg.MCP.Pool.MaxGlobalConcurrency = over.MCP.Pool.MaxGlobalConcurrency
				}
				if over.MCP.AuditRetentionDays != 0 {
					cfg.MCP.AuditRetentionDays = over.MCP.AuditRetentionDays
				}
				if len(over.MCP.CmdExecWhitelist) > 0 {
					cfg.MCP.CmdExecWhitelist = over.MCP.CmdExecWhitelist
				}
			}
		}
	}
	// env 白名单
	if v := os.Getenv("MCP_BIND_HOST"); v != "" {
		cfg.MCP.Bind.Host = v
	}
	if v := os.Getenv("MCP_BIND_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MCP.Bind.Port = n
		}
	}
	if v := os.Getenv("MCP_LOG_LEVEL"); v != "" {
		cfg.MCP.LogLevel = v
	}
	if v := os.Getenv("MCP_DEFAULT_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MCP.DefaultTimeout = n
		}
	}
	if v := os.Getenv("SOCKET_SERVER_LOG"); v != "" {
		cfg.Agent.LogFile = v
	}
	if v := os.Getenv("MCP_UPGRADE_REPO"); v != "" {
		cfg.MCP.UpgradeRepo = v
	}
	if v := os.Getenv("MCP_UPGRADE_MIRROR"); v != "" {
		cfg.MCP.UpgradeMirror = v
	}
	return cfg
}
