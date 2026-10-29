// Package config 合体 YAML 配置 + env 白名单覆盖（设计文档 §7）。
//
// 全部键有默认值：不写配置文件即可启动。env 覆盖仅白名单键：
// MCP_BIND_HOST/PORT、MCP_LOG_LEVEL（config loader 语义）、
// MCP_DEFAULT_TIMEOUT（mcpbridge socket_client 语义）、SOCKET_SERVER_LOG（agent 日志）。
// /opt/socket/config 的 autoupgrade=/http_port=/proxy= 三键由 agent 侧实时读取，
// 不进本结构（升级互操作，见设计 §7）。
package config

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Agent struct {
	TCPPort int    `yaml:"tcp_port"`
	LogFile string `yaml:"log_file"`
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
	Bind               Bind     `yaml:"bind"`
	DBPath             string   `yaml:"db_path"`
	DownloadDir        string   `yaml:"download_dir"`
	Proxy              string   `yaml:"proxy"`
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
			LogLevel:           "INFO",
			DefaultTimeout:     30,
			BehindProxy:        false,
			Pool:               Pool{MaxConnPerTarget: 5, IdleTimeout: 600, BorrowTimeout: 10, MaxGlobalConcurrency: 50},
			AuditRetentionDays: 90,
			CmdExecWhitelist:   []string{},
		},
	}
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
	return cfg
}
