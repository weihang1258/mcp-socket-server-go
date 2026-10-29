# socketstack（mcp-socket-server-go）

socket_server（靶机内部服务，Python v1.8.3）与 mcp_socket_server（中央 MCP 桥，Python v0.3.2）的 Go 合体复刻。单一二进制，双运行模式，systemd 双单元开关（agent 默认开、mcp 默认关）。

> 设计文档（唯一方案来源，经 5+3 轮对抗性审查）：`docs/superpowers/specs/2026-10-28-go-rewrite-design.md`

## 构建

```bash
go build -o socketstack ./cmd/socketstack/
# 版本注入
go build -ldflags "-X github.com/weihang1258/mcp-socket-server-go/internal/agent.Version=1.9.0" -o socketstack ./cmd/socketstack/
```

要求 Linux（agent 的 AF_PACKET 抓包/回放）；mcp 模式理论可跨平台。交叉编译：`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`（纯 Go，无 cgo）。

## 用法

```
socketstack                     # mcp stdio（本地 MCP 客户端）
socketstack mcp serve           # MCP Streamable HTTP :9010/mcp
socketstack agent               # agent（:9000 TCP + :9001 文件服务）
socketstack serve               # agent 别名（旧 Python unit ExecStart 兼容）
socketstack install [--with-mcp]    # 装 systemd 单元并启动（--with-mcp 加装 mcp 单元）
socketstack agent|mcp start|stop|status|enable|disable
socketstack agent autoupgrade on|off
```

## 部署布局（与 Python 版逐字一致，升级互操作）

- 二进制：`/usr/local/bin/socketstack`（Release 资产对外名 `socket_server`）
- 版本：`/opt/socket/versions/<v>/socket_server` + `current` 软链（dt20 升级/switch_to）
- 配置：`/etc/socketstack/config.yaml`（全部有默认值）+ `/opt/socket/config` 旧键兼容（autoupgrade/http_port/proxy，旧文件优先）
- 数据：`/var/lib/socketstack/`（mcp DB/下载目录；不迁移旧 Python DB）

## 测试

```bash
go test ./...        # 全量单测（协议逐帧/工具/池/锁/升级/mock 对拍）
go test -race ./...
```

## 状态

- agent 侧：全部 datatype（0-20/131/171-175/200）+ :9001 + 升级落地 ✅；AF_PACKET 抓包/回放真机验收 ✅
- mcp 侧：15 工具 + 双传输 ✅（默认端口 9010；改端口用配置 `mcp.bind.port`，经 systemd 启动时 env `MCP_BIND_PORT` 需写进 unit 的 `Environment=`）
- 真机验收 ✅：反向 oracle 38+13（Go/Python 双跑）、15 工具 e2e、三链升级闭环（Go↔Python 混部）、chromedp 重定向拨测、chromium 自动下载（npmmirror r1730241 → 536MB 落盘可执行）
- 平台：Linux 完整功能（AF_PACKET 仅 Linux）；darwin/windows 可编译，抓包/回放返回不可用错误
