# socketstack

靶机内部服务（socket_server）与中央 MCP 桥（mcp_socket_server）的 Go 合体复刻。**一个二进制，两种运行模式**：

| 模式 | 部署位置 | 监听 | systemd 单元 | 默认 |
|---|---|---|---|---|
| `agent` | 靶机（内网） | :9000 帧协议 / :9001 文件服务 | `socket_server.service` | 装 |
| `mcp` | 中央节点 | :9010 Streamable HTTP / stdio | `socketstack-mcp.service` | 不装 |

> 兼容 Python v1.8.3（agent）与 v0.3.2（mcp）的 wire 协议与部署布局，可原地替换、可回滚。

---

## 一键安装

**agent（靶机）** —— 需要 root。整段粘贴即可：

```bash
# 默认走国内加速；能直连 GitHub 的机器把 MIRROR 置空
MIRROR=https://gh-proxy.com/
URL=https://github.com/weihang1258/mcp-socket-server-go/releases/latest/download/socket_server

curl -fsSL "${MIRROR}${URL}" -o /tmp/socket_server \
  && chmod +x /tmp/socket_server \
  && sudo /tmp/socket_server install \
  && sudo socketstack agent start
```

`install` 装单元并设开机自启（与 Python 版语义一致，不自动 start），最后一条命令拉起服务。

> 加速站可用 `https://gh-proxy.com/`（实测 15MB / 6.6s）或 `https://ghfast.top/`（5.6s），均返回与 Release 完全一致的 sha256。

验证：

```bash
systemctl status socket_server          # active (running)
ss -ltn | grep -E ':9000|:9001'         # 两个端口都在监听
```

**mcp（中央节点）** —— 同样需要 root：

```bash
MIRROR=https://gh-proxy.com/
URL=https://github.com/weihang1258/mcp-socket-server-go/releases/latest/download/socket_server

curl -fsSL "${MIRROR}${URL}" -o /tmp/socket_server \
  && chmod +x /tmp/socket_server \
  && sudo /tmp/socket_server install --with-mcp \
  && sudo socketstack mcp start
```

`install --with-mcp` 先把 agent 装好（靶机侧），再装 mcp 单元并设自启；最后一条 `mcp start` 才真正拉起服务。

> 标准部署是**分机安装**：靶机只装 agent，中央只装 mcp。`--with-mcp` 是同机调试用。
> 从 Python 版原地升级：直接执行上面的 install，旧单元与路径会被复用（见「升级」）。

**卸载**（保留版本目录、配置与 MCP 数据库）：

```bash
sudo socketstack uninstall
```

---

## 使用

### agent 侧

装好即用，客户端用 Python 版 `socket_client` 或 MCP 桥连接 `:9000` 即可，协议不变。

```bash
sudo socketstack agent start|stop|status|disable
sudo socketstack agent autoupgrade on|off     # 自动升级开关（写 /opt/socket/config）
```

### mcp 侧

MCP 客户端连接 `http://<中央节点>:9010/mcp`。本地调试可用 stdio：

```bash
socketstack            # 无参数 = mcp stdio
socketstack mcp serve  # 显式 HTTP 模式
sudo socketstack mcp start|stop|status
```

改端口：编辑 `/etc/socketstack/config.yaml` 的 `mcp.bind.port`。注意经 systemd 启动时，环境变量 `MCP_BIND_PORT` 需写进 unit 的 `Environment=` 才生效。

---

## 配置

`/etc/socketstack/config.yaml` —— **全部键可省略**，不建文件也能跑：

```yaml
agent:
  tcp_port: 9000
  log_file: /var/log/socket_server.log
  chromium_prefetch: false    # true = 启动时后台预取 chromium（仅能上外网的机器开）

mcp:
  bind: {host: 0.0.0.0, port: 9010}
  db_path: /var/lib/socketstack/mcp.db
  download_dir: /var/lib/socketstack/downloads
  proxy: ""
  log_level: INFO
  default_timeout: 30
```

旧键兼容：`/opt/socket/config` 里的 `autoupgrade=` / `http_port=` / `proxy=` 会被 agent 实时读取，且**优先级高于新配置**（与 Python 版互操作）。

### chromium 预取

默认关闭，与 Python 一致（首次用到浏览器模式时才现场下载，真机约 223s / 536MB）。

能访问 `registry.npmmirror.com` 的机器可设 `agent.chromium_prefetch: true`，启动时后台预取，首次 `boce_run` 就不必现场下载。**内网/离线靶机保持关闭**——开了会让每次重启白跑一次完整下载。

---

## 升级

自动升级（默认开）由 agent 自己完成：中央节点推送 → dt20 落地 → 切换 `current` 软链。

手动升级三选一：

```bash
# 1. 覆盖安装（最简单，保留配置与数据）
sudo /tmp/socket_server install

# 2. 单元操作
sudo socketstack agent stop && sudo /tmp/socket_server install

# 3. 关掉自动升级
sudo socketstack agent autoupgrade off
```

升级在版本目录 `current` 软链层面切换，失败可回滚到 `versions/<旧版本>/`。

---

## 部署布局

| 路径 | 用途 |
|---|---|
| `/usr/local/bin/socketstack` | 二进制 |
| `/opt/socket/versions/<v>/socket_server` + `current` 软链 | 版本（dt20 升级切换点） |
| `/opt/socket/config` | 旧键配置（autoupgrade/http_port/proxy） |
| `/etc/socketstack/config.yaml` | 新配置（全部可选） |
| `/var/lib/socketstack/` | mcp 数据库与下载目录 |

---

## 从源码构建

```bash
go build -ldflags "-X github.com/weihang1258/mcp-socket-server-go/internal/agent.Version=1.9.0" \
  -o socketstack ./cmd/socketstack/
```

纯 Go，无 cgo。交叉编译：`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`。

- **Linux**：完整功能（AF_PACKET 抓包/回放仅 Linux）。
- **darwin / windows**：可编译，抓包/回放返回不可用错误。

---

## 测试

```bash
go test ./...          # 全量单测
go test -race ./...    # 竞态检测
```

反向对拍脚本（用 Python 版作 oracle 打 Go agent）：`scripts/oracle/`。

---

## 已知运行特性

- **单连接串行**：每条 TCP 连接按 read→do()→write 循环处理（与 Python ThreadingTCPServer 同构）。同一连接上的后续请求会排在前一个请求完成之后。
- **首次 chromium 下载会占住该连接**：默认与 Python 一致，客户端超时 `timeout+10`（默认 130s）小于首次下载耗时（约 223s），该连接会被判超时；日志会打印手动下载方法。开启 `chromium_prefetch` 可避免。

---

## 状态

- agent：全部 datatype（0-20 / 131 / 171-175 / 200）+ :9001 + 升级落地；AF_PACKET 抓包/回放真机验收通过
- mcp：15 个工具 + stdio/HTTP 双传输
- 真机验收：反向 oracle 51 项（Go/Python 双跑）、15 工具 e2e、三链升级闭环（Go↔Python 混部）、chromedp 拨测、chromium 自动下载

设计文档（唯一方案来源）：`docs/superpowers/specs/2026-10-28-go-rewrite-design.md`
