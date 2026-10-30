# socketstack

靶机内部服务（socket_server）与中央 MCP 桥（mcp_socket_server）的 Go 合体复刻。**一个二进制，两种运行模式**：

| 模式 | 部署位置 | 监听 | systemd 单元 | 默认 |
|---|---|---|---|---|
| `agent` | 靶机（内网） | :9000 帧协议 / :9001 文件服务 | `socket_server.service` | 装 |
| `mcp` | 中央节点 | :9010 Streamable HTTP / stdio | `socketstack-mcp.service` | 不装 |

> 兼容 Python v1.8.3（agent）与 v0.3.2（mcp）的 wire 协议与部署布局，可原地替换、可回滚。

---

## 一键安装

**agent（靶机）** —— 需要 root。一个二进制，一条命令装完即启动：

```bash
# 默认走国内加速；能直连 GitHub 的机器把 MIRROR 置空
MIRROR=https://gh-proxy.com/
URL=https://github.com/weihang1258/mcp-socket-server-go/releases/latest/download/socket_server

curl -fsSL "${MIRROR}${URL}" -o /tmp/socket_server \
  && sudo install -m 0755 /tmp/socket_server /usr/local/bin/socketstack \
  && sudo socketstack install
```

`install` 会把二进制落进版本目录、建好软链、注册 systemd、**启动服务**。装完直接可用。

> 加速站可用 `https://gh-proxy.com/`（实测 15MB / ~4s）或 `https://ghfast.top/`，均返回与 Release 一致的 sha256。

验证（一条命令看全部）：

```bash
socketstack status
```

```
版本      : v1.9.3
agent 服务: active (socket_server.service)
mcp 服务  : active (socketstack-mcp.service)

路径
  入口 (CLI)   /usr/local/bin/socketstack -> /opt/socket/versions/current/socket_server
  当前版本目录 /opt/socket/versions/current/socket_server
  ...
日志
  agent  tail -f /var/log/socket_server.log
  mcp    journalctl -u socketstack-mcp -f
```

**mcp（中央节点）** —— 同样需要 root：

```bash
sudo install -m 0755 /tmp/socket_server /usr/local/bin/socketstack
sudo socketstack install --with-mcp
```

`install --with-mcp` 同一份二进制先装 agent 单元、再装 mcp 单元，**两个都启动**。

> 标准部署是**分机安装**：靶机只装 agent，中央只装 mcp。`--with-mcp` 是同机调试用。
> 从 Python 版原地升级：执行同样的 `install`，旧单元与路径会被复用（见「升级」）。

**卸载**（保留版本目录、配置与 MCP 数据库）：

```bash
sudo socketstack uninstall
```

---

## 使用

### agent 侧

装好即用，客户端用 Python 版 `socket_client` 或 MCP 桥连接 `:9000` 即可，协议不变。

```bash
socketstack status                            # 版本 / 服务状态 / 路径 / 日志命令
sudo socketstack agent start|stop|restart|disable
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
  proxy: ""                                      # 中央下载升级包用；空则回退 /opt/socket/config 的 proxy=
  upgrade_repo: weihang1258/mcp-socket-server-go # upgrade_run 从这里拉靶机包
  upgrade_mirror: ""                             # GitHub 前缀，如 https://gh-proxy.com/
  log_level: INFO
  default_timeout: 30
```

旧键兼容：`/opt/socket/config` 里的 `autoupgrade=` / `http_port=` / `proxy=` 会被 agent 实时读取；mcp 的 `proxy` 未配置时也回退到这里的 `proxy=`（与 Python 版互操作）。

### 中央推送升级（upgrade_run）的出网配置

`upgrade_run` 由中央节点下载靶机包再经 `:9001` 推送。中央节点出网受限时二选一：

```yaml
mcp:
  proxy: http://10.12.186.204:7897   # 走代理（查版 + 下载都可用）
  # 或者
  upgrade_mirror: https://gh-proxy.com/   # 走镜像（只能下载；查版仍需代理或显式指定 version）
```

都不配且直连不通时，`upgrade_run` 必须**显式给 version**，且仍需要能下到包。

### chromium 预取

默认关闭，与 Python 一致（首次用到浏览器模式时才现场下载，真机约 223s / 536MB）。

能访问 `registry.npmmirror.com` 的机器可设 `agent.chromium_prefetch: true`，启动时后台预取，首次 `boce_run` 就不必现场下载。**内网/离线靶机保持关闭**——开了会让每次重启白跑一次完整下载。

---

## 升级

**自动升级（默认开）**：中央节点推送 → dt20 落地 → 原子切换 `current` 软链 → 重启。靶机零外呼，不受本机网络影响。

**手动升级 / 覆盖修复**：下载新二进制后执行同样的安装命令即可，配置、数据、单元全部保留：

```bash
MIRROR=https://gh-proxy.com/
URL=https://github.com/weihang1258/mcp-socket-server-go/releases/latest/download/socket_server

curl -fsSL "${MIRROR}${URL}" -o /tmp/socket_server \
  && sudo install -m 0755 /tmp/socket_server /usr/local/bin/socketstack \
  && sudo socketstack install
```

同版本重跑也覆盖（二进制损坏时用它修复）。

**回滚**：`versions/<旧版本>/` 都还在，改 `current` 指回去再重启即可：

```bash
sudo ln -sfn /opt/socket/versions/1.9.1 /opt/socket/versions/current
sudo socketstack agent start   # 单元 active 时用 systemctl restart socket_server
```

**关掉自动升级**：`sudo socketstack agent autoupgrade off`（写 `/opt/socket/config`）。
注意它只是**闸门**：agent 不会自己轮询找新版本，只决定中央推过来时接不接受。

---

## 安装路径与日志

### 程序在哪

**全机只有一份二进制**，另外两个是指向它的软链：

```
/usr/local/bin/socketstack  ──┐   ← 敲命令用的入口（软链）
                              ↓
/opt/socket/versions/current  ──→ versions/1.9.3/socket_server   ← 真身，systemd 执行它
```

| 路径 | 内容 |
|---|---|
| `/opt/socket/versions/1.9.3/socket_server` | **唯一的二进制真身**（版本目录） |
| `/opt/socket/versions/current` | 指向当前版本目录的软链 —— 升级/回滚只切这个链接 |
| `/usr/local/bin/socketstack` | 指向 `current/socket_server` 的软链（PATH 入口，不在 PATH 加第二个文件） |

```bash
socketstack status                                  # 版本 + 服务状态 + 全部路径 + 日志命令
readlink -f /opt/socket/versions/current            # 当前版本目录
```

### 日志在哪

| 服务 | 日志位置 |
|---|---|
| **agent**（`socket_server.service`） | 文件 **`/var/log/socket_server.log`**（与 Python 版同一路径，追加写）；同时进 journald |
| **mcp**（`socketstack-mcp.service`） | **仅 journald**（`journalctl -u socketstack-mcp`），不写文件 |

```bash
sudo tail -f /var/log/socket_server.log        # agent 主日志
sudo journalctl -u socket_server -f            # agent（systemd 侧）
sudo journalctl -u socketstack-mcp -f          # mcp 全部日志
```

日志路径可用环境变量 `SOCKET_SERVER_LOG` 覆盖（写进 unit 的 `Environment=` 才生效）。

### 配置与数据

| 路径 | 内容 |
|---|---|
| `/opt/socket/config` | 旧键配置：`autoupgrade=` / `http_port=` / `proxy=`（**优先级高于新配置**） |
| `/etc/socketstack/config.yaml` | 新配置（全部可选，不存在也能跑） |
| `/var/lib/socketstack/` | mcp 数据库 `mcp.db`（+ `-wal`/`-shm`）与下载目录 |

### systemd 单元

| 单元 | 文件 | ExecStart |
|---|---|---|
| `socket_server.service` | `/etc/systemd/system/socket_server.service` | `/opt/socket/versions/current/socket_server serve` |
| `socketstack-mcp.service` | `/etc/systemd/system/socketstack-mcp.service` | `/usr/local/bin/socketstack mcp serve` |

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
- **抓包 stop 的 drain 有 2s 上限**：Python 版靠「1 秒收不到新帧」判断队列排空，在有持续流量的网卡上永不成立（`capture_stop` 30s 超时、实例持锁导致 `cmd_exec` 全被拒）。Go 版改为最多 drain 2s 后强制收尾——stop 瞬间已在缓冲里的帧仍会落盘，但**极端突发流量下可能丢弃 stop 之后才到达的少量帧**。
- **`status` 会跑一次 `ldd`**：仅当 chromium 已下载时探测缺库，未下载则跳过。

---

## 状态

- agent：全部 datatype（0-20 / 131 / 171-175 / 200）+ :9001 + 升级落地；AF_PACKET 抓包/回放真机验收通过
- mcp：15 个工具 + stdio/HTTP 双传输
- 真机验收：反向 oracle 51 项（Go/Python 双跑）、15 工具 e2e、三链升级闭环（Go↔Python 混部）、chromedp 拨测、chromium 自动下载

设计文档（唯一方案来源）：`docs/superpowers/specs/2026-10-28-go-rewrite-design.md`
