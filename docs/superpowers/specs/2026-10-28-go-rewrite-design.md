# mcp-socket-server-go 重构方案（设计文档）

日期：2026-10-28
状态：待评审
本文档是 Python 版 [mcp_socket_server](https://github.com/weihang1258/mcp_socket_server)（v0.3.2，2075 行）Go 重写的唯一方案来源。所有工具行为、协议细节以 Python 源码与 socket_server 仓库源码为权威推导，不凭记忆。

## 1. 目标与非目标

**目标**
1. 功能全量对齐 Python 版：**15 个 MCP 工具**（含 `file_transfer` 指引工具）、批量部分失败语义、连接池、状态锁、审计、标签解析、升级编排、stdio + Streamable HTTP 双传输。
2. 安装启动极简：单二进制，零配置可启动（全部配置有默认值，YAML 可选），提供 `install`/`start`/`stop`/`status` 服务子命令。
3. 协议零漂移：TCP 帧与 Python 客户端字节级一致，用 mock socket_server 自动对拍验证。

**非目标**
- 不迁移 Python 版 SQLite 数据（新库，切换时重新 `add_target`）。
- 不兼容 Python 版 config.yaml 键名（新 YAML 结构）。
- 不做鉴权（Python 版也仅留 TODO，对齐现状：内网信任 + DNS rebinding 保护关闭）。
- 不删 Python 版（保留为参考实现，Go 验收通过后的退役是独立决策）。

## 2. 权威协议契约（来自 /home/weihang/socket_server）

帧格式（`test_e2e.py send_request`，长度/datatype 均为 **native int32**，即 x86 小端）：

```
发送: [4B len(i, native)][4B datatype(i, native)][payload]
  len = 4 + len(payload)
上传 step23 例外: [4B len(i)][原始内容]（无 datatype，bin_recv_flag=True 时服务端跳过类型解析）
```

响应按 datatype 分五类（`test_e2e.py` + Python `socket_client.py`）：

| 响应形态 | datatype | 说明 |
|---|---|---|
| 裸 JSON 文本（无前缀，读至超时） | 0/5/6/7/8/14/171 | `_recv_until_timeout`：读到首 chunk 后 0.5s 短探 |
| `[4B len i][gzip JSON]` | 1/16 | |
| `[8B len <Q][content]` | 3（可选 gzip）/174（必 gzip） | 下载/监听数据流 |
| `[4B len i][JSON]` | 131/200 | |
| inline 短文本 ack（`b"21 ok"` 等） | 21/22/23/24 步间 | `b"ok"`/`b"error"`/`{"error":...}` |
| `b"ok"` | 15/172/173/175 | 172/173/175 错误时 1.7.1+ 为 `{"error":...}` JSON |

**特殊协议（易踩坑，必须有专项测试）**
- **上传四步握手 21→22→23→24，必须同一 TCP 连接**：21 payload `{"filepath":..., "gzip":bool}` → 22 payload `<Q 原始内容长度>`（8 字节小端，gzip 压缩后的长度）→ 23 裸帧发内容 → 24 空触发写盘。每步等 `b"NN ok"`。
- **下载 type 3** 路径走协议层状态 `kwargs["filepath"]`（21 步设置，同连接），payload `{"gzip":bool}`，响应 `[8B <Q][content]`。
- **121/122/123 已弃用**，不实现。
- 持久连接：服务端 handle() 循环，连接可复用。

## 3. MCP 工具清单（15 个，逐项对齐 server.py）

| # | 工具 | datatype | 锁类 | 危险 | 关键行为 |
|---|---|---|---|---|---|
| 1 | list_targets | - | - | RO | 空 + note(未初始化) |
| 2 | add_target | - | - | 写 | TCP 探活 3s 拒绝，force 跳过；剥 IPv6 方括号 |
| 3 | remove_target | - | - | 写 | 活跃锁/活跃监听时拒绝 |
| 4 | version | 14 | NONE | RO | 返回字符串版本 |
| 5 | file_transfer | - | - | RO | 纯本地：生成 :9001 curl 上传/下载命令；host 解析三形态（裸IP/裸IPv6/[v6]:port）；IPv6 加方括号 |
| 6 | isfile | 7 | NONE | RO | payload `{"file": path}` |
| 7 | isdir | 8 | NONE | RO | payload `{"dir": path}` |
| 8 | pcap_flow_extract | 200 | NONE | RO | len-prefix JSON；>1000 条截断 + truncated 标记 |
| 9 | cmd_exec | 1 | SHELL | DANGER | 白名单前缀匹配；stdout >64KB 截断；wait=false 返回 note；timeout=wait?60:15 |
| 10 | capture_start | 5 | CAPTURE(path) | 写 | 失败 `_error` 通道；res:false 无 error → B23 泛化文案；**锁成功时保留到 stop 释放** |
| 11 | capture_stop | 6 | CAPTURE | 写 | 四态判定；pcap_complete=false → failed+warning；failed_details 保留结构化；无锁竞争下的独立释放逻辑 |
| 12 | boce_run | 131 | BROWSER | 写 | timeout≥10 校验；socket_timeout=timeout+10；inner=max(3,timeout-10)；error → 抛错判失败 |
| 13 | replay_run | 0 | REPLAY | 写 | 失败 status=error → 抛错 |
| 14 | socket_listen | 171-175 | SYSTEM | 写 | start 后 dt14 探版本≥1.7.1 登记 liveness；stop 清除；fetch 超 max_bytes 落盘 `/home/tmp/listen_<ts>.log` + base64 截断返回；save 需 file |
| 15 | upgrade_run | 20 | SYSTEM | DANGER | 版本校验→查最新(可选)→中央下载+sha256→:9001 推包→dt20→轮询 dt14 确认(180s/3s)→failed 含未确认 target |

通用批量语义（`_run_batch`）：`{ok: N, failed: [{target, reason}], results: [{target, ...data}]}`；单 target 失败不影响他台；锁冲突 fail-fast；fn 返回 `{"_error":...}` 或 `False` 都判 failed；None → note（B18）。

## 4. 模块结构（Go）

```
cmd/mcp-socket-server-go/  # 子命令: run(stdio默认)/serve/install/start/stop/status
internal/protocol/         # TCP 客户端: 帧/五类响应/上传握手/下载 (对应 socket_client.py)
internal/pool/             # 每靶机连接池 + 批量调度 (对应 pool.py)
internal/locks/            # per-target 多模式锁 fail-fast (对应 locks.py)
internal/registry/         # 靶机注册表 SQLite + @tag 解析 (对应 registry.py)
internal/audit/            # 审计 SQLite (对应 audit.py)
internal/upgrades/         # 查版/下载/推包/轮询 (对应 upgrades.py)
internal/config/           # YAML 配置 + 默认值 + env 覆盖 (对应 config.py)
internal/tools/            # 15 个 MCP 工具注册 (对应 server.py)
internal/mcpserver/        # stdio + Streamable HTTP 传输
internal/svc/              # systemd install/uninstall (服务化,Python 版没有的增量)
```

## 5. 技术选型（已验证）

- **Go 1.21 + 自动工具链**：本机 go 1.21.13，`go 1.21` 声明下 go.mod 写 `go 1.25` 即自动下载 1.25 工具链构建（已实测通过 goproxy.cn）。
- **MCP SDK：官方 `github.com/modelcontextprotocol/go-sdk v1.8.0`**（已实测构建成功：`mcp.NewServer(&mcp.Implementation{Name,Version}, *mcp.ServerOptions)`）。支持 stdio + Streamable HTTP，单依赖树满足双传输。
- **YAML：`gopkg.in/yaml.v3`**；**SQLite：`modernc.org/sqlite`**（纯 Go 无 cgo，交叉编译单二进制的关键）。
- 其余全用标准库（TCP/goroutine/gzip/json/sha256/HTTP multipart 推包）。

## 6. 配置（新结构，全部有默认值 = 零配置可启动）

```yaml
# 全部可省略；不写此文件即用默认值启动
bind: {host: 0.0.0.0, port: 8080}     # Streamable HTTP
db_path: ./mcp_socket_server.db       # SQLite(注册表+审计同库,WAL)
download_dir: ./downloads
proxy: ""                             # GitHub 下载代理,留空直连
log_level: INFO
default_timeout: 30
pool: {max_conn_per_target: 5, idle_timeout: 600, borrow_timeout: 10}
audit_retention_days: 90
cmd_exec_whitelist: []
```
env 覆盖：`MCP_BIND_HOST` / `MCP_BIND_PORT` / `MCP_LOG_LEVEL` / `MCP_DEFAULT_TIMEOUT`（对齐 Python 版语义）。

版本号：从 **0.4.0** 起（接续 Python 0.3.2 序列）。

## 7. 服务化与安装（新增验收要求）

```
mcp-socket-server-go              # 无参数 = stdio 模式（MCP 客户端本地接入）
mcp-socket-server-go serve        # Streamable HTTP :8080/mcp（可 --config 覆盖）
mcp-socket-server-go install      # 安装 systemd 单元并启动（二进制复制到 /usr/local/bin）
mcp-socket-server-go start|stop|status|uninstall
```
- systemd 单元：`Restart=on-failure`，环境变量走单元文件 `Environment=`。
- deploy 脚本：`curl -L ... | sh` 一条命令装好（GitHub Release 提供单二进制）。

## 8. 验证策略（三层）

1. **协议单测**：`internal/protocol` 用 `net.Pipe`/本地 mock listener 喂字节，逐帧断言（含五类响应、21-24 握手、type 3 下载、174 首字节探测分支）。
2. **mock 对拍**：一个 ~百行 mock socket_server（收帧、回 canned 响应、录制原始字节）。同一用例分别跑 Python 客户端和 Go 客户端，**逐字节比对请求帧、比对响应解析结果**。对拍脚本进 CI。dtype 覆盖：0/1/3/5/6/7/8/14/20/131/171-175/200 + 上传握手。
3. **真实靶机 e2e**：全 15 工具对真实 socket_server 跑一轮人工验收（危险工具单独确认）。

## 9. 实施顺序（每层先测试后实现，TDD）

```
protocol(含mock) → config/registry/audit(SQLite) → pool → locks
→ tools(只读组) → tools(写组) → upgrades → 传输(stdio/HTTP) → 服务化 → e2e 验收
```

每步提交到本仓库；全部通过后 tag v0.4.0。

## 10. 风险与对策

| 风险 | 对策 |
|---|---|
| 协议 drift（最大风险） | §8 mock 对拍 + 逐字节 CI；socket_server 协议演进时同步两版客户端 |
| SDK Go 1.25 要求 vs 本机 1.21 | 已验证 auto-toolchain 经 goproxy.cn 可用；构建产物仍单二进制 |
| modernc SQLite 性能弱于 cgo | 本场景写入量极低（注册+审计），无感知；纯 Go 换交叉编译能力，值 |
| 升级轮询 180s 窗口内服务重启 | 逻辑原样复刻（短连接 dt14 轮询，不复用垂死连接） |
