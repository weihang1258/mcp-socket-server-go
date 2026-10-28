# socketstack-go 合体重构方案（设计文档 v2）

日期：2026-10-28（v2，取代同日 v1）
状态：待评审

本文档是 **socket_server**（Python，v1.8.3，靶机侧内部服务）与 **mcp_socket_server**（Python，v0.3.2，中央 MCP 桥）两项目合并为单一 Go 项目的唯一方案来源。所有行为、协议细节均以两仓库源码逐文件通读推导（socket_server 14 文件 / mcp_socket_server 12 文件 + test_e2e.py 帧格式权威源），不凭记忆。

## 0. 合体架构与开关模型

```
┌────────────────── 一个二进制 socketstack ──────────────────┐
│                                                            │
│  agent 模式(内部服务,默认开)      mcp 模式(对外桥,默认关)   │
│  ├─ :9000 TCP 帧协议             ├─ 15 个 MCP 工具         │
│  ├─ :9001 HTTP 文件服务          ├─ 连接池/锁/注册表/审计   │
│  ├─ datatype 处理器(0~200)       ├─ 升级编排(推包/轮询)    │
│  └─ supervisor/升级落地          └─ stdio + Streamable HTTP│
└────────────────────────────────────────────────────────────┘
        靶机侧部署 agent 单元          中央节点部署 mcp 单元
```

- **同一个二进制，两种运行模式**（`socketstack agent` / `socketstack mcp`），不是单进程同时跑两个服务：agent 跑在靶机、mcp 跑在中央节点，物理上分开部署，合的是**代码仓库与构建产物**。
- **开关**：
  - 安装时：`socketstack install` 默认只装并启用 `socketstack-agent.service`；`socketstack install --with-mcp` 才同时装 `socketstack-mcp.service`。
  - 运行时：`socketstack mcp enable|disable|start|stop|status` 与 `socketstack agent enable|disable|start|stop|status` 分别管理两个 systemd 单元（即开关的"启动、关闭等动作"）。
  - 配置兜底：`config.yaml` 里 `mcp.enabled: false` 默认值；`serve` 类子命令读它决定行为，但真正的启停动作以 systemd 单元为权威。
- 一份代码、一份 Release 产物、一个版本号（从 1.9.0 起，接续 socket_server 1.8.x 序列；dt14 上报该版本，中央侧升级比对 `>= 1.8.0` 天然兼容）。

## 1. 目标与非目标

**目标**
1. **agent 侧全量对齐 socket_server v1.8.3**：TCP :9000 帧协议、:9001 HTTP 文件服务、全部在用 datatype、AF_PACKET 抓包、pcap 回放、拨测、监听、升级落地、systemd 自管理。
2. **mcp 侧全量对齐 mcp_socket_server v0.3.2**：15 个 MCP 工具、批量部分失败语义、连接池、状态锁、审计、标签解析、升级编排、stdio + Streamable HTTP 双传输。
3. 协议零漂移：agent 侧对外帧格式与 Python 版字节级一致；mcp 侧客户端与 Python socket_client.py 逐字节一致。双向对拍验证。
4. 单二进制交叉编译（纯 Go，无 cgo）。

**非目标**
- 不迁移 Python 版 SQLite 数据、不兼容旧 config.yaml 键名（新 YAML 结构）。
- 不做 MCP 鉴权（对齐现状：内网信任 + DNS rebinding 保护关闭）。
- datatype 16（python_cmd，`eval` 任意 Python）**不复刻**——Go 无 Python 解释器，且该接口是任意代码执行的裸洞，Python 版也从未被 MCP 暴露。收到 dt16 回 `{"error":"not supported"}`。（见 §12 差异清单）
- datatype 121/122/123 不复刻（Python 版已整段注释弃用）。
- 不删 Python 两仓库（保留为参考实现与对拍 oracle）。

## 2. 权威协议契约（:9000 TCP）

帧格式（`test_e2e.py send_request`，长度/datatype 均为 **native int32**，即 x86 小端）：

```
发送: [4B len(i, native)][4B datatype(i, native)][payload]
  len = 4 + len(payload)
上传 step23 例外: [4B len(i)][原始内容]（无 datatype，bin_recv_flag=True 时服务端跳过类型解析）
```

服务端接收循环（protocol.py handle() 语义，agent 侧必须逐条复刻）：
- 首包 <4B 断连；按 4B len 读满 payload；**收到字节数 > len 时丢弃当前帧继续**（不回错误）。
- 收满一帧后：非 bin 模式拆 4B datatype + data；bin 模式（22 步后）datatype 恒置 23。
- 持久连接：handle() 循环，连接可复用；ConnectionReset 退出。
- 响应 sendall 失败 → sleep 3s 重发一次，再失败放弃。

**文件传输状态机（21→22→23→24 必须同一连接，服务端连接级状态）**
- 21: `{"filepath":...,"gzip":bool}` → 存连接级 filepath/gzip → 回 `b"21 ok"`。
- 22: `<Q 8B 小端 压缩后内容长度>` → 置 bin_recv_flag、bufsize 放大 → 回 `b"22 ok"`。
- 23: 裸帧内容累积；==length → 回 `b"23 ok"`、退出 bin 模式；>length → RuntimeError 断连。
- 24: 空 payload 触发写盘（gzip 则解压；解压结果 `b"^$"` 特例当空文件）→ 回 `b"24 ok"`。
- 下载 type 3：payload `{"gzip":bool}`，走连接级 filepath，回 `[8B <Q len][content]`。

响应五类（mcp 侧客户端解析，按 datatype）：

| 响应形态 | datatype | 说明 |
|---|---|---|
| 裸 JSON 文本（无前缀，读至超时） | 0/5/6/7/8/14/171 | 首 chunk 后 0.5s 短探 |
| `[4B len i][gzip JSON]` | 1/16 | |
| `[8B len <Q][content]` | 3（可选 gzip）/174（必 gzip） | 下载/监听数据流；174 错误时是裸 `{"error":...}`（首字节 `{` 探测分支） |
| `[4B len i][JSON]` | 131/200 | |
| inline 短文本 | 21/22/23/24 步间 | `b"NN ok"`；15/172/173/175 为 `b"ok"`，172/173/175 错误时 1.7.1+ 为 `{"error":...}` JSON |

## 3. agent 侧 datatype 全量清单（对齐 handlers.py do()）

| dt | 功能 | 实现要点（源码定位） |
|---|---|---|
| 0 | pcap 回放 | 必填 pcaps/uplink_iface/downlink_iface 校验；PcapReplayer 全参数透传；回 stats JSON（裸文本）。error → `{"status":"error","message":...}` |
| 1 | 命令执行 | `exec_cmd_subprocess`：shell 模式 root 剥 `sudo ` 前缀（带选项不剥）；args/timeout 用途；回 `[4B i][gzip JSON {code,stdout,stderr}]`；wait=False 不回 |
| 3 | 文件下载 | 连接级 filepath；可选 gzip；`[8B <Q][content]` |
| 4 | routeinfo | `route -n` 解析（2 行头 + 数据行 zip）；失败抛错断连 |
| 5 | 抓包开始 | tcpdump_start：AF_PACKET 子进程→Go goroutine；同 path 先停旧；失败回 `{"res":false,"error":原因}` |
| 6 | 抓包停止 | 四态 `stopped/exitcode/pcap_complete/note/error`；幂等（未在抓 stopped=false+note） |
| 7/8 | isfile/isdir | payload `{"file"/"dir": path}` → `{"res":bool}` |
| 9 | mkdir | `os.makedirs` → `{"res":null}` |
| 10 | 改 MTU | ifconfig 解析（新旧两种格式），不等则设置后 sleep 5s；需 ifconfig 存在 |
| 11 | 取字节数 | `{"path":...}` → `{"res":size}` |
| 14 | 版本 | `json.dumps(VERSION)`（带引号 JSON 字符串） |
| 15 | 解压 zip | `unzip [-o] [-P passwd] file [-d outdir]`，list args 防注入；回 `b"ok"` |
| 16 | python_cmd | **不复刻**，回 `{"error":"datatype 16 not supported in Go version"}` |
| 18 | ensure_command | which 检查 → `{"res":bool}` |
| 19 | 版本详情 | 纯本地：version/repo/release_notes/latest/has_upgrade |
| 20 | 升级落地 | 版本正则 + 64 位 hex sha 校验；autoupgrade=off 拒；升级锁互斥；active_clients>1 且非 force 拒；落盘成功回 `{"ok":true,"version":...}`，后台 0.3s 后 switch_to（原子软链+重启） |
| 131 | 拨测 | chromium 自检（不存在自动下载 npmmirror + 依赖 yum/apt 自动装，两级失败回 error）；封堵=纯 HTTP 并发；重定向=chromium headless 跳转判定；回 `[4B i][JSON]` |
| 171 | 监听启动 | 全局单实例 ss；host=None 双栈；幂等（已活跳过）；回 `{"pid":[...]}`（ss 解析） |
| 172/173 | 监听清数据/保存 | 未启动回 `b"error"`；成功 `b"ok"`；173 payload `{"file":...}` |
| 174 | 监听取流 | 未启动回 `{"error":...}`；否则 gzip(全量 data) `[8B <Q][content]` |
| 175 | 监听停止 | 3×0.5s 轮询确认停止；失败回 `{"error":"停止监听失败，端口仍被占用"}` |
| 200 | pcap 五元组流 | 纯 struct 解析（VLAN/IPv4/IPv6；TCP/UDP/SCTP/ICMP）；方向判定：首包默认 → SYN/SYN+ACK 修正 → HTTP 方法/响应行修正，一次锁定；回 `[4B i][JSON]` |

**抓包（capture.py → Go）**，最难模块，逐点复刻：
- `syscall.Socket(AF_PACKET, SOCK_RAW, 0)` proto=0 创建，全部 setsockopt 就位后最后 `bind(eth, ETH_P_ALL)`——杜绝 bind→BPF 之间未过滤窗口。
- 时间戳四级降级：SO_TIMESTAMPING(HW|SW|RAW) → SO_TIMESTAMPING(RX_SW) → SO_TIMESTAMPNS → 用户态 monotonic；cmsg `SCM_TIMESTAMPING`（ts[0]HW/ts[1]SW）解码，ts[0]==0 退化 ts[1] 并 warn 一次。
- VLAN 还原：`PACKET_AUXDATA` cmsg，tp_status VLAN_VALID/TPID_VALID 位判定，offset 12 插回 4B 标签（对齐 libpcap）。
- SO_RCVBUF 32MB + getsockopt 验证截断告警；promisc 失败仅 warn。
- BPF 过滤（extended 非空）：Go 编译 tcpdump 表达式——**用 `golang.org/x/net/bpf` + 自带小型编译器不现实**，改为 exec `tcpdump -ddd <expr>` 取指令序列注入 SO_ATTACH_FILTER（兼容无 tcpdump 时报启动失败，与 Python scapy attach_filter 失败即抛错语义一致）。
- 停止语义：置 stop → **drain 完队列剩余帧**再退出；join 超时不关文件返回 False；tpacket_stats 在 close 前读；落盘后按时间戳稳定重排（支持 4 种 magic，原子 replace）。
- pcap 写：纳秒 magic 0xA1B23C4D、snaplen 65535、DLT_EN10MB。
- 单队列配置：ethtool -L / sysfs msi_irqs / /proc/interrupts 三路找 IRQ、绑非 0 空闲 CPU（/proc/stat 满载排除）、禁 RPS/RFS——**Go 进程内直接做**（Python 放子进程是为 GIL，Go 无此问题，见 §12）。

**回放（replayer.py → Go）**：五元组建流（hint/SYN/反向流推断方向）、对称换向改写（force_*）、IPv4↔IPv6 互转（含重算 IP/TCP/UDP/ICMP 校验和；SCTP CRC32C 同 Python 不动）、VLAN 增改、AF_PACKET SOCK_RAW 发送（socket 缓存复用）、mbps 每包+全局两级限速、pcap 缓存写（微秒 magic）。

**拨测（boce.py → Go）**：封堵 = `net/http` + goroutine 池（UA 伪装、allow_redirects=false、200 计成功）；重定向 = `chromedp` 驱动外部 chromium（headless 参数同 Python 12 个 args；framenavigated/request 计数判定；browser 崩溃重启重试一次）；chromium 自动下载（npmmirror API 查最新 revision、proxy 走 /opt/socket/config 的 proxy=）。

**:9001 HTTP 文件服务（http_file.py → Go）**：Go `net/http` 原生流式——GET `/files?path=` 1MB 分块 + Content-Length 锁死；POST multipart 流式（`multipart.Reader` 边收边写 `.part`，path 先到直写 + 原子 rename，file 先到落临时文件后搬运）；realpath 归一化；boundary ≤256 校验；畸形 body 400 JSON。http_port 读 /opt/socket/config（0=关闭，缺省 9001）。

**服务化（supervisor/upgrader/autoupgrade → Go）**：unit 自愈（ExecStart 指向 current 软链）、/opt/socket/versions 布局、current 原子软链切换、finalize_pushed_version（staging sha256 校验→chmod 755→os.replace→清 staging）、/opt/socket/config autoupgrade 开关读写。**全部路径与 Python 版逐字相同**（升级互操作的关键：中央新版可升旧靶机，旧中央可升 Go 靶机）。

**serve 环境初始化（__init__.setup_environment → Go）**：日志（路径优先级 显式>SOCKET_SERVER_LOG>/var/log/socket_server.log）、rmem/wmem_max≥32MB、java PATH、防火墙关闭命令组（逐条保留）。

## 4. mcp 侧 15 个 MCP 工具（对齐 server.py，v1 文档 §3 表全量保留）

| # | 工具 | datatype | 锁类 | 危险 | 关键行为 |
|---|---|---|---|---|---|
| 1 | list_targets | - | - | RO | 空 + note(未初始化) |
| 2 | add_target | - | - | 写 | TCP 探活 3s 拒绝，force 跳过；剥 IPv6 方括号 |
| 3 | remove_target | - | - | 写 | 活跃锁/活跃监听时拒绝 |
| 4 | version | 14 | NONE | RO | 返回字符串版本 |
| 5 | file_transfer | - | - | RO | 纯本地：生成 :9001 curl 命令；host 三形态解析；IPv6 加方括号 |
| 6 | isfile | 7 | NONE | RO | payload `{"file": path}` |
| 7 | isdir | 8 | NONE | RO | payload `{"dir": path}` |
| 8 | pcap_flow_extract | 200 | NONE | RO | len-prefix JSON；>1000 条截断 + truncated |
| 9 | cmd_exec | 1 | SHELL | DANGER | 白名单前缀；stdout >64KB 截断；wait=false 返回 note；timeout=wait?60:15 |
| 10 | capture_start | 5 | CAPTURE(path) | 写 | 失败 `_error` 通道；res:false 无 error → B23 泛化；**锁成功保留到 stop 释放** |
| 11 | capture_stop | 6 | CAPTURE | 写 | 四态判定；failed_details 保留结构化；独立释放逻辑 |
| 12 | boce_run | 131 | BROWSER | 写 | timeout≥10；socket_timeout=timeout+10；inner=max(3,timeout-10)；error 抛错 |
| 13 | replay_run | 0 | REPLAY | 写 | status=error 抛错 |
| 14 | socket_listen | 171-175 | SYSTEM | 写 | start 后 dt14 探版本≥1.7.1 登记 liveness；fetch 超 max_bytes 落盘 + base64 截断 |
| 15 | upgrade_run | 20 | SYSTEM | DANGER | 版本校验→查最新(可选)→下载+sha256→:9001 推包→dt20→轮询 dt14(180s/3s)→failed 含未确认 |

通用批量语义（`_run_batch`）：`{ok: N, failed: [{target, reason}], results: [{target, ...data}]}`；单 target 失败不影响他台；锁冲突 fail-fast；`{"_error":...}`/`False` 判 failed；`None` → note（B18）。池参数 max_conn_per_target=5 / idle 600s / borrow 10s / 全局 50；复用连接同步 socket_timeout（N8 修复语义）。

## 5. 模块结构（Go）

```
cmd/socketstack/          # 入口: agent|mcp|install|uninstall|status|version
internal/frame/           # 共享帧编解码: [4B i len][4B i dt][payload] + 21-24 状态机
internal/agent/           # ===== socket_server 复刻 =====
  server.go               # :9000 双栈 TCP(allow_reuse,daemon_threads→goroutine), 客户端计数
  handlers.go             # do() 全 datatype 分发(§3 表)
  netexec.go              # exec_cmd_subprocess(root 剥 sudo, env 清理)/routeinfo/mtu/unzip/ensure_command
  capture.go              # AF_PACKET 抓包(时间戳降级/VLAN 还原/BPF/停止 drain/重排)
  singlequeue.go          # ethtool 单队列 + IRQ 绑定 + RPS/RFS
  replayer.go             # pcap 回放(流表/改写/校验和/限速)
  boce_http.go            # 封堵拨测(net/http)
  boce_browser.go         # 重定向拨测(chromedp) + chromium 自动下载
  listen.go               # 171-175 监听(goroutine, /tmp/socketbin 落盘)
  pcapflow.go             # dt200 五元组提取
  httpfile.go             # :9001 流式文件服务
  upgrade.go              # dt20 落地 + current 软链 + autoupgrade 配置
  setup.go                # serve 环境初始化(防火墙/rmem/java/日志)
internal/svc/             # systemd 两单元的 install/enable/disable/start/stop/status
internal/mcpbridge/       # ===== mcp_socket_server 复刻 =====
  protocol.go             # :9000 客户端(五类响应解析, 对齐 socket_client.py)
  pool.go                 # 每靶机连接池 + 批量调度
  locks.go                # per-target 多模式锁 fail-fast
  registry.go             # SQLite 注册表 + @tag 解析
  audit.go                # SQLite 审计
  upgrades.go             # 查版/下载/推包/每日兜底/退避
  tools.go                # 15 工具注册 + _run_batch
  transport.go            # stdio + Streamable HTTP
internal/config/          # 合体 YAML + env 覆盖
```

`internal/frame` 双向共用：agent 的接收循环与 mcpbridge 的客户端编帧共用同一常量与 21-24 状态机定义，防两侧漂移。

## 6. 技术选型（已验证/待验证标注）

- **Go 1.21 + auto-toolchain**（本机 1.21.13，go.mod 声明 1.25 经 goproxy.cn 实测可用）。
- **MCP SDK**：官方 `github.com/modelcontextprotocol/go-sdk v1.8.0`（已实测构建成功），stdio + Streamable HTTP 单依赖树。
- **YAML** `gopkg.in/yaml.v3`；**SQLite** `modernc.org/sqlite`（纯 Go 无 cgo）。
- **`golang.org/x/sys/unix`**：AF_PACKET socket、cmsg（SO_TIMESTAMPING/PACKET_AUXDATA）解析、PACKET_ADD_MEMBERSHIP。已确认 unix 包有 Socket/Recvmsg/ParseSocketControlMessage。
- **`github.com/chromedp/chromedp`**：重定向拨测。纯 Go CDP 客户端，无 cgo。
- BPF 过滤：不引依赖，exec `tcpdump -ddd` 编译（靶机本就有 tcpdump 概率低——失败即启动失败，语义对齐 Python scapy 失败抛错）。
- 回放发送 / 抓包：x/sys/unix 原生，无 libpcap 依赖。
- 校验和/pcap 解析：手写（对齐 Python struct 逻辑，百行级）。

## 7. 配置（合体，全部有默认值 = 零配置可启动）

```yaml
# agent 段(靶机侧; /etc/socketstack/config.yaml, 亦兼容读 /opt/socket/config 的
# autoupgrade=/http_port=/proxy= 三键——升级互操作必需)
agent:
  tcp_port: 9000
  http_port: 9001          # 0=关闭
  log_file: /var/log/socket_server.log   # env SOCKET_SERVER_LOG 覆盖
# mcp 段(中央侧)
mcp:
  enabled: false           # 默认关;真正的启停以 systemd 单元为权威
  bind: {host: 0.0.0.0, port: 8080}
  db_path: ./mcp_socket_server.db
  download_dir: ./downloads
  proxy: ""                # GitHub 下载代理
  log_level: INFO
  default_timeout: 30
  pool: {max_conn_per_target: 5, idle_timeout: 600, borrow_timeout: 10}
  audit_retention_days: 90
  cmd_exec_whitelist: []
```

env 覆盖：`MCP_BIND_HOST/PORT`、`MCP_LOG_LEVEL`、`MCP_DEFAULT_TIMEOUT`、`SOCKET_SERVER_LOG`。

版本号：**1.9.0** 起（二进制内嵌；dt14 / dt19 / initialize serverInfo 同源）。

## 8. 服务化与安装

```
socketstack agent          # 前台跑 :9000+:9001（调试用）
socketstack mcp            # stdio 模式（本地 MCP 客户端接入）
socketstack mcp serve      # Streamable HTTP :8080/mcp
socketstack install [--with-mcp]     # 装 agent 单元并启动; --with-mcp 同时装 mcp 单元
socketstack agent start|stop|status|enable|disable
socketstack mcp  start|stop|status|enable|disable    # = 开关动作
socketstack uninstall
```

- 两个 systemd 单元共享一个二进制（复制到 /usr/local/bin/socketstack）：
  - `socketstack-agent.service`：`ExecStart=/usr/local/bin/socketstack agent`，Restart=always/5s（对齐 Python）。
  - `socketstack-mcp.service`：`ExecStart=/usr/local/bin/socketstack mcp serve`，Restart=on-failure。
- agent 侧同时保留 Python 版布局语义：部署到 /opt/socket/versions/<v>/ + current 软链 + unit 自愈，使**旧中央（Python mcp_socket_server）可以升级 Go 靶机、新中央可以升级旧 Python 靶机**（二进制文件名仍为 `socket_server`，dt20 落地路径不变）。
- GitHub Release 附带 `.sha256`，供 upgrade_run 下载校验。

## 9. 验证策略（三层 + 双向对拍）

1. **协议单测**：`internal/frame` net.Pipe 逐帧断言（五类响应、21-24 握手、type 3、174 首字节探测、超长帧丢弃、持久连接复用）。
2. **mock 对拍（mcp 侧）**：~百行 mock socket_server（Go 写，收帧回 canned 响应、录制原始字节）。同一用例跑 Python socket_client 与 Go 客户端，逐字节比对。进 CI。
3. **反向对拍（agent 侧）**：用 **Python 版 test_e2e.py / mcp_socket_server 的 mock_socket_server.py 作客户端 oracle** 打 Go agent：15 工具 + 全 datatype + 上传下载握手逐项过。这是 agent 复刻正确性的最强证据——Python 客户端不改一行。
4. **单模块深测**：capture（注入虚拟帧验 VLAN 还原/时间戳解码/停止 drain）、replayer（构造 pcap 验校验和与方向判定）、pcapflow（与 Python 输出逐字段 diff）。
5. **真实靶机 e2e**：全 15 工具 + agent 全 datatype 对真实环境跑一轮人工验收（危险工具单独确认）。

## 10. 实施顺序（TDD，每步提交）

```
frame(共享编解码+21-24 状态机) → config/svc
→ agent 只读组(14/7/8/9/11/18/19/4/200 + :9001 httpfile)
→ agent 文件传输(3/21-24) → agent 命令(1/15/10)
→ agent listen(171-175) → agent boce(131, 先封堵后重定向)
→ agent capture(5/6) → agent replayer(0) → agent 升级(20/upgrader/supervisor)
→ mcpbridge protocol(+mock 对拍) → pool/locks/registry/audit
→ mcpbridge tools(只读→写) → upgrades → transport(stdio/HTTP)
→ 合体 CLI/服务化/双单元 → 反向对拍全量 → 真实 e2e → tag v1.9.0
```

agent 侧先行的原因：mcp 侧的对拍 oracle 需要 Go agent 就位后可用「Go mcp 客户端 ↔ Go agent」闭环自测。

## 11. 风险与对策

| 风险 | 对策 |
|---|---|
| 协议 drift（最大风险） | §9 双向对拍进 CI；两客户端（Go/Python）共用 frame 包常量 |
| AF_PACKET cmsg 细节（SCM_TIMESTAMPING/auxdata ABI） | 单元测试用真实环回抓包验证；对拍 Python 抓包结果 diff pcap |
| chromedp 与外部 chromium 版本兼容 | 锁 chromedp 版本；chromium 自动下载同 Python 路径（npmmirror 同源） |
| tcpdump 不存在的靶机 BPF 编译失败 | 语义对齐 Python（失败即启动失败带原因）；文档注明装 tcpdump 或不用 filter |
| 升级互操作（Go↔Python 混部） | 路径/文件名/unit 布局逐字对齐 §8；e2e 混部验收 |
| modernc SQLite 性能 | 写入量极低（注册+审计），无感知 |

## 12. 与 Python 版的有意差异清单（评审重点）

| # | 差异 | 理由 |
|---|---|---|
| 1 | dt16 python_cmd 不实现 | Go 无解释器；原接口即 `eval()` 裸洞，MCP 从未暴露 |
| 2 | 抓包/监听从子进程改进程内 goroutine | Python 子进程是为 GIL 隔离（boce worker 抢 GIL 丢包根因）；Go 无 GIL，goroutine 即隔离。**协议行为不变**（dt5/6 四态、dt171-175 应答逐字节一致） |
| 3 | boce 重定向由 pyppeteer 改 chromedp | 同为外部 chromium 的 CDP 客户端，判定逻辑（jumped_urls/request_count）逐条对齐 |
| 4 | BPF 编译由 scapy 改 `tcpdump -ddd` exec | 无纯 Go tcpdump 表达式编译器；失败语义对齐 |
| 5 | exec_cmd_subprocess 的 PyInstaller env 清理（_MEI/_PYI）删除 | Go 版无 PyInstaller |
| 6 | dt19 release_notes 从打包时生成改为内嵌编译信息 | `go build -ldflags` 注入，行为等价 |
| 7 | 一仓一码一版本号（1.9.0），替代 1.8.x/0.3.2 双线 | 合体后无意义维持两线 |
