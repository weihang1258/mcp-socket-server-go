# socketstack-go 合体重构方案（设计文档 v2.1）

日期：2026-10-28（v2.1，经 5 维度并行审查修订；取代 v2）
状态：待评审

本文档是 **socket_server**（Python，v1.8.3，靶机侧内部服务）与 **mcp_socket_server**（Python，v0.3.2，中央 MCP 桥）两项目合并为单一 Go 项目的唯一方案来源。所有行为、协议细节均以两仓库源码逐文件通读推导，并经 5 个独立审查维度（协议保真度 / agent 深层模块 / MCP 层 / 架构与 Go 可行性 / 有意差异与风险）交叉核验。

**版本基线警示（审查实锤）**：socket_server 仓库 commit `f13b65d` 将 dt5/dt6/131/171/172/173 的接口行为**整体回退到 v1.7.0 原样**（仅保留 175）。本文档一切 wire 契约以**回退后的当前源码**为权威；mcp 客户端 socket_client.py 中"1.7.1+ 四态 / 1.7.2+ error 通道"的解析分支对本服务端是**死代码**，仅作兼容保留。

## 0. 合体架构与开关模型

```
┌────────────────── 一个二进制 socketstack ──────────────────┐
│  agent 模式(内部服务,默认开)      mcp 模式(对外桥,默认关)   │
│  ├─ :9000 TCP 帧协议             ├─ 15 个 MCP 工具         │
│  ├─ :9001 HTTP 文件服务          ├─ 连接池/锁/注册表/审计   │
│  ├─ datatype 处理器(0~200)       ├─ 升级编排(推包/轮询)    │
│  └─ supervisor/升级落地          └─ stdio + Streamable HTTP│
└────────────────────────────────────────────────────────────┘
        靶机侧部署 agent 单元          中央节点部署 mcp 单元
```

- **同一个二进制，两种运行模式**，物理分开部署（agent 在靶机、mcp 在中央），合的是代码仓库与构建产物。
- **开关权威只有一个：systemd 单元**（审查修订：删除 v2 的 `mcp.enabled` 配置键——三种控制面互相矛盾）：
  - `socketstack install` 默认只装并启用 `socketstack-agent.service`；
  - `socketstack install --with-mcp` 额外安装 `socketstack-mcp.service`（仅同机调试/特殊拓扑用，标准部署仍分机安装）；
  - `socketstack agent|mcp enable|disable|start|stop|status` 分别管理两单元 = 开关的"启动、关闭等动作"。
- **子命令职责切分（不读任何 enabled 开关）**：`socketstack`（无参数）= stdio MCP 客户端本地接入；`socketstack mcp serve` = Streamable HTTP（systemd ExecStart 唯一入口）；`socketstack agent` = 前台跑 :9000+:9001（systemd ExecStart 入口，见 §8 升级兼容布局）。
- 版本语义分离（审查修订）：**dt14/dt19 上报的靶机版本**与 **MCP initialize serverInfo 的桥版本**是两个东西。发行包统一版本号 1.9.0 起，但 serverInfo.version 单独走桥版本序列 0.4.0（不冒用靶机版本）。

## 1. 目标与非目标

**目标**
1. **agent 侧全量对齐 socket_server v1.8.3 当前源码**（含 f13b65d 回退后的 wire 行为）。
2. **mcp 侧全量对齐 mcp_socket_server v0.3.2**：15 个 MCP 工具（schema/annotations/默认值以 server.py:262-786 为逐行契约）、批量部分失败语义、连接池、状态锁、审计、标签解析、升级编排、stdio + Streamable HTTP。
3. 协议零漂移：agent 对外帧格式与 Python 版字节级一致；mcp 客户端与 Python socket_client.py 一致。双向对拍验证。
4. 单二进制，**Linux only**（AF_PACKET/抓包/单队列均 Linux 能力，build tag `//go:build linux` 隔离；mcp 模式理论可跨平台编译但不在验收范围）。

**非目标**
- 不迁移 Python 版 SQLite 数据（旧 DB 文件不读、不写、不覆盖——新部署重新 add_target）；不兼容旧 config.yaml 键名（但 §7 的 /opt/socket/config 三键除外）。
- 不做 MCP 鉴权（对齐现状：内网信任 + DNS rebinding 保护关闭）。
- **datatype 16（python_cmd）不复刻**：Go 无 Python 解释器；收到后回 **`[4B i][gzip JSON {"error":"datatype 16 not supported"}]`**——沿用 dt1 的响应形态（`recv_gzip_response` 可解析），保证旧中央调用时不因裸 JSON 被误当长度前缀而挂死（审查修订）。验收标注：旧 e2e 的 dt16/dt122 用例对 Go 靶机为预期失败。
- datatype 121/122/123 不复刻（源码已整段注释弃用）。
- 不删 Python 两仓库（参考实现 + 对拍 oracle）。

## 2. 权威协议契约（:9000 TCP）

帧格式：`[4B len][4B datatype][payload]`，两个前缀均为**固定 little-endian int32**（x86 native；Go 实现写死小端，不随宿主）。`len = 4 + len(payload)`。

**服务端接收循环（protocol.py handle() 逐条语义）**
1. recv(10240) 循环；首包 <4B → log + **break 断连**（无响应）。
2. 非接收态：累计至读满 len 字节；累计 >len → 丢弃当前帧、清缓冲继续（等下一帧头）。
3. 收满一帧：`bin_recv_flag==False` 时帧体拆 [4B datatype][data]（帧体 <4B → 跳过继续）；`bin_recv_flag==True` 时 datatype 恒置 23、帧体即文件内容（**长度前缀仍照常消费**——step23 的 `[4B len][内容]` 走同一套定长收帧，只是不拆 datatype）。
4. `do()` 返回响应 → sendall；**sendall 失败 → sleep 3s 重发一次**。此重试只适用 on_data 响应；**21/22/23/24 握手应答不走重试**。
5. `do()` 返回 nil（未知 datatype `else: pass`）→ 不发任何响应，连接继续等下一帧。
6. **`do()` 内任何异常（JSON 解析失败、错键 KeyError、routeinfo RuntimeError、boce 运行时异常等）→ 顶层捕获、log、`request.close()` 断连，无任何响应帧**——"异常=静默死亡"是对拍必须覆盖的模式。
7. ConnectionReset → break。持久连接，可复用。

**文件传输状态机（21→22→23→24 同一连接，连接级状态 filepath/gzip/bin_recv_flag/bufsize；初值 filepath="tmp"）**
- 21: `{"filepath":...,"gzip":bool}` → 更新连接级状态 → `b"21 ok"`。JSON 解析失败/缺 filepath(filepath=None) → 后续 dt24 `open(None)` 异常断连（不复刻则行为漂移）。
- 22: payload `<Q 8B 小端 压缩后长度>`；**<8B → log + continue（无响应、不进 bin 模式）**；成功 → bin_recv_flag=True、bufsize→102400000 → `b"22 ok"`。
- 23: 内容累积；==length → bufsize→1024、bin 复位 → `b"23 ok"`；**>length → RuntimeError（bufsize 复位、bin 复位）→ 顶层异常 → 断连**；未满 → 继续收。
- 24: 写盘（gzip 则解压；解压结果 `b"^$"` 当空文件）→ `b"24 ok"`。
- 下载 dt3：payload 只有 `{"gzip":bool}`；**文件路径读连接级 filepath**（21 步设置），非 payload 字段。

**响应五类（datatype → 形态，按当前源码核定）**

| 形态 | datatype | 说明 |
|---|---|---|
| 裸 JSON 文本（无前缀） | 0/4/5/6/7/8/9/10/11/14/15?/18/19/20/171 | `_recv_until_timeout`：首 chunk 后 0.5s 短探。dt15 例外见下行 |
| `b"ok"` / `b"error"` inline | 15/172/173 | 15 成功恒 `b"ok"`（unzip 缺失也回 ok）；**172/173 未启动/失败是裸 `b"error"`**（回退后契约，非 JSON） |
| inline `b"NN ok"` | 21/22/23/24 | 握手应答 |
| `{"error":...}` JSON | 174/175/131 预检 | 174 未启动、175 未启动或停止失败；131 仅 chromium 预检失败（带 `[4B i]` 前缀） |
| `[4B i][gzip JSON]` | 1（含 Go 版 dt16 兜底） | dt1 的 `wait=false` 时 exec 返回 None → `json.dumps(None)`="null" **仍回 gzip 帧**（非不回） |
| `[4B i][JSON]` | 131 正常/200 | 长度前缀非 gzip |
| `[8B <Q len][content]` | 3（可选 gzip）/174（必 gzip） | 174 错误时是裸 `{"error":...}`（首字节 `{` 探测分支） |

**服务端全局状态与并发（审查补充）**
- `active_clients`：setup/finish 计数，**覆盖所有 :9000 连接含 MCP 桥的空闲池连接**——dt20 的 `active_clients>1 拒绝升级` 按此语义（空闲池连接也算数，Go 只计"处理中"会误放行）。
- `ss`（监听单例）、`boce`/browser：模块级单例，Go 用包级状态 + mutex；并发访问策略见 §11。

## 3. agent 侧 datatype 全量清单（逐条对齐 handlers.py do() 当前源码）

| dt | 功能 | 实现要点（⚠ 标注 = 审查修正项） |
|---|---|---|
| 0 | pcap 回放 | truthy 校验 pcaps/uplink_iface/downlink_iface；**错误文案固定** `"Missing required parameters: uplink_iface or downlink_iface"`（缺 pcaps 也报这个）；PcapReplayer 其余参数透传；stats JSON 裸文本。回放内部异常 → `{"status":"error","message":str(e)}` |
| 1 | 命令执行 | exec_cmd_subprocess：shell+str 时 root 剥裸 `sudo `（带选项/空命令不剥，仅 root）；env 清理：**删 LD_LIBRARY_PATH**（非 PyInstaller 特有，保留）+ _PYI_*/_MEIPASS 前缀变量删除仅 Go 版可省（无 PyInstaller，见 §12）；wait=false → **返回 None → 照常回 "null" gzip 帧**（⚠ 审查修正：不是不回）；回 `[4B i][gzip {code,stdout,stderr}]` |
| 3 | 文件下载 | ⚠ 路径读连接级 filepath（payload 仅 gzip）；`[8B <Q][content]` |
| 4 | routeinfo | `route -n` 解析（头 2 行 + zip）；**非零退出 → RuntimeError → 断连无响应**（⚠ 审查修正）；route 命令缺失同理 |
| 5 | 抓包开始 | **⚠ 回退后契约：`{"res": bool}`**——失败 `{"res": false}` 无 error 字段（1.7.2 的 error 通道已随 f13b65d 回退删除）；eth 空 → routeinfo 默认路由网卡（取不到 → false）；同 path 先停旧；清旧文件失败仅 warn |
| 6 | 抓包停止 | **⚠ 回退后契约：`{"res": bool}`**——成功 true；从未 start 幂等 true；停止失败 false（含 join 超时/子进程非零退出）。mcp 客户端的四态解析分支保留为兼容死代码 |
| 7/8 | isfile/isdir | `{"file"/"dir": path}` → `{"res":bool}` |
| 9 | mkdir | `{"res":null}`（os.makedirs 返回 None） |
| 10 | 改 MTU | ifconfig 解析（新旧两格式）；值不等则设置后 sleep 5；需 ifconfig 存在否则 RuntimeError |
| 11 | 取字节数 | `{"res":size}` |
| 14 | 版本 | `json.dumps(VERSION)` 带引号 |
| 15 | 解压 zip | list args 防注入；**成功/失败/unzip 缺失一律 `b"ok"`** |
| 16 | python_cmd | Go 版不复刻：回 `[4B i][gzip {"error":...}]`（§1） |
| 18 | ensure_command | which → `{"res":bool}`（带 install_cmd 时跑安装再查） |
| 19 | 版本详情 | version/repo/release_notes/latest_version/has_upgrade；Go 版 release_notes 编译期注入，`has_upgrade = (注入版本 != VERSION)`（注入相同时恒 false，验收标注为有意差异） |
| 20 | 升级落地 | 版本正则 `^\d+(\.\d+){1,3}$` + 64hex sha；autoupgrade=off 拒；升级锁互斥；**active_clients>1（含空闲池连接）且非 force 拒**；同步落盘（staging sha256 校验→chmod 755→replace→清 staging），成功 `{"ok":true,"version":...}`；后台 0.3s 后 switch_to（原子软链+重启） |
| 131 | 拨测 | chromium 预检：不存在→自动下载 npmmirror（失败回 `[4B i][{"error":...}]`）；自检 stderr 含 `cannot open shared object file` 才装依赖（yum/apt 二选一；**无包管理器只 log 继续**；装后复测失败回 `[4B i][{"error": stderr[:200]}]`）；之后 boce() 运行时异常**冒泡 → 断连无响应**（⚠ 回退后契约）；封堵=`{"res":...}`？**否——回 `[4B i][json]`**（do() 对 131 加 pack）。拨测细节见 boce 段 |
| 171 | 监听启动 | **⚠ 成功契约 = "端口被任何人持有"而非"本次启动成功"**：ss 存活→跳过；ss 死→重启；无 ss→新建启动（start_server 吞异常返回 None）；**无条件回 `{"pid":[ss输出解析]}`，可为 `[]`**（bind 失败也回空 pid 列表，不报错——回退后"换端口静默忽略"语义）。pid 来源 `ss -lptn` 解析 |
| 172/173 | 清数据/保存 | 判活 `ss and ss.pid()`；未启动 → **裸 `b"error"`**（⚠ 回退后契约，非 JSON）；成功 `b"ok"`；173 payload `{"file":...}`（缺键 → 异常断连） |
| 174 | 监听取流 | **判活仅 `ss is None`**（对象在但监听死 → 回 `gzip(空data)` 流，非 error——quirk 复刻）；正常 gzip(全量) `[8B <Q][content]` |
| 175 | 监听停止 | ss 为 None → `{"error":"未启动监听"}`；stop_server（terminate→join3→kill 链）后 **3 轮：先查 `ss.pid()` 有 pid 才 sleep 0.5**；仍活 → 清 ss、回 `{"error":"停止监听失败，端口仍被占用"}`；停止路径含 **stop_server 内对端口残留者逐个 `kill -9` 清扫**（缺它则陈旧占端口场景误报失败） |
| 200 | pcap 五元组 | **⚠ 输出全部是字符串**：srcPort/destPort/protoType 均为 str（ICMP 端口 `"0"`；protoType "1"=TCP "2"=UDP "3"=SCTP "4"=ICMP/ICMPv6）；流键 = (ip, port字符串) 元组**字典序** sort + protoType（"9">"10" 的序也照抄）；方向判定：首包默认 → SYN/SYN+ACK 修正 → HTTP 方法列表/`HTTP/1.` 响应行修正，一次锁定；解析边界：**单层 VLAN 无 QinQ、IPv4 不验总长/分片、IPv6 固定 offset 6 不走扩展头**；坏 pcap 跳过（log 继续）；`[4B i][JSON]` |

**抓包（capture.py → Go）**：proto=0 创建 → 全部 setsockopt 就位 → 最后 `bind(eth, ETH_P_ALL)`（防未过滤窗口）；时间戳四级降级（SO_TIMESTAMPING HW|SW|RAW → RX_SW → SO_TIMESTAMPNS → monotonic；cmsg ts[0]==0 退化 ts[1] + warn 一次）；VLAN 还原（PACKET_AUXDATA；`tci!=0 OR VLAN_VALID`、tpid 默认 0x8100；offset 12 插 4B）；SO_RCVBUF 32MB + getsockopt 截断验证；promisc 失败仅 warn；**BPF（extended 非空）：exec `tcpdump -ddd` → 解析首行条数 + 逐行转 unix.SockFilter → unix.SockFprog 注入 SO_ATTACH_FILTER**（tcpdump 缺失/编译失败 = 抓包启动失败回 res:false，agent 主服务不受影响）；停止：置 stop → **drain 完队列再退**（1s 超时轮）；join 10s 超时不关文件返回 false；tpacket_stats close 前读；落盘后 4 种 magic 识别 + 稳定排序重排（原子 replace）；pcap 写纳秒 magic 0xA1B23C4D、snaplen 65535。**Go 差异：goroutine 长驻循环必须 panic recover**（Python 子进程的故障隔离理由在 Go 仍部分成立——recv 循环 panic 不得拖死 agent，见 §12）。

**单队列（SingleQueueRxThread → Go）**：ethtool -l 查/`-L combined 1` 缩；IRQ 三路查找（msi_irqs 目录 → /proc/interrupts 名称匹配 → grep）；绑非 0 空闲 CPU（/proc/stat ≥99% 排除 + 已分配集合 + CPU0 保留）；禁 RPS/RFS；/tmp/cpus 缓存；**全部 best-effort：失败仅 warn 不阻断抓包**（发行版/驱动差异大，验收按目标机型实测）。

**回放（replayer.py → Go）**：五元组（含 MAC）建流；方向 = hint 优先 → SYN → 反向流推断 → 默认 uplink；`directionless && no_tuple_modification && !force_build_flow` → 不建流直发；对称换向 force_* 改写；IPv4↔IPv6 互转（IP/TCP/UDP/ICMP 校验和重算；SCTP 不动）；VLAN 增改（已有 81 00 只换 TCI）；AF_PACKET SOCK_RAW 发送（socket 缓存复用；需 root/CAP_NET_RAW）；mbps 每包+全局两级限速；pcap 缓存（微秒 magic 单/双文件）；字节统计 `max(orig_len, 60)`。

**拨测（boce.py → Go）**：封堵 = net/http 并发（UA 伪装 Chrome/120、allow_redirects=false、200=成功、time 累计）；重定向 = chromedp（**重试触发条件精确对齐：仅异常含 `"Connection is closed"` 时关 browser 重启重试一次**，非泛化崩溃重试；判定 = framenavigated 跳转 URL 集合 / request 计数>1 / ERR_TOO_MANY_REDIRECTS 分支；chromium 启动参数以 boce.py:201-213 的 11 个 args 逐项对齐）；chromium 自动下载（npmmirror 查最新 revision、/opt/socket/config 的 proxy=、临时目录解压 chmod、失败打印手动步骤）。

**:9001 HTTP 文件服务（http_file.py → Go）**：GET 流式 1MB 分块 + Content-Length 锁死；POST multipart 流式落盘（path 先到直写 `<path>.part` + 原子 replace；file 先到临时文件后 move——**upgrade_run 推 staging 依赖父目录自动 makedirs**）；边界复刻：多 file 字段追加写首个句柄且 size 只报最后一段、path 值 4096 上限→400、伪命中分隔集合含 `--`/`\r\n`/**裸 `\n`**（⚠ Go mime/multipart 不容忍 LF 结尾——需自定义 reader，列入 §12）、缺 path 时 400 发生在 body 全量消费后、realpath 归一化、boundary ≤256；http_port 读 /opt/socket/config（0=关闭，缺省 9001）；双栈 + IPv6 失败降级。

**服务化（supervisor/upgrader/autoupgrade → Go）**：路径逐字对齐 Python：`/opt/socket/versions/<v>/socket_server`、`.staging/socket_server`、`current` 软链原子切换、unit 自愈（ExecStart 指向 current）、/opt/socket/config 的 `autoupgrade=`（缺省 on，Go 的 dt20 落地前**实时读旧文件**）与 `http_port=`/`proxy=`（见 §7 优先级）。

**serve 环境初始化**：日志（显式 > SOCKET_SERVER_LOG > /var/log/socket_server.log；目录不存在跳过文件 handler 不崩）、rmem/wmem_max≥32MB、java PATH、防火墙命令组逐条保留；PyInstaller 的 PLAYWRIGHT_BROWSERS_PATH 逻辑删除（§12）。

## 4. mcp 侧 15 个 MCP 工具

契约基准：参数名/类型/默认值/required/annotations（readOnlyHint/destructiveHint/idempotentHint/openWorldHint）以 `mcp_socket_server/server.py:262-786` 为**逐行对拍契约**，不在文档重复罗列；下表只记业务要点。⚠ = 审查修正。

| # | 工具 | dt | 锁 | 危险 | 要点 |
|---|---|---|---|---|---|
| 1 | list_targets | - | - | RO | 空 + note |
| 2 | add_target | - | - | 写 | TCP 探活 3s；force 跳过；剥 IPv6 方括号 |
| 3 | remove_target | - | - | 写 | 活跃锁/活跃监听拒绝 |
| 4 | version | 14 | NONE | RO | 字符串版本 |
| 5 | file_transfer | - | - | RO | :9001 curl 指令；host 三形态；IPv6 加方括号 |
| 6 | isfile | 7 | NONE | RO | `{"file": path}` |
| 7 | isdir | 8 | NONE | RO | `{"dir": path}` |
| 8 | pcap_flow_extract | 200 | NONE | RO | >1000 截断 + truncated；⚠ flows 字段类型与 §3 dt200 字符串契约一致 |
| 9 | cmd_exec | 1 | SHELL | DANGER | 白名单前缀；stdout>64KB 截断标记；wait=false → note（来源：客户端收 "null" → data=None → B18 note，⚠ 链路修正）；timeout=wait?60:15 |
| 10 | capture_start | 5 | CAPTURE(path) | 写 | ⚠ 服务端只回 `{"res":bool}`：res:false 无 error → False → B23 泛化文案（error 通道是兼容分支，对 v1.8.3 服务端为死代码）；锁成功保留到 stop |
| 11 | capture_stop | 6 | CAPTURE | 写 | ⚠ 服务端回 `{"res":bool}` → 客户端 legacy 映射（true→stopped；false→error 可重试）；四态/failed_details 分支保留为兼容代码；锁无论成败释放 |
| 12 | boce_run | 131 | BROWSER | 写 | timeout≥10（pydantic 校验，Go 侧参数校验等价实现）；socket_timeout=timeout+10；inner=max(3,timeout-10)；服务端 `{"error"}` → 抛错；**运行时异常断连 → 客户端 recv 异常 → failed**（⚠ 回退后路径） |
| 13 | replay_run | 0 | REPLAY | 写 | status=error 抛错 |
| 14 | socket_listen | 171-175 | SYSTEM | 写 | save 需 file；未知 action 校验；start 后 dt14 探版本≥1.7.1 登记 liveness（⚠ 172/173 失败是裸 b"error"，客户端 `_decode_listen_error` 双兼容照抄）；fetch 超 max_bytes 落盘 /home/tmp/listen_<ts>.log + base64 截断；174 首字节 `{` 探测 |
| 15 | upgrade_run | 20 | SYSTEM | DANGER | resolved 空 → 逐 target failed；版本非法/查版失败/下载失败 → target="*"；run_one 预检 dt14≥1.8.0（⚠ 对 Go 靶机 1.9.0 天然通过）；push_binary（IPv6 方括号）；dt20 error → `_error`；close 归还（不复用垂死连接）；轮询 180s/3s（短连接新建，host:port 拆分同 registry）；终态审计含确认结果 + duration_ms |

通用批量语义（_run_batch）：`{ok, failed:[{target,reason}], results:[{target,...}]}`；**results 只含成功项，dict 展开（_wrap）、非 dict 包 `result`；failed 单列**；锁顺序 = 先锁后借池，锁冲突 fail-fast → 该 target failed；池借出失败 → 释放已获锁；`{"_error":...}`/False → failed；None → note；审计 outcomes 逐 target `{target,ok,error}` + params 截断 200 + duration_ms。

**池/锁/注册表/审计/升级编排契约补充（审查补齐）**
- 池：max_conn_per_target=5、idle 600s、borrow 10s、**全局并发 50**；acquire 超时抛错；过期连接锁外 close；**connect 失败回滚 _inuse + notify**（泄漏即永久耗尽）；不健康连接锁外关闭；复用连接同步 socket_timeout（N8）；Scheduler.session 独占借还。
- 锁：CAPTURE 按 `(path,)`；capture 与排他互斥；冲突文案由 manager 回填真实 target（B07）；release_target 静默兜底。
- 注册表：resolve —— `@tag` 展开、未知静默跳过；`host:port` 拆分 = **冒号后全数字才拆（源码 quirk：裸 IPv6 尾段数字如 `fd00::5` 也会被截，照抄不修）**；listen_liveness 列启动时 ALTER TABLE 迁移。
- socket_client：inline ack 0.3s 短探、每次 send/recv 前 settimeout 防 0.5s 泄漏、`_decode_listen_error` 兼容 1.6.x 裸 error。
- upgrades：raw version.py 查版（非 API）；退避 1h→2h→4h（首败 warning、后续 debug、恢复 info）；ensure_release_binary 幂等复用（sha 校验后 tmp+原子落盘）；每日兜底先睡 24h、绝不自动升级。
- 传输：Streamable HTTP 经 ASGI app 由 HTTP server 绑定、DNS rebinding 保护关闭；serverInfo.version = 桥版本 0.4.0（与 dt14 靶机版本分离）。
- 日志：init_server 按配置重设级别；registry/audit 共用 db_path（WAL）。

## 5. 模块结构（Go）

```
cmd/socketstack/          # 入口: (无参)=mcp stdio | mcp serve | agent | install | uninstall
                          #       agent|mcp enable|disable|start|stop|status
internal/frame/           # 仅字节层: 常量/读写帧/长度校验(⚠ 审查修订: 21-24 状态机不放这里,
                          #   它依赖连接级业务状态,归 internal/agent; mcpbridge 保留客户端响应形态解释)
internal/agent/           # server/handlers/netexec/capture/singlequeue/replayer
                          # boce_http/boce_browser/listen/pcapflow/httpfile/upgrade/setup
                          # connstate.go: 连接级 filepath/gzip/bin 状态 + 21-24 状态机
internal/svc/             # systemd 两单元 install/uninstall/enable/start/stop/status
internal/mcpbridge/       # protocol/pool/locks/registry/audit/upgrades/tools/transport/config
internal/config/          # 合体 YAML + env 覆盖(覆盖键白名单见 §7)
```

## 6. 技术选型

- **Go：go.mod `go 1.24` + `toolchain go1.25.x`**（本机 1.21.13 经 auto-toolchain 实测；Release 构建机固定新工具链，**auto-toolchain 仅构建期依赖，非靶机运行时依赖**）；CI 验证 `CGO_ENABLED=0` 全量构建。
- **MCP SDK**：`github.com/modelcontextprotocol/go-sdk v1.8.0`（依赖存在性已核实；stdio + Streamable HTTP 路由/超时/客户端兼容性属本项目集成验证，见 §9）。
- **`golang.org/x/sys/unix`**：AF_PACKET、Recvmsg + ParseSocketControlMessage（SCM_TIMESTAMPING/PACKET_AUXDATA 的 **cmsg 内容解析手写**——API 只给原始字节）、PACKET_ADD_MEMBERSHIP、SockFprog。权限前提：root 或 CAP_NET_RAW（写进部署文档与 §11）。
- **`github.com/chromedp/chromedp`**：重定向拨测（纯 Go CDP）。
- **`modernc.org/sqlite`**（纯 Go）；**单写连接 + busy_timeout** 策略（§11 并发条目）。
- YAML `gopkg.in/yaml.v3`。**不引入 golang.org/x/net**（v2 文档 §3 的 x/net/bpf 提法删除——BPF 走 `tcpdump -ddd` exec，解析细节：首行条数 → 逐行 `code jt jf k` → SockFilter 数组 → SockFprog{Len, &filters[0]}，指针生命周期覆盖 setsockopt 调用）。
- "已验证"两级标注：依赖存在性/接口可用 = 已核实；项目场景集成 = §9 验收项。

## 7. 配置与配置源优先级

```yaml
# /etc/socketstack/config.yaml（全部可省略；不写即默认值）
agent:
  tcp_port: 9000
  log_file: /var/log/socket_server.log   # env SOCKET_SERVER_LOG > 此键 > 默认
mcp:
  bind: {host: 0.0.0.0, port: 8080}
  db_path: /var/lib/socketstack/mcp.db   # systemd 用绝对路径(WorkingDirectory 固定)
  download_dir: /var/lib/socketstack/downloads
  proxy: ""
  log_level: INFO
  default_timeout: 30
  behind_proxy: false                    # ⚠ 审查补齐(v2 遗漏)
  pool: {max_conn_per_target: 5, idle_timeout: 600, borrow_timeout: 10, max_global_concurrency: 50}
  audit_retention_days: 90
  cmd_exec_whitelist: []
```

**/opt/socket/config（旧键，兼容源）**：`autoupgrade=`、`http_port=`、`proxy=` 三键由 agent 侧**实时读取**（dt20 前检查 / :9001 端口 / chromium 下载），与 YAML 的关系 = **旧文件对这三键优先**（升级互操作要求旧中央写 /opt/socket/config 后 Go agent 即刻生效）；Go 版提供 `socketstack agent autoupgrade on|off` 子命令**写回旧文件**（对齐 Python set_autoupgrade）。历史遗留 `port=9000` 键**不接线**（Python 版亦然，文档明示）。

env 覆盖（**白名单，仅以下键**，审查修订）：`MCP_BIND_HOST/PORT`、`MCP_LOG_LEVEL`（config loader 语义）；`MCP_DEFAULT_TIMEOUT`（socket_client 语义，非 config loader）；`SOCKET_SERVER_LOG`。其余参数仅 YAML。

版本号：发行包 1.9.0 起；dt14/dt19 报 1.9.0 序列；serverInfo.version 报 0.4.0 序列。

## 8. 服务化、安装与升级互操作

```
socketstack                    # stdio（本地 MCP 客户端）
socketstack mcp serve          # Streamable HTTP（systemd mcp 单元唯一入口）
socketstack agent              # 前台 agent（调试；systemd 经 current 软链调用）
socketstack install [--with-mcp] | uninstall
socketstack agent|mcp start|stop|status|enable|disable
socketstack agent autoupgrade on|off
```

- **二进制名闭环（审查修订，P1）**：Release 资产对外名 = `socket_server`（dt20/staging/final 路径逐字不变，Python 中央可直接升 Go 靶机）；安装时复制为 `/usr/local/bin/socketstack`；**agent 单元 ExecStart = `/opt/socket/versions/current/socket_server agent`**（走软链 → switch_to 切链重启即换版）；mcp 单元 ExecStart = `/usr/local/bin/socketstack mcp serve`。
- 单元：agent `Restart=always`/5s；mcp `Restart=on-failure` + `WorkingDirectory=/var/lib/socketstack`。**自愈逻辑兼容识别旧 `socket_server.service` 与新 `socketstack-agent.service`，不误改对方**；uninstall 保留 /opt/socket/versions、配置与 mcp DB（数据式卸载，明示列出删除项才删）。
- 升级闭环验收（§9）：Go 中央→Go 靶机、Python 中央(0.3.2)→Go 靶机、Go 中央→Python 靶机(1.8.3) 三条链各跑一轮；Release 附 `.sha256`。

## 9. 验证策略

1. **协议单测**：net.Pipe 逐帧（§2 全部分支：21-24 全路径含 <8B/超长断连/`^$`、超长帧丢弃、异常断连无响应、未知 dt 无响应、sendall 重试范围）。
2. **mock 对拍（mcp 侧）**：Go mock socket_server 喂 canned 字节；Python socket_client vs Go 客户端逐字节比对。CI。
3. **反向对拍（agent 侧）**：Python test_e2e.py / mcp_socket_server mock 作 oracle 打 Go agent，**不改一行**。覆盖全部 dt + §2/§3 全部 ⚠ 修正项；dt4 断连、dt16 错误帧、131 运行时异常断连单列用例；e2e 中 dt16/dt122 标注预期失败。
4. **深模块差分**：capture/pcapflow/replayer 与 Python 输出逐字段 diff（含 dt200 字符串类型与字典序）；chromedp vs pyppeteer 同一跳转样例集；`tcpdump -ddd` 已知表达式注入匹配验证；multipart LF 结尾容忍用例。
5. **升级闭环**：三链各一轮（§8）+ 180s 轮询窗口。
6. **真实 e2e**：15 工具 + agent 全 dt 人工验收；IPv6 靶机路径（add_target/push 方括号/双栈监听——**注意 Python 客户端 AF_INET-only，IPv6 属 Go 有意增强**，对拍时单独标注）；`go test -race` 全量并发（ss/boce/browser 单例、池、SQLite 并发写）。

## 10. 实施顺序（TDD）

```
frame(字节层) → config/svc
→ agent 只读组(14/7/8/9/11/18/19/4/200) → :9001 httpfile
→ 文件传输(3/21-24) → 命令(1/15/10)
→ listen(171-175) → boce(131) → capture(5/6) → replayer(0)
→ 升级(20/upgrader/supervisor)
→ mcpbridge protocol(+mock 对拍) → pool/locks/registry/audit
→ tools(只读→写) → upgrades → transport(stdio/HTTP)
→ 合体 CLI/双单元 → 三链升级闭环 → 真实 e2e → tag v1.9.0
```

## 11. 风险与对策

| 风险 | 对策 |
|---|---|
| 协议 drift（最大） | §9 双向对拍 CI；frame 常量共享；本文档 ⚠ 项全部入用例 |
| AF_PACKET cmsg ABI / 权限 | 真机集成测试；root/CAP_NET_RAW 写进部署文档；32/64 位 ABI + cmsg 截断用例 |
| goroutine panic 拖死 agent | 所有长驻 goroutine（抓包 recv/监听/重放/boce worker）强制 recover + 状态上报 + stop 可重试（§12#2） |
| chromedp 语义漂移 | 判定逐条对齐 boce.py + 样例差分；chromium 同源自动下载 |
| tcpdump 缺失/表达式差异 | 缺失=抓包启动失败（res:false），agent 主服务不受影响；表达式子集文档化 |
| 单例并发（ss/boce/browser） | 包级 mutex + `-race` CI；busy_timeout + 单写连接管 SQLite |
| IPv6 | 监听/解析全双栈；客户端对拍时 Python AF_INET-only 基线单独标注 |
| 升级互操作 | §8 三链闭环 + 路径逐字对齐 + 自愈双 unit 识别 |
| 时区/时间戳 | 统一本地时区 time.Now()（对齐 Python time.time()/datetime.now()），审计/落盘文件名格式逐字对齐 |
| modernc SQLite 并发 | 单写 goroutine 串行化 + busy_timeout；并发注册/审计用例 |
| 旧部署静默变更 | 旧 DB 不覆盖；旧 config 三键兼容 + port= 键不接线写进部署文档 |
| 发行版差异（route/ethtool/net-tools 缺失） | routeinfo 失败=RuntimeError 断连（对齐）；单队列 best-effort warn |

## 12. 与 Python 版的有意差异清单（评审重点，v2.1 修订）

| # | 差异 | 理由 / 兼容动作 |
|---|---|---|
| 1 | dt16 不实现，回 `[4B i][gzip {"error"}]` | Go 无解释器 + eval 裸洞；帧形态沿用 dt1 使旧中央 `recv_gzip_response` 可解析不挂死；验收标注旧 e2e dt16 用例预期失败 |
| 2 | 抓包/监听子进程 → goroutine | GIL 隔离不再需要；**但故障隔离仍在**：所有长驻 goroutine panic recover + 异常上报，stop 语义（drain/超时不关文件）逐条保留 |
| 3 | pyppeteer → chromedp | 判定逻辑逐条映射（jumped_urls/request_count/Connection-is-closed 重试一次/11 args） |
| 4 | scapy BPF → `tcpdump -ddd` exec | 无纯 Go tcpdump 编译器；失败=抓包启动失败带原因（对齐 scapy 抛错语义） |
| 5 | PyInstaller env 清理（_PYI_*/_MEIPASS 前缀）删除；**LD_LIBRARY_PATH 清理保留** | 前者无 PyInstaller；后者是通用污染防护 |
| 6 | release_notes 编译期注入（-ldflags）；has_upgrade = 注入版本≠VERSION（恒 false） | dt19 结构不变，语义验收标注 |
| 7 | 一仓一码，发行版本 1.9.0 起 | dt14 靶机序列 / serverInfo 桥序列（0.4.0）分离 |
| 8 | multipart 伪命中集合含裸 `\n`（Go 标准库不容忍） | 自定义 multipart reader 保留 Python 行为；列入 §9 差分用例 |
| 9 | PLAYWRIGHT_BROWSERS_PATH 注入删除 | Go 无 playwright |
| 10 | IPv6 TCP 客户端支持（Python client AF_INET-only） | 有意增强，对拍单独标注；不影响 wire 格式 |
| 11 | mcp 模式理论可非 Linux 编译，验收仅 Linux | AF_PACKET build-tag 隔离 |
