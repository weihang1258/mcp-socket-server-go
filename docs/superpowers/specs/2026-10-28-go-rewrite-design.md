# socketstack-go 合体重构方案（设计文档 v2.2）

日期：2026-10-28（v2.2，第 2 轮对抗性复审修订；取代 v2.1）
状态：实施中（agent 侧全量落地；待真机验收项见 §13）

本文档是 **socket_server**（Python，v1.8.3，靶机侧内部服务）与 **mcp_socket_server**（Python，v0.3.2，中央 MCP 桥）两项目合并为单一 Go 项目的唯一方案来源。全部行为以两仓库源码逐文件通读推导，经两轮独立对抗性审查（5+3 个维度）交叉核验。

**版本基线警示**：socket_server 仓库 commit `f13b65d` 将 dt5/dt6/131/171/172/173 的接口行为**整体回退到 v1.7.0 原样**（仅保留 175）。本文档一切 wire 契约以**回退后的当前源码**为权威；mcp 客户端 socket_client.py 中"四态 / error 通道"解析分支对本服务端是**死代码**，仅作兼容保留。

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

- **同一个二进制，两种运行模式**，物理分开部署（agent 在靶机、mcp 在中央）。
- **开关权威只有一个：systemd 单元**：
  - `socketstack install` 默认只装并启用 agent 单元；`install --with-mcp` 额外装 mcp 单元（同机调试用，标准部署分机安装）；
  - `socketstack agent|mcp enable|disable|start|stop|status` 分别管理两单元 = 开关的"启动、关闭等动作"。
- **子命令（不读任何 enabled 开关）**：`socketstack`（无参）= stdio MCP 本地接入；`socketstack mcp serve` = Streamable HTTP（mcp 单元唯一入口）；`socketstack agent` / **`socketstack serve`** = agent 模式（`serve` 为 `agent` 的别名，见 §8 升级互操作）。`serve` 与 `agent` 均为 systemd agent 单元合法入口。
- **版本语义分离**：dt14/dt19 报靶机版本（1.9.0 序列）；MCP serverInfo.version 报桥版本（0.4.0 序列）。发行包统一版本号。

## 1. 目标与非目标

**目标**
1. agent 侧全量对齐 socket_server v1.8.3 当前源码（含 f13b65d 回退后 wire 行为）。
2. mcp 侧全量对齐 mcp_socket_server v0.3.2：15 个 MCP 工具（schema/annotations/默认值以 server.py:262-786 为逐行契约）、批量部分失败语义、连接池、状态锁、审计、标签解析、升级编排、stdio + Streamable HTTP。
3. 协议零漂移：agent 对外帧格式与 Python 版字节级一致；mcp 客户端与 Python socket_client.py 一致。双向对拍验证。
4. 单二进制，**Linux only**（AF_PACKET/抓包/单队列均 Linux 能力，build tag `//go:build linux` 隔离；mcp 模式理论可跨平台编译但不在验收范围）。

**非目标**
- 不迁移 Python 版 SQLite 数据（旧 DB 不读不写不覆盖，新部署重新 add_target）；不兼容旧 config.yaml 键名（§7 的 /opt/socket/config 三键除外）。
- 不做 MCP 鉴权（对齐现状：内网信任 + DNS rebinding 保护关闭）。
- **datatype 16（python_cmd）不复刻**：Go 无解释器；收到后回 `[4B i][gzip JSON {"error":"datatype 16 not supported"}]`（沿用 dt1 响应形态，`recv_gzip_response` 可解析，旧中央不挂死）。验收标注旧 e2e dt16/dt122 用例预期失败。
- datatype 121/122/123 不复刻（源码已注释弃用）。
- Python 源码中的**死代码不移植**（全仓 grep 无调用点；非穷尽列举，同型新增同理）：capture.py 的 `cache_cpus/restore_cpus/remove_cpusfile/get_tx_cpu/config_rx_thread_cpus/tcpdump_isrun`、replayer.py 的 `PcapStats/PacketBuffer`、netutils.py 的 `wait_until/wait_not_until/cur_time`、boce.py 的 `kill_all_chrome/_sniff_command`。/tmp/cpus 缓存机制随其死亡，不进设计。
- 不删 Python 两仓库（参考实现 + 对拍 oracle）。

## 2. 权威协议契约（:9000 TCP）

帧格式：`[4B len][4B datatype][payload]`，两个前缀均为**固定 little-endian int32**。`len = 4 + len(payload)`。

**服务端接收循环（protocol.py handle() 逐条语义）**
1. recv(10240) 循环；**recv 返回空（对端关闭）→ break 断连**。
2. 首包 <4B → log + break 断连（无响应）。
3. 非接收态：累计至读满 len；累计 >len → 丢弃当前帧、清缓冲继续（等下一帧头）。
4. 收满一帧：`bin_recv_flag==False` 时帧体拆 [4B datatype][data]（帧体 <4B → 跳过继续）；`bin_recv_flag==True` 时 datatype 恒置 23、帧体即文件内容（**长度前缀仍照常消费**——step23 的 `[4B len][内容]` 走同一套定长收帧，不拆 datatype）。
5. `do()` 返回响应 → sendall；**sendall 失败 → sleep 3s 重发一次**。仅适用 on_data 响应；21/22/23/24 握手应答不走重试。
6. `do()` 返回 nil（未知 datatype `else: pass`）→ 不发响应，连接继续。
7. **`do()`/协议分支内任何异常（dt21 畸形 JSON、dt22>8B、dt24 无前置、错键 KeyError、routeinfo RuntimeError、boce 运行时异常等）→ 顶层捕获、log、close 断连，无任何响应帧**——"异常=静默死亡"是对拍必测模式。
8. ConnectionReset → break。持久连接，可复用。

**连接级状态（protocol.py setup() 只初始化 4 个：filepath="tmp"、content=b""、bin_recv_flag=False、length=0；⚠ `gzip` 不在 setup 初始化——未经 dt21 直发 dt24 触碰 `self.gzip` 即 AttributeError 断连）**

**文件传输状态机（21→22→23→24 同一连接）**
- 21: `{"filepath":...,"gzip":bool}` → 更新连接级 filepath/gzip → `b"21 ok"`。**两个失败分支**：①畸形 JSON → json.loads 抛 → **立即断连无响应**（走不到 "21 ok"）；②JSON 合法但缺 filepath → get(None) 存 None → 回 "21 ok"，**后续 dt24 `open(None)` 异常断连**。
- 22: payload `<Q 8B 小端 压缩后长度>`。**三态**：①<8B → log + continue（无响应、不进 bin 模式）；②**>8B → struct.error → 断连无响应**；③恰 8B → bin_recv_flag=True、bufsize→102400000 → `b"22 ok"`。
- 23: 内容累积；==length → bufsize→1024、bin 复位 → `b"23 ok"`；>length → RuntimeError（bufsize/bin 复位）→ 顶层异常断连；未满 → 继续收。
- 24: 写盘（gzip 则解压；解压结果 `b"^$"` 当空文件）→ `b"24 ok"`。
- 下载 dt3：payload 只有 `{"gzip":bool}`；**文件路径读连接级 filepath**。

**响应五类（datatype → 形态，按当前源码核定）**

| 形态 | datatype | 说明 |
|---|---|---|
| 裸 JSON 文本（无前缀） | 0/4/5/6/7/8/9/10/11/14/18/19/20/171 | 首 chunk 后 0.5s 短探 |
| `b"ok"` inline | **15/172/173/175 成功** | 15 恒 ok（unzip 缺失/失败也 ok）；**175 停止成功也是裸 `b"ok"`**；172/173 成功 ok |
| `b"error"` inline | 172/173 未启动/失败 | **裸字节**（回退后契约，非 JSON） |
| inline `b"NN ok"` | 21/22/23/24 | 握手应答 |
| `{"error":...}` JSON | 174 未启动 / 175 未启动或停止失败 / 131 预检失败（带 `[4B i]` 前缀） | |
| `[4B i][gzip JSON]` | 1（含 Go 版 dt16 兜底） | dt1 `wait=false` 时 exec 返回 None → `json.dumps(None)`="null" **仍回 gzip 帧** |
| `[4B i][JSON]` | 131 正常/200 | 长度前缀非 gzip |
| `[8B <Q len][content]` | 3（可选 gzip）/174（必 gzip） | 174 错误时是裸 `{"error":...}`（首字节 `{` 探测分支） |

**服务端全局状态与并发**
- `active_clients`：setup/finish 计数，**覆盖所有 :9000 连接含 MCP 桥空闲池连接**——dt20 的 `>1 拒绝升级` 按此语义。
- `ss`（监听单例）、`boce`/browser：模块级单例，Go 用包级状态 + mutex（§11）。

## 3. agent 侧 datatype 全量清单（逐条对齐 handlers.py do() 当前源码）

| dt | 功能 | 实现要点 |
|---|---|---|
| 0 | pcap 回放 | truthy 校验 pcaps/uplink_iface/downlink_iface；**错误文案固定** `"Missing required parameters: uplink_iface or downlink_iface"`；除 pcaps 外参数全量透传 PcapReplayer；stats JSON 裸文本；内部异常 → `{"status":"error","message":str(e)}` |
| 1 | 命令执行 | exec_cmd_subprocess：shell+str 时 root 剥裸 `sudo `（带选项/空命令不剥，仅 root）；env 清理：**删 LD_LIBRARY_PATH**（保留）+_PYI_*/_MEIPASS 前缀删除（Go 可省，§12）；wait=false → None → **照常回 "null" gzip 帧**；回 `[4B i][gzip {code,stdout,stderr}]` |
| 3 | 文件下载 | 路径读连接级 filepath（payload 仅 gzip）；`[8B <Q][content]` |
| 4 | routeinfo | `route -n` 解析（头 2 行 + zip）；非零退出 → RuntimeError → 断连无响应；route 缺失同理 |
| 5 | 抓包开始 | **回退后契约：`{"res": bool}`**——失败 `{"res": false}` 无 error（1.7.2 error 通道已随 f13b65d 删除）；eth 空 → routeinfo() 取默认路由网卡（**route -n 失败 → RuntimeError 冒泡断连无响应；仅成功但无 Iface 才 false**）；同 path 先停旧；清旧文件失败仅 warn；**启动稳定窗：就绪信号 poll(10) 超时判失败；就绪后 0.5s 内查 _exc(ENETDOWN/ENODEV)/recv 线程存活，不存活 → error → false；失败回收链 stop_evt→join5→terminate→join3** |
| 6 | 抓包停止 | **回退后契约：`{"res": bool}`**——成功 true；从未 start 幂等 true；停止失败 false（join 超时/子进程非零退出）。mcp 客户端四态解析分支保留为兼容死代码 |
| 7/8 | isfile/isdir | `{"file"/"dir": path}` → `{"res":bool}` |
| 9 | mkdir | `{"res":null}` |
| 10 | 改 MTU | ifconfig 解析（新旧两格式）；值不等则设置后 sleep 5；ifconfig 缺失 → RuntimeError；**成功回 `{"res":null}`**（mtu() 无返回值） |
| 11 | 取字节数 | `{"res":size}` |
| 14 | 版本 | `json.dumps(VERSION)` 带引号 |
| 15 | 解压 zip | list args 防注入；**成功/失败/unzip 缺失一律 `b"ok"`** |
| 16 | python_cmd | Go 不复刻：回 `[4B i][gzip {"error":...}]`（§1） |
| 18 | ensure_command | which → `{"res":bool}`（带 install_cmd 时装后再查） |
| 19 | 版本详情 | version/repo/release_notes/latest_version/has_upgrade；Go 版 release_notes 编译期注入，`has_upgrade = (注入版本 != VERSION)`（恒 false，§12 验收标注） |
| 20 | 升级落地 | **归一化前置：version `str(...or"").strip().lstrip("v")`、sha `strip().lower()`（v 前缀/空白版本接受，缺失→空串→`{"error"}` 非断连）**；正则 `^\d+(\.\d+){1,3}$` + 64hex；autoupgrade=off 拒（实时读旧文件）；升级锁互斥；active_clients>1（含空闲池连接）且非 force 拒；同步落盘（staging sha 校验→chmod 755→replace→清 staging）→ `{"ok":true,"version":...}`；后台 0.3s 后 switch_to（原子软链+重启） |
| 131 | 拨测 | chromium 预检：不存在→自动下载 npmmirror（失败回 `[4B i][{"error":...}]`）；自检 stderr 含 `cannot open shared object file` 才装依赖（yum/apt 二选一；无包管理器只 log 继续；装后复测失败回 `[4B i][{"error": stderr[:200]}]`）；boce() 运行时异常**冒泡 → 断连无响应**；正常回 `[4B i][json]`。拨测细节见 boce 段 |
| 171 | 监听启动 | **成功契约 = "端口被任何人持有"**：ss 存活→跳过；ss 死→重启；无 ss→新建启动（start_server 吞异常返回 None）；**无条件回 `{"pid":[ss输出解析]}`，可为 `[]`**（bind 失败也回空列表不报错——回退后"换端口静默忽略"语义）。pid 来源 `ss -lptn` 解析 |
| 172/173 | 清数据/保存 | 判活 `ss and ss.pid()`；未启动 → **裸 `b"error"`**；成功 `b"ok"`；173 payload `{"file":...}`（缺键 → 异常断连）。172 成功语义 = cleandata 排空完成（见 listen 段） |
| 174 | 监听取流 | **判活仅 `ss is None`**（对象在但监听死 → 照常回 `gzip(ss.data)` 流，非 error——quirk；内容是**全量累积流**，抓过流量后非空）；正常 `[8B <Q][gzip(ss.data)][content]` |
| 175 | 监听停止 | ss 为 None → `{"error":"未启动监听"}`；stop_server（terminate→join3→kill 链 + **对端口残留者逐个 `kill -9` 清扫**）后 3 轮：先查 `ss.pid()` 有 pid 才 sleep 0.5；**轮询后 `ss = None` 无条件执行（成功失败都清）**；成功 `b"ok"`；仍活 → `{"error":"停止监听失败，端口仍被占用"}` |
| 200 | pcap 五元组 | **输出全部是字符串**：srcPort/destPort/protoType 均为 str（ICMP 端口 `"0"`；protoType "1"=TCP "2"=UDP "3"=SCTP "4"=ICMP/ICMPv6）；流键 = (ip, port字符串) 元组**字典序** sort + protoType；方向判定：首包默认 → SYN/SYN+ACK 修正 → HTTP 方法列表/`HTTP/1.` 响应行修正，一次锁定；边界：单层 VLAN 无 QinQ、IPv4 不验总长/分片、IPv6 固定 offset 6 不走扩展头；坏 pcap 跳过；`[4B i][JSON]` |

**抓包（capture.py → Go）**：proto=0 创建 → 全部 setsockopt 就位 → 最后 `bind(eth, ETH_P_ALL)`；时间戳四级降级（SO_TIMESTAMPING HW|SW|RAW → RX_SW → SO_TIMESTAMPNS → monotonic；cmsg ts[0]==0 退化 ts[1] + warn 一次）；VLAN 还原（PACKET_AUXDATA；`tci!=0 OR VLAN_VALID`、tpid 默认 0x8100；offset 12 插 4B；**帧 <12B 原样返回护栏**）；SO_RCVBUF 32MB + getsockopt 截断验证；promisc 失败仅 warn；BPF（extended 非空）：exec `tcpdump -ddd` → 首行条数 + 逐行 `code jt jf k` → unix.SockFprog 注入 SO_ATTACH_FILTER（**有意差异，源码为 scapy attach_filter，见 §12#4**；tcpdump 缺失/编译失败 = 抓包启动失败 res:false，agent 主服务不受影响）；停止：置 stop → drain 完队列再退（1s 超时轮）；join 10s 超时不关文件返回 false；tpacket_stats close 前读；落盘后 4 种 magic 识别 + 稳定排序重排（原子 replace）；pcap 写纳秒 magic 0xA1B23C4D、snaplen 65535。**goroutine 长驻循环强制 panic recover**（§12#2）。

**单队列**：ethtool -l 查/`-L combined 1` 缩（**缩后 sleep(3)、绑定后 sleep(2)**）；IRQ 三路查找（**msi_irqs 目录取前 max(count*2,4) 个 → /proc/interrupts 名称匹配（含任意含 "mlx5" 的行）截断 [:count] → grep**）；绑非 0 空闲 CPU（/proc/stat ≥99% 排除 + 已分配集合 + CPU0 保留；**全忙回退选最后一个 CPU；选 CPU 异常回退 CPU1；同网卡已有绑定直接复用不重配**）；禁 RPS/RFS；**全部 best-effort 失败仅 warn**；**运维语义：缩队列/绑 CPU/RPS 改动 stop 不还原，持续生效到下次手动调整**（类 docstring 明示，文档化到部署说明）。

**回放（replayer.py → Go）**：五元组（含 MAC）建流；**方向判定是 `if/elif/else` 链，非级联**：①双 hint 都提供 → 匹配则 uplink/downlink，**失配 → 记 log 并保持默认 uplink（不回退 SYN/反向流！）**；②否则 SYN 包 → uplink；③否则反向流已存在 → 反转；④默认 uplink；`directionless && no_tuple_modification && !force_build_flow` → 不建流直发；对称换向 force_* 改写；IPv4↔IPv6 互转（IP/TCP/UDP/ICMP 校验和重算；SCTP 不动）；VLAN 增改（已有 81 00 只换 TCI）；**非 IPv4/IPv6 以太帧跳过（不发送不计数）；解析失败帧 warn 跳过**；**读侧按 magic 选 ts_divisor（纳秒 magic→1e9，否则 1e6）——判错则限速节奏差 1000 倍**；**截断两态：记录头不完整（1-15B，读在 try 外）→ struct.error → `{"status":"error"}`；记录体截断/解析失败 → 逐帧 warn 跳过**；**跨族转换的 ICMP 分支是半成品（IPv6→IPv4 直接搬 ICMPv6 载荷、校验和不重算、IPv4 头 protocol 写 58；反向写 1）——照抄**；**回放侧 IPv6 同样固定 offset 6 不走扩展头**；AF_PACKET SOCK_RAW 发送（socket 缓存复用；需 root/CAP_NET_RAW）；mbps 每包+全局两级限速；pcap 缓存（微秒 magic 单/双文件）；字节统计 `max(orig_len, 60)`。

**拨测（boce.py → Go）**：封堵 = net/http 并发（UA Chrome/120、allow_redirects=false、200=成功、time 累计）；重定向 = chromedp：**每次 goto 成功后固定 `sleep(3)`**；mode="弹窗"或未知模式每次 run_single 恒判失败（无实现）；判定仅两分支——framenavigated 跳转 URL 集合非空 / request 计数>1（**ERR_TOO_MANY_REDIRECTS 只是 goto 异常分支的日志，不是第三判定条件**）；**重试仅异常含 `"Connection is closed"` 时关 browser 重启重试一次；重试路径首尝仅追加 exceptions/counts 列表、total/fail/time 不增，且最终统计由 run_multiple 从 gather 结果整体覆写（重试调用计一次）**；chromium 启动 11 args 逐项对齐 boce.py:201-213；chromium 自动下载：ensure_chromium **锁外快速路径 + `_browser_lock` 内 double-check**、npmmirror 查最新 revision、/opt/socket/config proxy=、**zip 下载到临时目录、`extractall` 到 /opt/socket（安装根的父目录）——Go `archive/zip` 无路径消毒，必须实现 zip-slip 防护（剥绝对路径/`..`，对齐 Python zipfile 行为）**、chmod 755、失败打印手动步骤；BrowserManager：close 失败也置 None + Go 侧显式 shutdown 钩子关闭 chromedp 上下文（替代 Python atexit）。

**:9001 HTTP 文件服务**：**响应契约：响应头 `Server: socket_server-file/1.8.2`；GET 200 带 `Content-Type: application/octet-stream` + `Content-Disposition: attachment; filename="<basename>"`；错误统一 JSON 体 `{"error": msg}`（400/404/500）；POST 成功体 `{"ok":true,"path":<realpath>,"size":N}`**。GET 流式 1MB 分块 + Content-Length 锁死；POST multipart 流式落盘（path 先到直写 `.part` + 原子 replace；file 先到临时文件后 move——upgrade_run 推 staging 依赖父目录自动 makedirs）；边界复刻：多 file 字段追加写首个句柄且 size 只报最后一段、path 值 4096 上限→400、伪命中分隔集合含 `--`/`\r\n`/裸 `\n`（自定义 reader，§12#8）、缺 path 时 400 发生在 body 全量消费后、realpath 归一化、boundary ≤256；http_port 读 /opt/socket/config（0=关闭，缺省 9001）；双栈 + IPv6 失败降级。

**socket_listen 内部（171-175 底座）**：**默认 port=30001**（dt171 payload 不带 port 时监听 :30001，pid 探测同端口）；host=None 双栈（V6ONLY=1/SO_REUSEADDR/backlog 128）；**每连接一线程收包入共享队列**；cachedata：启动即清 /tmp/socketbin，有数据累积、**队列空闲即整块落 `/tmp/socketbin/<epoch_us>.bin`、1s 轮询**；cleandata：**`while qsize: sleep(1)` 排空等待 + 1s**，清 `ss.data`，`rm -rf /tmp/socketbin/*`（→ dt172 后 dt174 回空流）；stop_server：terminate→join(3)→kill + 端口残留者 kill -9 清扫；start 后 sleep(5) 再验 pid。

**服务化（supervisor/upgrader/autoupgrade → Go）**：路径逐字对齐：`/opt/socket/versions/<v>/socket_server`、`.staging/socket_server`、`current` 原子软链、/opt/socket/config 的 `autoupgrade=`（缺省 on，dt20 前实时读）与 `http_port=`/`proxy=`（§7）。

**serve 启动编排（cli.py cmd_serve 顺序照抄）**：setup_environment → **ensure_unit_correct 自愈（失败仅 warn 不阻断）** → **:9001 先于阻塞的 TCP 主循环启动（整个 :9001 启动失败仅 warn，不影响 :9000——与内部 IPv6 降级是两层兜底）** → TCP 双栈阻塞。setup_environment：日志（显式 > SOCKET_SERVER_LOG > /var/log/socket_server.log；目录缺失跳过文件 handler）、rmem/wmem≥32MB、java：**找到 java 时**PATH 前插 + **硬编码写 `JAVA_HOME=/usr/local/jdk1.8.0_202`（不校验该路径存在；找不到 java 两者均不写）**、防火墙命令组逐条保留；PLAYWRIGHT_BROWSERS_PATH 删除（§12#9）。

## 4. mcp 侧 15 个 MCP 工具

契约基准：参数名/类型/默认值/required/annotations 以 `server.py:262-786` 为逐行对拍契约；表内加粗处为必须逐字复刻的 quirk/回退后契约。

| # | 工具 | dt | 锁 | 危险 | 要点 |
|---|---|---|---|---|---|
| 1 | list_targets | - | - | RO | 空 + note |
| 2 | add_target | - | - | 写 | TCP 探活 3s；force 跳过；剥 IPv6 方括号 |
| 3 | remove_target | - | - | 写 | 活跃锁/活跃监听拒绝；**quirk：锁/liveness/删除键全用原始 host（不剥方括号）——带 `[]` 的 IPv6 删不掉也匹配不到，照抄** |
| 4 | version | 14 | NONE | RO | 字符串版本 |
| 5 | file_transfer | - | - | RO | :9001 curl 指令；host 三形态；IPv6 加方括号 |
| 6 | isfile | 7 | NONE | RO | `{"file": path}` |
| 7 | isdir | 8 | NONE | RO | `{"dir": path}` |
| 8 | pcap_flow_extract | 200 | NONE | RO | >1000 截断 + truncated；flows 为字符串字段（与 §3 dt200 一致） |
| 9 | cmd_exec | 1 | SHELL | DANGER | 白名单前缀；**stdout>64KB 按 65536 字符（str len）截断，非字节**；wait=false → note（"null"→None→B18）；**timeout = wait ? timeout : min(timeout, 15)** |
| 10 | capture_start | 5 | CAPTURE(path) | 写 | 服务端只回 `{"res":bool}`：false 无 error → B23 泛化；error 通道为兼容死代码；锁成功保留到 stop |
| 11 | capture_stop | 6 | CAPTURE | 写 | 服务端 `{"res":bool}` → legacy 映射（true→stopped；false→error 可重试）；四态/failed_details 兼容保留；锁无论成败释放 |
| 12 | boce_run | 131 | BROWSER | 写 | timeout≥10（Go 参数校验等价 pydantic）；socket_timeout=timeout+10；inner=max(3,timeout-10)；服务端 `{"error"}` → 抛错；运行时异常断连 → recv 异常 → failed |
| 13 | replay_run | 0 | REPLAY | 写 | status=error 抛错 |
| 14 | socket_listen | 171-175 | SYSTEM | 写 | save 需 file；未知 action 校验；**start 空 pid → 客户端 raise → target failed（服务端不报错但桥报，跨层行为）**；start 后 dt14 探版本≥1.7.1 登记 liveness；172/173 失败裸 b"error"，`_decode_listen_error` 双兼容照抄；fetch 超 max_bytes 落盘 /home/tmp/listen_<ts>.log + base64 截断；174 首字节 `{` 探测 |
| 15 | upgrade_run | 20 | SYSTEM | DANGER | resolved 空 → 逐 target failed；版本非法/查版失败/下载失败 → target="*"；run_one 预检 dt14≥1.8.0；push_binary（IPv6 方括号）；dt20 error → `_error`；close 归还；轮询 180s/3s（**短连接新建；target 拆分 = `rpartition(":")` + 尾段 isdigit——与 registry 算法不同，`fd00::5` 会被拆成 host="fd00:" port=5，quirk 照抄**）；终态审计 + duration_ms |

通用批量语义（_run_batch）：`{ok, failed:[{target,reason}], results:[{target,...}]}`；results 只含成功项（dict 展开 _wrap、非 dict 包 `result`）、failed 单列；锁顺序 = 先锁后借池，冲突 fail-fast；池借出失败 → 释放已获锁；`{"_error":...}`/False → failed；None → note；审计 outcomes 逐 target + params 截断 200 + duration_ms。

**池/锁/注册表/审计/升级编排契约补充**
- 池：max_conn_per_target=5、idle 600s、borrow 10s、全局并发 50；acquire 超时抛错；过期连接锁外 close；connect 失败回滚 _inuse + notify；不健康连接锁外关闭；复用连接同步 socket_timeout（N8）；Scheduler.session 独占借还。**quirk：upgrade_run close 后以 healthy=True 归还 → 已关闭连接进 idle，下次 acquire 复用死连接首拍必失败一次（Python 实测行为，忠实复刻，升级后首个工具调用失败属预期）**。
- 锁：CAPTURE 按 `(path,)`；capture 与排他互斥；冲突文案由 manager 回填真实 target（B07）；release_target 静默兜底。
- 注册表 resolve：`@tag` 展开、未知静默跳过；**拆分算法 = 第一个冒号后的子串 isdigit 才拆**（`host:9000` 拆、`fd00::5` 因首冒号后含冒号**不拆、原样返回**——v2.1 的"尾段截断 quirk"是误报，已修正）；listen_liveness 列启动时 ALTER TABLE 迁移。
- socket_client：inline ack 0.3s 短探；每次 send/recv 前 settimeout 防 0.5s 泄漏；`_decode_listen_error` 兼容 1.6.x 裸 error。
- upgrades：raw version.py 查版；退避 1h→2h→4h（首败 warning、后续 debug、恢复 info）；ensure_release_binary 幂等复用（sha 校验后 tmp+原子落盘）；每日兜底先睡 24h、绝不自动升级。
- 传输：Streamable HTTP 经 ASGI app 绑定、DNS rebinding 关闭；serverInfo.version = 桥版本 0.4.0。
- 日志：init_server 按配置重设级别；registry/audit 共用 db_path（WAL）。

## 5. 模块结构（Go）

```
cmd/socketstack/          # 入口: (无参)=mcp stdio | mcp serve | agent | serve(=agent 别名)
                          #       install|uninstall | agent|mcp enable|disable|start|stop|status
internal/frame/           # 仅字节层: 常量/读写帧/长度校验（21-24 状态机归 agent，依赖连接级业务状态）
internal/agent/           # server/handlers/netexec/capture/singlequeue/replayer
                          # boce_http/boce_browser/listen/pcapflow/httpfile/upgrade/setup
                          # connstate.go: 连接级状态 + 21-24 状态机
internal/svc/             # systemd 单元 install/uninstall/enable/start/stop/status
                          # agent 单元沿用 socket_server.service（模板与 Python 逐字一致,见 §8）
internal/mcpbridge/       # protocol/pool/locks/registry/audit/upgrades/tools/transport
internal/config/          # 合体 YAML + env 覆盖（唯一配置模块,mcpbridge 不再单列）
```

## 6. 技术选型

- **Go**：go.mod `go 1.24` + `toolchain go1.25.x`（本机 1.21.13 经 auto-toolchain 实测；Release 构建机固定新工具链，auto-toolchain 仅构建期依赖）；CI 验证 `CGO_ENABLED=0`。
- **MCP SDK**：`github.com/modelcontextprotocol/go-sdk v1.8.0`（依赖已核实；Streamable HTTP 路由/超时/客户端兼容性属 §9 集成验证）。
- **`golang.org/x/sys/unix`**：AF_PACKET、Recvmsg+ParseSocketControlMessage（SCM_TIMESTAMPING/PACKET_AUXDATA 内容手写解析）、PACKET_ADD_MEMBERSHIP、SockFprog。权限前提：root 或 CAP_NET_RAW。
- **`github.com/chromedp/chromedp`**：重定向拨测。
- **`modernc.org/sqlite`**（纯 Go）；单写连接 + busy_timeout（§11）。
- YAML `gopkg.in/yaml.v3`。**不引入 golang.org/x/net**（BPF 走 `tcpdump -ddd` exec）。
- zip 解压：`archive/zip` + **自实现 zip-slip 防护**（Python zipfile 自带消毒，Go 没有——chromium 安装路径必须）。
- "已验证"两级：依赖存在性已核实；项目场景集成 = §9 验收。

## 7. 配置与配置源优先级

```yaml
# /etc/socketstack/config.yaml（全部可省略）
agent:
  tcp_port: 9000
  log_file: /var/log/socket_server.log   # env SOCKET_SERVER_LOG > 此键 > 默认
mcp:
  bind: {host: 0.0.0.0, port: 9010}
  db_path: /var/lib/socketstack/mcp.db   # systemd 用绝对路径
  download_dir: /var/lib/socketstack/downloads
  proxy: ""
  log_level: INFO
  default_timeout: 30
  behind_proxy: false
  pool: {max_conn_per_target: 5, idle_timeout: 600, borrow_timeout: 10, max_global_concurrency: 50}
  audit_retention_days: 90
  cmd_exec_whitelist: []
```

**/opt/socket/config（旧键，兼容源）**：`autoupgrade=`/`http_port=`/`proxy=` 由 agent 实时读取，**旧文件对这三键优先**；`socketstack agent autoupgrade on|off` 写回旧文件（对齐 Python）。历史 `port=9000` 键不接线。

env 覆盖（白名单）：`MCP_BIND_HOST/PORT`、`MCP_LOG_LEVEL`（config loader 语义）；`MCP_DEFAULT_TIMEOUT`（socket_client 语义）；`SOCKET_SERVER_LOG`。其余仅 YAML。

**默认路径变更（db_path/download_dir → /var/lib/socketstack）入 §12#11 有意差异。**

## 8. 服务化、安装与升级互操作（v2.2 重点修订）

```
socketstack                    # stdio（本地 MCP 客户端）
socketstack mcp serve          # Streamable HTTP（mcp 单元唯一入口）
socketstack agent              # agent 模式
socketstack serve              # agent 模式别名（升级互操作关键,见下）
socketstack install [--with-mcp] | uninstall
socketstack agent|mcp start|stop|status|enable|disable
socketstack agent autoupgrade on|off
```

**升级互操作（P0 修复）**：Python unit 模板是 `ExecStart={exec_path} serve`（supervisor.py:20），且 ensure_unit_correct 做整文件文本比对。因此：
1. **Go CLI 接受裸 `serve` = agent 别名**——旧 Python unit 直接拉起 Go 二进制不崩。
2. **agent 单元沿用 Python 的 `socket_server.service`，unit 模板与 Python 逐字一致**（Description/ExecStart `... serve`/Restart=always/5s/Environment=PATH 含 sbin——agent 大量依赖 route/ss/ifconfig/unzip/tcpdump/ethtool，systemd 默认 PATH 不够）。
3. **Go 的 ensure_unit_correct 保留 Python 语义**（整文件比对 + 两个早退分支：unit 不存在不创建、current 失效交给 service_enable）——因模板一致，Go↔Python 双向切换/回滚 unit 永不漂移，"双 unit 识别"问题消失。
4. mcp 单元为新增 `socketstack-mcp.service`（ExecStart=`/usr/local/bin/socketstack mcp serve`，Restart=on-failure，WorkingDirectory=/var/lib/socketstack）；install 时检查既有 unit，防双 enabled 抢 :9000。

- **二进制名闭环**：Release 资产对外名 `socket_server`（dt20/staging/final 路径不变）；安装复制为 `/usr/local/bin/socketstack`；agent unit ExecStart = `/opt/socket/versions/current/socket_server serve`（走软链，switch_to 切链即换版）。
- uninstall：保留 /opt/socket/versions、配置与 mcp DB（数据式卸载，删除项明示列出才删）。
- 升级闭环验收（§9）：Go 中央→Go 靶机、Python 中央(0.3.2)→Go 靶机、Go 中央→Python 靶机(1.8.3) 三链；Release 附 `.sha256`。

## 9. 验证策略

1. **协议单测**：net.Pipe 逐帧——§2 全部分支（21 三态含畸形 JSON 立即断连、22 <8B/>8B、24 无前置 AttributeError、EOF、超长帧丢弃、异常断连无响应、未知 dt 无响应、sendall 重试范围）。
2. **mock 对拍（mcp 侧）**：Go mock socket_server 喂 canned 字节；Python socket_client vs Go 客户端逐字节比对。CI。
3. **反向对拍（agent 侧）**：Python test_e2e.py / mcp mock 作 oracle 打 Go agent 不改一行；覆盖全部 dt + 全部 quirk 行；dt4 断连、dt16 错误帧、131 运行时断连、dt22>8B、dt24 无前置单列用例；e2e 中 dt16/dt122 预期失败标注。
4. **深模块差分**：capture/pcapflow/replayer 与 Python 输出逐字段 diff（dt200 字符串类型与字典序；回放 hint 失配不回退用例；ts_divisor 纳秒/微秒限速节奏）；chromedp vs pyppeteer 同跳转样例集；`tcpdump -ddd` 注入匹配验证；multipart LF 结尾容忍；zip-slip 防护用例。
5. **升级闭环**：三链各一轮 + `serve` 别名双向验证（Go 二进制被 Python unit 拉起 / Python 二进制被回滚 unit 拉起）+ 180s 轮询窗口 + 升级后首个调用失败一次的 quirk 验证。
6. **真实 e2e**：15 工具 + agent 全 dt 人工验收；IPv6 靶机路径（Python 客户端 AF_INET-only 基线单独标注）；`go test -race` 全量（ss/boce/browser 单例、池、SQLite 并发写）；跨平台 `go build`/`go vet` 矩阵（linux/amd64·arm64、darwin/amd64·arm64、windows/amd64）。

**验收结果（2026-10-29）**：1-6 全项通过——反向 oracle 38+13（Go/Python 双跑）、15 工具 e2e 双实现、三链升级闭环（Python 1.8.3 ↔ Go 1.9.x）、chromedp 拨测 4 例、AF_PACKET 抓包/回放、chromium 自动下载真机（r1730241 / 536MB）、`-race` 6 包、跨平台矩阵 5 组合。

## 10. 实施顺序（TDD）

```
frame(字节层) → config/svc(含 serve 别名+unit 模板)
→ agent 只读组(14/7/8/9/10/11/18/19/4/200) → :9001 httpfile
→ 文件传输(3/21-24) → 命令(1/15)
→ listen(171-175) → boce(131) → capture(5/6) → replayer(0)
→ 升级(20/upgrader/supervisor)
→ mcpbridge protocol(+mock 对拍) → pool/locks/registry/audit
→ tools(只读→写) → upgrades → transport(stdio/HTTP)
→ 合体 CLI/双单元 → 三链升级闭环 → 真实 e2e → tag v1.9.0
```

## 11. 风险与对策

| 风险 | 对策 |
|---|---|
| 协议 drift（最大） | §9 双向对拍 CI；frame 常量共享；全部 quirk 入用例 |
| AF_PACKET cmsg ABI / 权限 | 真机集成测试；root/CAP_NET_RAW 写进部署文档；32/64 位 ABI + cmsg 截断用例 |
| goroutine panic 拖死 agent | 长驻 goroutine 强制 recover + 状态上报 + stop 可重试 |
| chromedp 语义漂移 | 判定逐条对齐 boce.py + 样例差分；chromium 同源下载 + zip-slip 防护 |
| tcpdump 缺失/表达式差异 | 缺失=抓包启动失败（res:false）；表达式子集文档化 |
| 单例并发（ss/boce/browser） | 包级 mutex + `-race` CI；SQLite 单写连接 + busy_timeout |
| IPv6 | 监听/解析双栈；客户端对拍 Python AF_INET-only 基线单独标注；registry/upgrade_run 两套拆分 quirk 分开复刻 |
| 升级互操作 | `serve` 别名 + unit 模板逐字一致 + 三链闭环 + 自愈语义保留 |
| 时区/时间戳 | 本地时区 time.Now()（对齐 Python），审计/文件名格式逐字对齐 |
| 发行版差异（route/ethtool/net-tools） | routeinfo 失败=断连（对齐）；单队列 best-effort + 改动不还原语义文档化 |
| 旧部署静默变更 | 旧 DB 不覆盖；旧 config 三键兼容 + port= 不接线写进部署文档 |

## 12. 与 Python 版的有意差异清单

| # | 差异 | 理由 / 兼容动作 |
|---|---|---|
| 1 | dt16 不实现，回 `[4B i][gzip {"error"}]` | Go 无解释器 + eval 裸洞；帧形态沿用 dt1，旧中央可解析不挂死；旧 e2e dt16 用例预期失败 |
| 2 | 抓包/监听子进程 → goroutine | GIL 隔离不再需要；故障隔离仍在：长驻 goroutine 强制 recover + 异常上报；stop 语义（drain/超时不关文件）逐条保留 |
| 3 | pyppeteer → chromedp | 判定逐条映射（goto 后 sleep(3)/两分支判定/Connection-is-closed 重试一次且首尝不计数/11 args） |
| 4 | scapy BPF → `tcpdump -ddd` exec | 无纯 Go 编译器；失败=抓包启动失败带原因 |
| 5 | PyInstaller env 清理（_PYI_*/_MEIPASS）删除；LD_LIBRARY_PATH 清理保留 | 前者无 PyInstaller；后者通用污染防护 |
| 6 | release_notes 编译期注入（-ldflags）；has_upgrade 恒 false | dt19 结构不变，验收标注 |
| 7 | 一仓一码，发行版本 1.9.0 起；serverInfo 桥版本 0.4.0 分离 | |
| 8 | multipart 伪命中含裸 `\n`（Go 标准库不容忍） | 自定义 multipart reader 保留 Python 行为；差分用例 |
| 9 | PLAYWRIGHT_BROWSERS_PATH 注入删除 | Go 无 playwright |
| 10 | IPv6 TCP 客户端支持（Python client AF_INET-only） | 有意增强，对拍单独标注；wire 不变 |
| 11 | mcp 默认 db_path/download_dir 改 /var/lib/socketstack 绝对路径 | systemd WorkingDirectory 需要绝对路径；语义不变 |
| 12 | Python 死代码不移植（cache_cpus 族/get_tx_cpu/config_rx_thread_cpus/kill_all_chrome/tcpdump_isrun/PcapStats/PacketBuffer/wait_until 族/_sniff_command） | 全仓无调用点 |
| 13 | upgrade_run 轮询拆分对方括号 IPv6（`[fd00::5]:9000`）剥括号（Python rpartition 保留括号必败） | Go 行为更优；普通裸 v6 的 fd00::5 截断 quirk 仍照抄 |
| 14 | 封堵拨测连接禁 keep-alive 显式配置（Python 靠每请求新 Session） | 语义等价，实现路径不同 |
| 15 | mcp 默认 bind 端口 8080 → **9010**（2026-10-29 用户指定） | MCP_BIND_PORT env 仍可覆盖回任意端口 |
| 16 | dt1 stdout/stderr/encoding 键收编白名单但**值语义接线差异**：Go 恒 PIPE+utf-8（Python 原样传 Popen——encoding=null→bytes→json.dumps TypeError 断连、stdout=null→继承父 fd） | 桥自身 dt1 只发 args/cwd/wait；暴露面仅第三方移植客户端 |
| 17 | boce 弹窗/未知模式**零流量副作用**：Python 判定在 goto 之后（真实导航+耗 timeout+3s），Go 预检模式后秒回 false | 恒失败语义相同；对目标不产生访问流量 |
| 18 | chromedp Navigate 等 load（pyppeteer domcontentloaded）；timeout ctx 覆盖 tab 创建（Python 只罩 goto） | 判定通常不受影响（jumped 先置位）；冷启+小 timeout 时 Go 先败 |
| 19 | chromium_path 变更：Go 关旧建新；Python 忽略变更沿用旧 browser 直至自然死亡 | Go 行为更合理；wire 不可观察（响应形态一致） |
| 20 | 无 atexit 关 browser：Go 进程退出不杀 chromium 子进程，孤儿可能累积 | 运维级；Python boce.py:289-298 atexit 注册（活代码）；必要时加 Pdeathsig |
| 21 | dt171 死实例重启前 `shutdown()` 会 kill -9 端口上的**外来占用者**（Python start_server 不杀、bind 失败回空 pid 列表） | 早期 stop_server 清扫语义的连带效应；仅"死实例+端口被外人占"场景可观察 |
| 22 | dt1 args 为多键 dict 时按 key 排序迭代（Python dict 插入序不可由 JSON 稳定还原） | 单键 dict（真实用法）行为确定且对齐；多键顺序差异属输入病态 |
| 23 | chromium 下载并发：Python `_browser_lock` 串行阻塞；Go 同样阻塞串行 + 等锁 double-check | 语义一致（后到者复用先到者结果），无差异，仅记录实现路径 |
| 24 | zip 解压：Go `unzipInto` 逐条复刻 CPython `zipfile.extractall`（`_extract_member` 源码核对 + python3.9 实测）——路径段过滤 `""`/`.`/`..`（含中间段 `a/../../b.txt`→`a/b.txt`）、绝对路径去首斜杠、目录 0777&~umask、文件恒 0666&~umask（**忽略 external_attr**）；不复刻符号链接条目 | chromium 包内无符号链接（真机安装目录实测 0 个）；主目标另有显式 chmod 755 |
| 25 | mcp HTTP 绑定用 `net.JoinHostPort`（Python uvicorn `host:port` 直拼） | `mcp.bind.host` 配 v6 字面量时 Go 可用、Python 会 "too many colons"；默认 0.0.0.0 无差别 |
| 26 | 回放发送 socket 常驻缓存（`sendSockets`，按 iface 名，加锁）：Python `replay_files` 末尾 `_cleanup_sockets()` 每次回放建/关 | fd 数量按网卡数有界（≤2×N），换来免每次重建；网卡删除重建（ifindex 变化）时会 ENETDOWN，需重启 agent |
| 27 | chromium 并发下载冲突：Python `_browser_lock` 串行；Go 同样阻塞串行 + 锁内 double-check | 语义一致（后到者复用先到者结果） |
| 30 | `no_proxy` 后缀用**标签边界**匹配（`host==e \|\| HasSuffix(host, "."+e)`）；Python requests 用裸 `endswith`，故 `no_proxy=mirror.com` 在 Python 会命中 `notmirror.com`，Go 不会 | Go 更接近 curl/wget；Python 的裸后缀匹配本身是缺陷，且真实环境不会配成这种形式 |
| 29 | chromium 代理解析完全自实现（config `proxy=` 优先 → 无 scheme 自动补 `http://` → 环境变量小写优先 → 遵守 `no_proxy`/`NO_PROXY`） | 不用 `http.ProxyFromEnvironment`（其大小写优先级与 requests 不同，且无法在前面插入 config 覆盖）；no_proxy 语义有 6 组单测守护 |
| 28 | 首字节后 body 停摆按 requests 语义处理：Go 在 dial 时给 conn 包 `readDeadlineConn`（每次 Read 前重设 deadline），等效 requests 的 read timeout；**不是**总传输时限 | 36MB 目录列表/500MB zip 在慢链路上必须能传完 |
