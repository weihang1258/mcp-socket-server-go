# 代码审查复核（第二轮·2026-11-25）

对象：v1.9.26 基线，`internal/agent` + `internal/mcpbridge` + `cmd/socketstack`
方法：逐项回到代码原文验证；凡能真机验证的都在 82 上跑过；DPI 功能缺口用「设备实际状态文件清单 vs 桥侧支持清单」对比

---

## 一、复核结论速览

| 项 | 结论 |
|---|---|
| 上轮 22 项发现 | **19 项确认为真问题**，3 项结论需要修正（见第二节） |
| 修复方案 | **4 项需要替换成更优解**（见第三节） |
| 新增发现 | **9 项**（第四节），其中 2 项达到 P1 |
| DPI 功能缺口 | stat 文件覆盖 **23/76**；`clean_stat` 未实现；IP 库/方向判定未实现 |

---

## 二、上轮结论的修正（重要）

### 修正 1：P2-4 的 CPU 编号说错了 —— 实际是 CPU1，不是 CPU7

上轮我按「busy[0]=true，找不到空闲就取 n-1」推断会算成 CPU7。**在 82 上复刻这段逻辑，实际输出是 CPU1**：

```
代码会绑到 CPU: 1
n(目录数): 8   busy: [0]
进程实际可用: 0
```

原因：循环从 `c=1` 开始，CPU1 不在 busy 里，立刻返回 1。所以 CPU7 只在「1..7 全忙」时才出现。

**问题依然成立且更严重**：代码会把 `1` 写进 `/proc/irq/N/smp_affinity_list`，而本进程 cpuset 只有 `0`。内核要么拒绝要么静默无效，日志却无条件打「将网卡 ens3 的 N 个中断绑定到 CPU1」。**这个日志是错的，会直接把人带偏**。

### 修正 2：P2-5 不是两套版本比较，是三套

| 实现 | 位置 | 语义 |
|---|---|---|
| `parseVer3` / `verLess` / `atLeast` | `mcpbridge/tools.go:399-428` | 只认 `^\d+(\.\d+){1,3}$`，前缀比较 |
| `parseVersionParts` / `compareVersions` | `mcpbridge/dpi_ops.go:702-750` | `[.\-]` 切分，补零到 7 段，带字母权重 |
| `versionLess` | `agent/prune.go:93` | 逐段 `Atoi` 后比长度 |

三处对 `1.9.26-rc1` 会给出三种可能结论。`prune.go` 那个还会把 `rc1` 经 `Atoi` 失败静默变成 0。

### 修正 3：P3-9（dataLen 负值）与 P1-1 是同一个修复，不是独立项

已合并进 P1-1，不再单独计。

---

## 三、修复方案替换（上轮的方案不是最优）

### 方案替换 1：P1-1 的「256MB 上限」会挡住合法上传

上轮建议 256MB。**这是错的**：`dt23/dt24` 上传是「整个压缩文件作为一帧」发的，一个 500MB 的 pcap 压完约 450MB，会被 256MB 直接拒掉。

**更优方案**：

```
帧头解析后先验符号（负数直接断连），再按可用上限校验。
上限取可配置值，默认 2GB —— 覆盖最大合法上传，
同时把"客户端随便报个数就能吃满内存"压到可控范围。
真正的保护不是这个数，而是让 acc 的增长可观测：
超限时断连并记下 dataLen 与实际累计长度，日志能直接指出是谁在灌。
```

如果要做得更准，可以先去读 body 前 4 字节拿 datatype，再按类型分档（dt23/dt24 宽松、其余 16MB）。但这要求改收帧状态机，代价高于收益，默认 2GB 已经够用。

### 方案替换 2：P1-2 不必每次都整文件重排

上轮建议改成两遍流式。**可以更省**：绝大多数抓包本身时间戳就是递增的。

**更优方案**：

```
抓包写入时顺带记一个 isMonotonic 标志（已有 prevTs 可直接比）。
收尾时：
  - 若全程递增 → 完全不排序，省掉整文件读写 + 2 倍内存
  - 若有逆序 → 才走两遍流式（第一遍建偏移表，第二遍按序抄写）
```

实测意义：抓 5 分钟产生 1GB pcap 的常见场景，内存峰值从 2.1GB 降到接近 0，还省掉一次全量磁盘往返。

### 方案替换 3：P1-5 提上限不如直接流式落盘

上轮建议把 1GB 提到 4GB。**这是治标**：桥上仍然把整份内容读进内存再解压。

**更优方案**（协议本来就支持）：

```
dt3 响应格式是 [8B 压缩后长度][压缩内容]，长度先到 —— 桥侧完全可以在
拿到长度后 io.CopyN 到本地文件，边拷边 gunzip，全程不持有完整副本。
```

这样：上限问题消失（长度只是个数字）、内存从 O(文件) 降到 O(缓冲)、解压炸弹也被自然限制（写入量可校验）。改动只落在 `bridge/protocol.go:895-919`。

### 方案替换 4：P2-7 加大超时不如先修 P1-6

30 秒超时的根因是 agent 把整个目录的流全算完再返回。修完 P1-6（agent 侧 20 万条上限 + 早停）后，大多数目录在 30 秒内能返回。**先修根因，再看是否需要调超时**；直接调超时会让慢目录继续吃 CPU。

---

## 四、新增发现（上轮漏掉的）

### N1（P1）agent 侧完全没有写超时

```
grep SetWriteDeadline|SetDeadline internal/agent/  →  0 处
```

`downloadFile` 把整份内容（gzip 后 177MB）一次 `conn.Write(out)` 发出去。如果客户端连上后**不读**（比如测试脚本卡住、或进程被 SIGSTOP）：

- `Write` 阻塞在内核缓冲满
- 该 goroutine 永久持有 367MB 原文 + 177MB 压缩结果 + 177MB 输出副本 ≈ 700MB
- 没有任何东西能把它超时退出

这是「下载慢」那份文档里测到的 3 倍内存放大的**另一半原因**：不是峰值高，是峰值不释放。

**方案**：`handleConn` 里给每条连接设 `SetDeadline`（读写都设，与桥侧 `Timeout` 对齐），或至少给 `sendWithRetry` 设写超时。Python 原版也没有（socketserver 默认无超时），但 Python 进程不会被一条卡住的连接吃掉几百 MB。

### N2（P1）桥侧 4 处 `recvN` 无长度上限

只有 `downloadFile` 有 `1<<30` 保护（`protocol.go:908`）。这四处没有：

| 行 | 函数 |
|---|---|
| 206 | `recvGzipRaw`（dt1 cmd_exec） |
| 237 | `recvLenPrefixedJSON`（dt131 boce） |
| 311 | `recvLenPrefixedArray`（dt200） |
| 596 | `SocketListen fetch`（dt174） |

这四处都直接 `make([]byte, n)`，n 来自对端 4 字节。agent 回包错乱（比如协议错位、上个响应的残留字节被当成长度）时，一次可能申请 4GB。

**方案**：抽一个 `recvNChecked(n, max)`，四处统一走它。

### N3（P2）agent 每帧收满时重新分配整块缓冲

```go
data := acc
acc = make([]byte, 0, len(acc))   // 按上一帧长度重新分配并清零
```

每收满一帧就新分配一块 `len(acc)` 大小的内存。大帧（dt24 上传）时同帧存在两份完整副本。

**方案**：`acc = acc[:0]` 复用同一块底层数组（`data` 在 `processFrame` 返回前不会被覆盖，入参是只读的）。

### N4（P2）`listen` 的数据无上限累积

`listenInstance.data` 由 `appendData` 无界追加，只在 `listenClean` / `listenSave` 时清。Python 原版同样无上限（`self.data += ...`），所以是保真差异，但现场跑长连接收流时会吃内存。

**方案**：加一个可配置上限（默认 256MB），超限时停止 append 并记一次 warn，避免静默吃满。

### N5（P2）`replayer` 回放时整文件读入内存

`replayer.go:667 os.ReadFile(path)`。回放 1GB pcap 需要 1GB 常驻内存，且回放期间一直持有。

**方案**：`os.Open` + 逐记录读取（协议结构简单，`[16B 记录头][data]` 顺序读即可），把内存降到单包大小。

### N6（P2）`cleanEnv` 原地复用调用方的切片

```go
func cleanEnv(environ []string) []string {
	out := environ[:0]       // 复用底层数组，原地覆盖
    ...
}
```

当前三个调用点传的都是 `os.Environ()` 的新切片，**暂时安全**。但函数签名看起来是纯函数，任何一处改成传共享切片就会踩到。

**方案**：`out := make([]string, 0, len(environ))`，一个字的改动消除隐患。

### N7（P3）`frame.Read` / `frame.ReadRaw` 是死代码

全仓只有 `protocol_test.go` 用 `frame.Read`，生产路径走 `Encode`/`EncodeRaw`。

**方案**：要么让测试改用内部判定，要么留着但在注释里写明「仅测试使用」。

### N8（P3）`stripSudoPrefix` 自身不判 root

两个调用点都先判了 `os.Geteuid() == 0`，所以行为正确。但函数注释写「root 时剥」，实际是「调用方保证 root 时才剥」，把判定放到函数里更稳。

### N9（P3）`setupMachineEffectsImpl` 关防火墙/SELinux

与 Python 原版一致（`__init__.py:140`），但这是**整机副作用**：`systemctl stop firewalld`、`iptables -F`、`setenforce 0`。在别人的测试机上跑一次 agent 就会把防火墙清掉，且日志只有一行命令回显。

不算 bug（保真要求），但值得在 `dpi_get_info` 或启动日志里显式标一句「已关闭本机防火墙」，让人知道发生了什么。

---

## 五、DPI 功能缺口盘点（用户要求的部分）

### 5.1 状态文件：设备 76 个，桥侧支持 23 个

82 的 `/dev/shm/xsa/` 下实际有 **76 个 .stat 文件**，桥侧 `statKinds` 只认 23 种。

已覆盖：
```
xrt xrtinfo port_for_snmp httpxdr xdrtxtlog xdrtxtlog2 eublock proto_app(proto.app)
flow eu_urlnode eu_restore eu_policy adms_idc_debug eu_output mirrorvlan pcapdump
uploadfile msgtask datarpt datarpt_conn commem marex(4份) time_main
```

**未覆盖、但现场明显有用**（按价值排序）：

| stat 文件 | 内容 | 为什么值得接 |
|---|---|---|
| `tcpsegment.stat` | `overtm_cnt` `seqrst_cnt` `cache_cnt` `blkmem_cnt` — 分段重组、乱序、超时 | 判断分流侧是否在重组报文，直接关系到抓包比对 |
| `ring.stat` / `ext_xrt.stat` | 每端口 `IO-WK fails` `TX fails` `RX missed` `RX errors` | **丢包的硬件侧证据**；现在只能从 xrt 间接看 |
| `malicious.stat` | `flow_cnt` `pkt_cnt` `detect_cnt` `mpm/spm/pcre` `block_cnt` `flood_cnt` | 恶意流量检测的分项计数，现在完全没有出口 |
| `evilblock.stat` | 11 个 `evilblk_sts_*` 状态：rst_encap_fail / 302_pkt_encap / need_drop / match_yes… | 封堵失败时能直接看是哪一步失败 |
| `proto.public.stat` | 每协议的 `up_pkts/dn_pkts/up_bytes/dn_bytes/flows` | **现成的方向统计**（up/dn 已经分好了），和用户要的「入向/出向」直接对应 |
| `proto.stat` / `proto.rule.stat` / `proto_ctrl.stat` | 协议库 insert/update/find_ok | 协议识别命中率 |
| `mirrorvlan_limit.stat` | 每 VLAN 的 `active/limit/reject` | 镜像 VLAN 被限流的证据 |
| `pcapdump_storage.stat` | `CommandId / StorageAmount / IDC_HouseID / DeviceID` | pcapdump 落盘归属，与 house 概念直接相关 |
| `eu_overseaip.stat` | `dns_no_overseaip` `vpnblock_no_overseaip` 等 | **跨境判定失败计数**，和 overseaip_ipsegs 配套 |
| `sysinfo.stat` | CPU 线程分配（io/wk/fo/ot/mast） | 判断 DPI 是否按预期分核 |
| `updown.stat` / `flow_filter.stat` / `event.stat` | 当前为空，但结构存在 | 预留 |
| `dnsxdr` `ftpxdr` `mailxdr` `httpproto` `idfy` `xdrud3` `xdr_background` `xdrtxtlog_size` `uploadfile_size` `memreport` `dpdk_mem` `sysinfoflowcommempool` `marex_*`(另 12 份) `malicious_*`(另 8 份) | 各协议 XDR / 资源占用 | 按需 |

**方案**（最小改动、可扩展）：

```
在 statKinds 增加一个 kind = "raw_text"：
  - 不做结构化解析，直接把文件内容按「行号 + 原文」返回
  - 配 path 参数即可读任意 .stat
  - 再为上面价值最高的 10 个补结构化 kind（tcpsegment / ring / malicious /
    evilblock / proto_public / mirrorvlan_limit / pcapdump_storage /
    eu_overseaip / sysinfo / ext_xrt）
```

这样既有「任意文件可读」的兜底，又对常用文件给出可查询的字段。不需要改 agent 协议（都走 dt1 `cat`）。

### 5.2 `clean_stat` 未实现

Python `device/dpi.py:190`：

```
/opt/dpi/cmdmsg xsa 1    → 清空 DPI 状态
等 flow.stat concurrent_cnt 降为 0
校验 xrt.stat total == 0，最多重试 3 轮
```

桥侧没有任何对应工具。目前只能用 `shell_exec` 拼命令 + `dpi_wait_stat` 手工做，容易漏掉「重试 3 轮」和「xrt 收包数归零」这两个判定。

**方案**：新增 `dpi_clean_stat`，作为上面两件事的编排（复用 `dpi_wait_stat` 的轮询逻辑）。

### 5.3 `wait_flow_timeout` / `wait_pcapdump_writeover` / `wait_socket_*` 的实际覆盖情况

逐项验证（这是上轮没做的）：

| Python 方法 | 桥侧能否做到 | 怎么做 |
|---|---|---|
| `wait_flow_timeout` 等 `concurrent_cnt`=0 | **能** | `dpi_wait_stat kind=flow field=all.concurrent_cnt value=0`（flow 是 kv 模式，`parseKV` 产出单行 `all`，字段可直接取） |
| `wait_pcapdump_writeover` 等 awk `$10`=0 | **能（近似）** | `pcapdump` 是 block 模式，`$10` 对应 `marex_amt_loss`；用 `dpi_wait_stat field=all.marex_amt_loss`。**但需要注意 pcapdump.stat 有两个表块**，字段名要按第一块的表头取 |
| `wait_socket_fopen` | **能** | `dpi_wait_file source=datarpt mode=open`（已实现，含基线处理） |
| `wait_socket_fclose` | **能** | `dpi_wait_file source=datarpt mode=close`（已实现） |
| `clean_stat` | **不能** | 见 5.2 |

结论：三个 wait 已能用现有工具凑出来，只有 `clean_stat` 是真缺口。

### 5.4 机房 IP 库 + 方向判定（用户明确要求的）

上轮只给了设计，没有落到「到底缺哪些函数」。补齐如下。

#### 现状：概念已经在设备上，但没有出口

```
house_ipsegs.txt   1000|90134|20.1.1.1|20.255.255.254        ← 机房段（含 IPv6）
overseaip_ipsegs.txt 108.138.7.71|108.138.7.71|跨境|测试1    ← 跨境段
zcip_ipsegs.txt    172.31.139.140                           ← 裸 IP
pcip_ipsegs.txt    （82 上为空）
```

`house_ipsegs.txt` 第一行的第 2 列（`houseid_inner`）就是 pcapdump 用例里 `hid=` 的来源。**「机房」在业务侧已有权威定义，但没有一处代码用它判断报文方向。**

设备上还有一个更直接的证据：`proto.public.stat` 已经把每个协议的 `up_pkts/dn_pkts/up_bytes/dn_bytes` 分开统计——说明设备内部本来就有方向概念，只是没暴露给上层。

#### 缺失的函数清单

| 缺口 | 说明 |
|---|---|
| IP 段解析 | 4 种格式（house / pcip / oversea / zcip）无解析器 |
| IP → 前缀转换 | `起..止` 区间需转 CIDR 前缀集合 |
| 前缀索引 | 无 radix 树，无 `Contains(addr)` |
| 快照管理 | 无分层、无原子替换、无按 mtime 按需重载 |
| 方向判定 | 无 `(src,dst) → internal/inbound/outbound/external` |
| 与 pcap 流程集成 | `pcap_flow_extract` 返回的五元组不带方向 |

#### 方案（保持上轮设计，补上落地细节）

**分层**：

```
L0 内置保留段（10/8、172.16/12、192.168/16、::1、fc00::/7）
L1 设备文件（house / pcip / oversea / zcip 四份，各自一个 scope）
L2 单次调用附加段（工具参数）
查询时 L2 > L1 > L0 覆盖
```

**复用（用户核心诉求：不要每次转换生成库）**：

```
Snapshot 不可变；加载新版本时构造新 Snapshot，atomic.Pointer 原子替换。
读侧全程无锁 —— pcap 逐包判定是每包一次查询，加锁会是瓶颈。
旧 Snapshot 交给 GC。
持久化到 /var/lib/socketstack/ipdb/<scope>-<sha256>.json，重启直接复用，
文件没变就不重新解析。
```

**查询结构**：IPv4 / IPv6 各一棵 radix 树。**stdlib `net/netip` 就够，不引第三方**——`geoip2` 需要商业 mmdb，`ip2region` 是地理库，都不解决「这个 IP 属不属于我们机房」。

**工具**（两个即可，不做「转换库」这种一次性动作）：

```
ip_db_load   从靶机读 N 份 ipsegs 并重建快照（可指定 scope 子集）
             返回 {loaded_at, scopes:{house:{entries,prefixes,sha256}}, elapsed_ms}

ip_lookup    批量方向判定
             pairs:[{src,dst},...] 上限 1 万对
             返回 [{src,dst,src_in,dst_in,direction}]
```

**两种实现路径**：

| 路径 | 改动 | 优点 | 缺点 |
|---|---|---|---|
| A 桥侧全做 | 读文件走现成 `file_get`(dt3)，解析与查询全在桥侧 | **不改协议、不改 agent**，约 400 行 | 大目录的流要全传回桥 |
| B agent 侧 dt201 | agent 内置 ipdb，dt200 直接返回方向 | 五元组传输量不变，方向就地算 | 多一个 datatype + agent 代码 |

建议先做 A。理由：`pcap_flow_extract` 目前已经把全量流传回桥（P1-6 修完会截断），桥侧后处理加三个字段零成本；而 B 的价值要等大目录场景出现后才体现。

#### 唯一不确定项（需要业务答复）

`darea` 的 `1/2/3` 在 `marex_helper.py` 里对应 **信安 / 数安 / 网安**，XDR 名叫 `PCAPDUMP_IS / DS / NS`。这看起来是**业务域**，不是方向。用户说的「入向/出向」若与 IS/DS/NS 是同一套维度，需要给出映射；若不是，IP 库就只做「机房内外四态」，映射层留空。

---

## 六、按严重度重排后的最终清单

| 级别 | 项 | 变化 |
|---|---|---|
| P1 | P1-1 帧长上限（方案已换） | 方案替换 |
| P1 | P1-2 排序内存（方案已换） | 方案替换 |
| P1 | P1-3 停止失败仍删登记 | 确认 |
| P1 | P1-4 句柄双关 | 确认（概率低但后果重） |
| P1 | P1-5 下载内存（方案已换） | 方案替换 |
| P1 | P1-6 dt200 无上限 | 确认 |
| **P1** | **N1 agent 无写超时** | **新增** |
| **P1** | **N2 桥侧 4 处 recvN 无上限** | **新增** |
| P2 | P2-1 下载错误被吞 | 确认 |
| P2 | P2-2 关闭错误未查 | 确认 |
| P2 | P2-3 CPU 绑定不释放 | 确认 |
| P2 | P2-4 选核错（**CPU1 而非 CPU7**） | **结论修正** |
| P2 | P2-5 版本比较（**三套**） | **结论修正** |
| P2 | P2-6 文件锁未落地 | 确认 |
| P2 | P2-7 dt200 超时（先修 P1-6） | 方案替换 |
| **P2** | **N3 每帧重分配缓冲** | **新增** |
| **P2** | **N4 listen 无上限** | **新增** |
| **P2** | **N5 replayer 整文件读** | **新增** |
| **P2** | **N6 cleanEnv 原地复用** | **新增** |
| P3 | P3-1~P3-8 + N7/N8/N9 | 确认 + 新增 |

功能缺口：
- stat 覆盖 23/76（含 `raw_text` 兜底 + 10 个结构化）
- `clean_stat` 未实现
- IP 库 / 方向判定未实现（设计见 5.4）

---

## 七、仍然没做完的部分

- `boce*.go`（chromium 拨测）整体未审
- `cmd/socketstack/wire.go` 的 install / uninstall 之外的分支未审
- `internal/mcpbridge/dpi_ops.go` 的 FTP 下载路径（780-905）只做了结构扫描
- 所有结论为静态阅读 + 定点真机验证，**未跑压测**；N1/N3/N5 的内存数字是按代码结构推算，未实测
