# DPI 可集成能力分析：机房 IP 段 → IP 库 + 方向判定（2026-11-25）

## 一、先看清楚现场已有的「IP 段」资产

靶机 `/opt/dpi/xsaconf/rule/` 下共 4 份 IP 段文件，格式各不相同（82 实测）：

| 文件 | 格式 | 实测样例 | 用途 |
|---|---|---|---|
| `house_ipsegs.txt` | `houseid\|innerid\|起\|止`，IPv4 与 IPv6 混写 | `1000\|90134\|20.1.1.1\|20.255.255.254` | 机房内（house）IP 段 |
| `pcip_ipsegs.txt` | 同 house 格式，但 82 上是空文件 | — | 专线/客户 IP |
| `overseaip_ipsegs.txt` | `起\|止\|类别\|备注` | `108.138.7.71\|108.138.7.71\|跨境\|测试1` | 跨境判定 |
| `zcip_ipsegs.txt` | 裸 IP 每行一个 | `172.31.139.140` | 专线出口 |

`house_ipsegs.txt` 95 行左右（现场实测 13 行，含注释头 + `//POLICY_FILE_END`）。
真实生产规模未知，从策略交换中心（172.31.138.184）取不到该文件（路径不存在，说明它们不是 DPI 设备）。

**关键**：`house_ipsegs.txt` 第一行的 `houseid / houseid_inner` 就是 pcapdump 用例在
`business/pcapdump.py:212` 用 `awk -F '|' '{print $2}'` 取出来填 `hid=` 的那个值。
也就是说「机房」这个概念在业务里已经有权威定义，只是目前**没有任何代码用它判断报文方向**。

---

## 二、用户要的能力拆解

> 支持输入参数源 ip 和目的 ip 来判断入向出向还是全在机房内或者全在机房 ip 外

即：给定 (srcIP, dstIP)，输出 4 个状态之一：

| 状态 | src 在机房 | dst 在机房 | 业务含义 |
|---|---|---|---|
| `internal` | 是 | 是 | 机房内互访 |
| `outbound`（出向） | 是 | 否 | 机房 → 外部 |
| `inbound`（入向） | 否 | 是 | 外部 → 机房 |
| `external` | 否 | 否 | 全在机房外 |

这正好对应 DPI 策略里的 `darea`（1 信安 / 2 数安 / 3 网安）与 `way`（12/13/14）分类，
以及测试侧 `PCAPDUMP_IS / PCAPDUMP_DS / PCAPDUMP_NS`（IS=Internal-?、DS=?、NS=?）。

> **需要用户确认**：IS/DS/NS 三个缩写的准确展开。从 `marex_helper.py:70-78` 看，
> `IS`/`DS`/`NS` 与 `darea=1/2/3`（信安/数安/网安）绑定，**不是**方向缩写。
> 如果用户说的「入向/出向」是另一套维度，需要给出对应关系，否则这套库只能算「机房内外」，
> 不能直接映射到 darea。

---

## 三、复用设计（避免每次转换生成 IP 库）

用户的核心诉求是「分层加载 + 随时重复加载更新 + 查询走内存」。

### 3.1 数据结构：两级索引 + 前缀树

不要每次转换都生成文件。设计成：

```
          ┌────────────────────────────────────────┐
          │  ipdb.Manager（进程级单例，RWMutex）     │
          │  atomic.Pointer[Snapshot]  ← 读无锁     │
          └────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
    scope "house"    scope "oversea"   scope "zcip"
    (IPv4 树)         (IPv4 树)         (IPv4 树)
    (IPv6 树)         (IPv6 树)         (IPv6 树)
```

**Snapshot 不可变**：加载新版本时构造全新 Snapshot，原子替换指针。
读侧全是无锁读；旧 Snapshot 由 GC 回收。这样「随时重复加载」零停机、零读写竞争。

**查询结构**：每个 scope 两个 `netipx` 风格的 radix 树（IPv4 一棵、IPv6 一棵）。
不用 `net.IPNet` 线性扫描 —— `/24` 级别几千条线性扫一遍是微秒级，
但 pcap 逐包判定是**每包一次**，百万包 = 一分钟。radix 树单次查询 O(32) / O(128)，纳秒级。

区间转前缀：`起..止` 用「区间 → CIDR 集合」的标准算法（`rangeToPrefixes`），
一个 `1.2.0.0-1.2.255.255` 段天然就是 `1.2.0.0/16`；跨非对齐边界时拆成 ≤ 32 个前缀。
这是纯函数，可单测，**不需要任何外部库**（stdlib `net/netip` 足够）。

### 3.2 分层加载（用户明确要求的「分层」）

三层，各层来源不同、失效策略不同：

| 层 | 来源 | 何时重载 | 变更频率 |
|---|---|---|---|
| L0 静态 | 打包进二进制的内置段（可选，如 `10.0.0.0/8`、`192.168.0.0/16` 内网保留段） | 永不 | 随版本 |
| L1 设备文件 | 从靶机读 `house_ipsegs.txt` 等 4 个文件 | 手动 `ipdb_load`，或按 `file_stat` 的 mtime 判定（见 3.4） | 每次策略下发 |
| L2 临时覆盖 | 工具参数里直接给的额外段 | 单次调用生效 | 临时 |

查询时按 scope 分别查，覆盖关系用「L1 覆盖 L0、L2 覆盖 L1」。

### 3.3 查询接口（对 MCP 暴露什么）

**不要**做成一个「转换 IP 库」的工具 —— 那是浪费，用户明确说了不要每次生成。
做成两个工具：

```
1. ip_db_load       重新从靶机读 N 份 ipsegs 文件并重建内存库（可指定 scope 子集）
   targets, scopes: ["house","oversea","zcip","pcip"], reload: bool
   → {loaded_at, scopes:{house:{entries, prefixes, sha256}, ...}, elapsed_ms}

2. ip_lookup        批量判定方向
   targets, scopes: ["house"]（默认只 house）, pairs: [{src,dst}, ...] 或
   srcs: [...], dsts: [...]（同下标配对）
   → [{src, dst, src_in: bool, dst_in: bool, direction: "internal"|"inbound"|"outbound"|"external"},
       ...]
```

`pairs` 上限建议 10000，超出分批。查询纯内存，10k 对 < 1 ms。

### 3.4 「随时可以执行重复加载来更新库」

三个触发入口，都要有：

1. **显式**：`ip_db_load` 工具（用户/agent 主动调）
2. **隐式按需**：`ip_lookup` 发现 mtime 变了 → 自动重载一次（读 4 个文件的 mtime，`file_stat` 已有 `size_bytes`，但**没有 mtime**，需要扩 `dt25` 或复用 `cmd_exec` `stat -c %Y`；见下方「需补的协议」）
3. **定时**：桥侧后台 goroutine，每 N 分钟（默认 0 = 关闭）重新读一遍。**不建议默认开**，因为 DPI 设备上 `cat /dev/shm/xsa/*.stat` 已经很频繁，再加一个后台任务会干扰时序敏感的测试。

### 3.5 与现有 pcap 流程的集成点（这才是价值所在）

现在 `pcap_extract_flows`（dt200）只返回五元组，**没有方向/机房内外**。
两个落点：

**A. agent 侧扩展 dt200（推荐）**
`extractPcapFlowFiveTuples` 已有完整 IP，加一个可选的 scopes 参数，
在 `flowJSON` 里补 `src_in` / `dst_in` / `direction` 三个字段。
好处：一次传输解决，不用拿几千条流回来再逐条查。
代价：agent 侧要加载 IP 库（读设备文件，无新增协议）。

**B. 桥侧后处理（零协议改动）**
`pcap_flow_extract` 返回后，桥侧拿到 `flows` 数组，本地查库补字段。
好处：不动 agent、不动协议、改动最小。
代价：桥侧要能读到设备文件 —— 但桥侧是**中央节点**，没有设备的 ipsegs 文件。
所以这条路要求 ip_db_load 先把库缓存到桥侧本地（`/var/lib/socketstack/ipdb/<sha>.json`），
查询全在桥侧内存里做。这条路的**复用价值更高**：一次 load，之后所有工具的 flow 结果都能带方向。

**C. pcapdump 对比时不要求方向**
别把方向强制塞进 `compare_pcap` 等价逻辑 —— 用户已经说明「业务上会抓包进行对比」，
对比是按流粒度做的，方向判定是附加信息，不能影响比对结论。

### 3.6 文件格式解析（4 种，都要支持）

```go
// house / pcip
// 1000|90134|20.1.1.1|20.255.255.254
// 跳过: 以 # 或 // 开头、空行、//POLICY_FILE_END
type hostSeg struct{ houseID, innerID int; lo, hi netip.Addr }

// oversea
// 108.138.7.71|108.138.7.71|跨境|测试1
type overseaSeg struct{ lo, hi netip.Addr; cat, note string }

// zcip
// 172.31.139.140       ← 单 IP，无区间
```

IPv6 在 house 里是**全 0 展开**的（`2E02:0000:...:0000`），`netip.ParseAddr` 直接支持。
注意样例里有 `0000:...:2000 - 0000:...:20FF` 这种取末字节区间的，也要按区间算法拆前缀。

### 3.7 为什么不用现成库

- `oschwald/geoip2-golang`：需要 `.mmdb` 商业库，与现场 ipsegs 文本无关，且 CGO/大文件依赖
- `lionsoul2014/ip2region`：地理定位库，不是「机房段集合」，判不了「这个 IP 属于我们机房」
- `netaddr` 类：**stdlib `net/netip` + `Prefix.Contains` 完全够用**，radix 树自己写 80 行即可

ponytail 原则：先 stdlib，不引入依赖。

---

## 四、需要补的协议能力

| 需求 | 现状 | 建议 |
|---|---|---|
| 读文件 mtime | `file_stat` 只有 `exists/is_dir/size_bytes` | 扩 `dt25`（新增）或在 `file_stat` 里加 `mtime_unix`（需新 datatype，因为 isfile/isdir/getsize 都是无 mtime 的老接口） |
| 一次读多个文件 | 现在是 4 次 dt3 下载 | 可以接受（文件都几 KB），不必新增批量读 |
| agent 侧加载库 | 无 | 新增 datatype（建议 `dt201`，避开已占用的 0/1/3-11/14-20/131/171-175/200） |
| 桥侧缓存库 | 无 | 复用 SQLite（`bridge.go` 的 Registry 已有 `sql.DB`），建 `ipdb_snapshots` 表 |

如果不想动协议，**最小可落地版本**：

- 桥侧独立实现「读 ipsegs 文件」：用现成的 `file_get`（dt3）把 4 个文件拉到桥本地
  → 解析成 Snapshot → 内存缓存
- 全部方向判定在桥侧做，agent 一行代码不改
- 新增 2 个工具：`ip_db_load` / `ip_lookup`
- `pcap_flow_extract` 后端补方向字段（桥侧后处理）

这条路 **0 协议改动、0 agent 改动**，纯新增 mcpbridge 代码约 400 行 + 测试 300 行。
若要 agent 侧原生方向（好处是大目录不必把流传回来），再加 dt201，约多 200 行。

---

## 五、实施步骤（建议按此顺序）

**S1 纯解析层（可独立验收）**
- `internal/ipdb/segment.go`：4 种格式解析 + `rangeToPrefixes`
- `internal/ipdb/snapshot.go`：IPv4/IPv6 radix 树、`Contains(addr)`、原子替换
- 单测：区间转换边界（跨 /24、单 IP、IPv6 全 0 展开、注释行跳过）

**S2 加载层**
- `internal/ipdb/manager.go`：`Load(paths map[scope]remotePath)` → 走 `Client.downloadFile`
- 持久化到 `/var/lib/socketstack/ipdb/<scope>-<sha>.json`（快照，重启可复用）
- `ip_db_load` 工具

**S3 查询层**
- `ip_lookup` 工具：pairs → 四态
- 批量上限、分批保护

**S4 与 pcap 流程集成**
- `pcap_flow_extract` 结果补 `src_in/dst_in/direction`
- 保持 `compare_pcap` 不受影响（方向只作为附加字段）

**S5（可选）agent 侧 dt201**
- agent 内置 ipdb + dt200 直接返回方向，省一次传输

---

## 六、验收方式（真机）

用 82 现成的 `house_ipsegs.txt`（13 行，含 `20.1.1.1-20.255.255.254`、`192.168.1.1`、IPv6 段）：

```
ip_db_load  scopes=["house","oversea"]
ip_lookup   pairs=[
  {src:"20.1.1.2",   dst:"8.8.8.8"},        // 期望 outbound
  {src:"8.8.8.8",    dst:"20.1.1.2"},       // 期望 inbound
  {src:"20.1.1.2",   dst:"192.168.1.1"},    // 期望 internal
  {src:"8.8.8.8",    dst:"1.1.1.1"},        // 期望 external
  {src:"2E02:0000:...:0001", dst:"20.1.1.2"} // 期望 inbound（IPv6 源在机房）
]
```

再加一条**重载一致性**验收：改 `house_ipsegs.txt` 增删一行 → `ip_db_load` → 同一对 IP
判定跟着变，且 sha256 变了。

---

## 七、风险与取舍

| 风险 | 说明 | 取舍 |
|---|---|---|
| `house_ipsegs.txt` 的生产规模未知 | 现场只有 13 行样例。若上万行，radix 树仍纳秒级，加载几百毫秒 | 可接受 |
| 「全是 0 的 IPv6」写法 | `0000:...:2000` 实际是 `::2000`，区间拆前缀要正确 | 单测覆盖 |
| darea(IS/DS/NS) 与「入向/出向」是否同义 | **未确认**，需用户答复 | 先只做机房内外四态，映射层留接口 |
| 桥侧缓存与设备侧不一致 | 设备改了文件而桥没重载 → 判定用旧库 | `ip_lookup` 默认按需校验 mtime，可关 |
| 每台设备 4 份文件 × N 台 | 内存 × N，每份几 KB~几 MB | 可接受；大库再加 LRU |

---

## 八、结论

- **能做，且不需要改协议、不需要 agent 改动**（最小版本）
- 分层 + 快照原子替换正好满足「避免每次转换生成库」「随时重复加载更新」
- stdlib `net/netip` + 80 行 radix 树即可，**不引入任何第三方依赖**
- 与现有 pcap 流程的接点是「桥侧后处理补方向」，不污染 `compare_pcap` 语义
- 唯一阻塞点：**IS/DS/NS 与入向/出向的映射关系需要用户确认**

---

## 九、设计修订（2026-11-25 第二次，用户拍板）

接口从「scope 名称」改为「路径直给」，删掉名称→路径映射层：

```
ip_db_load
  targets: 靶机
  paths:   段文件路径数组，缺省 ["/opt/dpi/xsaconf/rule/house_ipsegs.txt"]
  → { libs: { "<路径>": {entries, prefixes, sha256, loaded_at} } }
  重复调用即刷新；sha256 没变的文件跳过重建

ip_lookup
  lib:   库路径（缺省 = 默认路径那个库）
  pairs: [{src, dst}, ...] 上限 1 万对
  → [{src, dst, src_in, dst_in, direction}]
```

要点：
1. **按文件分别建库**：桥内存 `map[路径]*Snapshot`，每份文件一个独立快照，
   原子替换单个库互不影响。判定基准 = `ip_lookup.lib` 指定的那个库。
2. **格式解析不再关联文件名**：一个宽容解析器吃所有格式——每行按 `|` 分列，
   取前两个能 ParseAddr 成功的列作起止（house 列3/4、oversea 列1/2 都能命中）；
   只有一个 IP 列 → 单 IP 段；注释行（#、//、POLICY_FILE_END、空行）跳过。
   用户上传任何自定义段文件都能直接建库，桥侧不用加格式支持。
3. 第四节「需要补的协议」中 dt25/dt201 相关行作废（本修订版 0 协议改动）；
   3.2 节「scope」概念改为「路径」。
