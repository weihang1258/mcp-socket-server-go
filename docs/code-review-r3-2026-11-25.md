# 代码审查第三轮（2026-11-25）

基线：v1.9.27（HEAD `3a5c64a`）
方法：前两轮全部结论逐条回验；新读 `boce*.go`、`upgrades.go` FTP、`transport.go`、`config.go`、`prune.go`；
凡能跑的都跑了（含真机 82）

---

## 零、这一轮最重要的发现：**file_put 已经完全坏了**

```
file_put   → 上传失败: HTTP 400 {"error":"empty body"}     ← 100KB 和 5 字节都这样
file_get   → 正常（同一个 :9001，只是方向不同）
```

**根因**：`tools_file.go:688` 用 `io.Pipe` 做请求体，Go 的 `http.NewRequest` 拿不到长度 →
走 `Transfer-Encoding: chunked`；而 agent 侧 `httpfile.go:369-377` 要求 `Content-Length`，
拿不到就判 `length <= 0` 回 400。

两端都是「对」的，是**契约没对上**：

| 端 | 行为 | 依据 |
|---|---|---|
| 桥 | `io.Pipe` → chunked（无 Length） | 7466f66「工具面 v3」引入 |
| agent | `Length<=0` → 400 empty body | 对齐 Python `http_file.py:289-293` |

对照实测（同一台 82）：

```
curl -F 上传（带 Content-Length）      → {"ok":true,"size":100000}     ✅
curl 模拟 chunked                      → {"error":"empty body"}          ❌
mcp file_put 100KB                     → HTTP 400 empty body             ❌
mcp file_put 5B                        → HTTP 400 empty body             ❌
```

**这解释了为什么前面几轮都没抓到**：`file_put` 是「先传 pcap 再回放/升级」的前置步骤，
一直用测试脚本里的 `curl` 绕过去跑，MCP 工具本身从来没被端到端用过一次。
全仓没有任何覆盖 `httpUpload` 成功路径的测试（只有 `contract_test.go` 里两条常量断言）。

**影响面**（三处都调用 `httpUpload`）：

| 调用 | 工具 | 后果 |
|---|---|---|
| `tools_file.go:279` | `file_put` | **整个工具不可用** |
| `dpi_ops.go:763` ← `uploadLocalFile` | `dpi_prepare_package` | 安装包上传失败 → `dpi_install` / `dpi_upgrade` 全链路断 |
| `dpi_ops.go:977` | 同上（另一个分支） | 同上 |

**最优方案**（二选一，我建议第一个）：

```
方案 A（改桥侧，最小）：既然文件大小事先已知（fi.Size()），直接给
  req.ContentLength = 总长度（head + 文件 + 结尾），并保留 io.Pipe 流式不变。
  三行代码。Content-Length 是事先可算的（head 定长 + fi.Size() + tail 定长），
  完全不需要先读进内存。

方案 B（改 agent 侧，更宽容）：chunked 请求也在长度未知时按块读，
  但这就偏离 Python 契约（Python 明确 length<=0 回 empty body），
  且会破坏「上传大小事先可校验」这一保护。不推荐。
```

顺带修 `P2-2`（agent 侧 `.part` 关盘错误不查）——同一个 POST 路径。

---

## 一、上两轮结论回验

| 项 | 结论 | 备注 |
|---|---|---|
| P1-1 帧长无上限 | ✅ 真 | 方案见下（已在 r2 换过） |
| P1-2 排序双倍内存 | ✅ 真 | r2 的 `isMonotonic` 方案**可行**：`captureRecvLoop` 每帧都算 `deadline`，加个 `prevTs` 比较即可，不需要新状态 |
| P1-3 停止失败仍删登记 | ✅ 真 | 已实测路径 |
| P1-4 句柄双关 | ✅ 真（概率低） | |
| P1-5 下载内存 | ✅ 真 | 但**影响面比想象的窄**：只有 DPI 配置读取（`readFileB64`）走 dt3；`file_get` 走 :9001 是流式的。所以 r2 的「改流式落盘」意义在于防炸，不在提速 |
| P1-6 dt200 无上限 | ✅ 真 | |
| P2-1 下载错误被吞 | ✅ 真 | |
| P2-2 关闭错误未查 | ✅ 真 | 与 file_put 同路径 |
| P2-3 CPU 绑定不释放 | ✅ 真 | |
| P2-4 选核错 | ✅ 真（**CPU1**，不是 CPU7） | |
| P2-5 版本比较 | ✅ 真（**三套**） | |
| P2-6 文件锁未落地 | ✅ 真 | |
| P2-7 dt200 超时 | ✅ 真 | 先修 P1-6 |
| N1 agent 无写超时 | ✅ 真 | `grep SetWriteDeadline` = 0 |
| N2 桥侧 4 处 recvN 无上限 | ✅ 真 | 206/237/311/596 |
| N3 每帧重分配 | ✅ 真 | |
| N4 listen 无上限 | ✅ 真 | |
| N5 replayer 整文件读 | ✅ 真 | |
| N6 cleanEnv 原地复用 | ✅ 真（隐患） | |
| N7 frame.Read 死代码 | ✅ 真 | |
| N8 stripSudoPrefix 不判 root | ✅ 真（调用方已判） | |
| N9 setup 关防火墙 | ✅ 真（与 Python 一致） | |

**没有一条被证伪。** 但有一条要补充说明：P1-1 的实际风险被低估了——
`dataLen` 是 `int32`，客户端传 `0xFFFFFFFF` 会被当成负数，`acc` 永远追不上，
连接一直挂着但不再收包。这不是 OOM，是**静默僵死**。修的时候要一起处理。

---

## 二、新增发现（这一轮）

### N10（P0，已实测）file_put 全链路不可用

见第零节。

### N11（P1）回放时命中 VLAN 报文会被**原样发送**

`buildModifiedPacket` 直接 `payload := ethBytes[14:]` 当 IP 头解析，
**没解 VLAN**。而 `replayer.go:701-708` 的 `replayFile` 是解了 VLAN 才拿到 `pkt`，
然后把这个**带 VLAN 标签的原始 pkt** 传给 `buildModifiedPacket`。

实测：

```
带 VLAN 标签的报文 + force_ip_src  → buildModifiedPacket 返回 nil（改写不生效）
不带 VLAN 的同一报文               → 改写生效，源地址变成 192.168.1.1
```

而 Python 原版 `replayer.py:588-593` 是**先解 VLAN 再取 payload**，所以 Python 能改。

后果：只要回放的 pcap 带 VLAN（现场几乎都带），`force_ip_src/dst/sport/dport` **全部静默失效**，包原样发送。日志里没有任何提示。

顺带一个短包 panic：

```
15 字节帧（ethType=0x0800 + 1 字节 0x45）→ PANIC: slice bounds out of range [:20] with capacity 1
14 字节帧（无 payload）                → PANIC: index out of range [0] with length 0
```

Python 原版对 15 字节是安全的（`payload[:20]` 对短切片不越界），14 字节会 `IndexError` 但被 `except Exception → return eth_bytes` 兜住。Go 侧没有 panic 兜底，`handleConn` 的 `recover` 会**断掉整条连接、回放中断**。

实测走完整 `replayFile`：合法包 + 14B + 15B 混排 → `packets=1`（只有第一包发出，
后两个直接 panic 中断）。也就是说**一个畸形 pcap 能让整次回放中途死掉**。

**最优方案**：

```
1. buildModifiedPacket 开头解 VLAN（与 replayFile 口径一致），
   或者更简单：让 replayFile 把解完 VLAN 的 payload 传过去。
2. 整段 rewrite 包进一个 recover 等价体：任何切片越界都回 nil（= 原样发送），
   与 Python `except Exception → return eth_bytes` 同语义。
   一个 defer recover + 命名返回值，8 行。
```

### N12（P1）FTP PASV 用服务器回的内网地址，NAT 后必然连不上

`parsePasv` 原样返回服务器给的 4 段 IP：

```
227 Entering Passive Mode (10,0,0,5,195,80)  → 桥去连 10.0.0.5:50000
```

若 FTP 服务器在 NAT 后（很常见），这个地址从桥不可达，`dpi_prepare_package` 直接失败。

**这是「不懂就留到最后确认」那一类** —— 现场 FTP 是否 NAT 后，我不知道。
但代码层面可以无条件更稳：**用控制连接的对端 IP 代替 PASV 返回的 IP**（PORT/EPRT 时代的标准做法，curl/wget 默认就这么做），只取 PASV 的端口号。这样 NAT 与否都能连上。

### N13（P1）FTP 多行响应不处理

`ftpDownload` 的 `expect(code)` 只读第一行：

```
220-First line of banner
220 Second line
```

`expect("220")` 拿到 `220-First...` 就算通过，然后 `220 Second line` 留在缓冲里，
下一条 `expect("331")` 读到它 → 「FTP 期望 331，收到 "220 Second line"」。
很多 FTP 服务器 banner 是多行的。

**方案**：`expect` 读到首字符是 `code-` 时继续读到 `code `（带空格）为止。

### N14（P1）配置项写了不生效（用户会被误导）

`config.go` 里 `mcp.pool.*`（4 项）和 `mcp.behind_proxy` 都被解析、被覆盖逻辑照顾到，
但**从来没传给 `mcpbridge`**：

```
BridgeConfig 结构体里没有 Pool 字段
NewScheduler() 无参数，sem 硬编码 make(chan struct{}, 50)
poolMaxConnPerTarget = 5 / poolIdleTimeoutSec = 600 / poolBorrowTimeoutSec = 10  全是 const
```

后果：改了 `max_conn_per_target: 20` 后重启，配了等于没配，**没有任何日志或警告**。
这和五轮验收里「mirror 配了不生效」是同一个病。

**方案**：把 4 项加进 `BridgeConfig` → `NewScheduler(cfg)`；`behind_proxy` 要么接上（设 `X-Forwarded-For` 处理）要么从配置结构和文档里删掉。

### N15（P2）`probeAlive` 把读 deadline 留成过去时间

```go
c.conn.SetReadDeadline(time.Now().Add(time.Millisecond))   // 探针
// 函数返回，没有重置
```

复用时下一条 `recv` 若发生在 1ms 之后就直接 i/o timeout。
现在恰好被 `c.send` 里的 `SetDeadline` 覆盖住了（`protocol.go:148/154`），
所以没暴露。但这是**顺序耦合**：任何「复用连接后不先 send 直接 recv」的路径都会踩。
建议 `probeAlive` 结束时恢复 `SetReadDeadline(time.Time{})` 或设为 `Timeout`。

### N16（P2）审计清理只在启动时跑一次

`OpenAudit` 里 `DELETE FROM audit_log WHERE ts < ...` 只在进程启动执行。
桥常驻数月不重启的话，90 天保留期不生效，库会无限增长。

**方案**：`Write` 里按计数每 N 条触发一次，或起一个日级 timer。

### N17（P2）`listen` 在队列满 + 连接不关时 shutdown 会卡死

```go
inst.q <- chunk        // 容量 1024，满则阻塞
```

cachedata 消费者只在 `time.After(1s)` 分支检查 `stopped`；一旦 `q` 满，
生产者卡在 `inst.q <- chunk`，消费者每轮都能取到，理论上能排空——但
`shutdown` 先 `Close` 连接再 `wg.Wait()`，若 Reading goroutine 正卡在 `q <-` 上，
连接已关不会再产生新 chunk，消费者能排空 → goroutine 退出。**实测推演能退出**，
但存在一个窗口：消费者 `appendData` 慢于生产。风险低，列为 P2。

### N18（P3）`replayFile` 里 `origLen` 可能为 0

`bytesInc := origLen; if bytesInc < 60 { bytesInc = 60 }` 已兜住，无问题，记录备查。

---

## 三、DPI 功能缺口（本轮新增部分）

### 3.1 上轮说的「三个 wait 已能凑出来」——**其中两个其实凑不出来**

上一轮我说 `wait_flow_timeout` / `wait_pcapdump_writeover` 可以用 `dpi_wait_stat` 实现。**实测证明我说错了**：

**`wait_flow_timeout`**：
```
dpi_read_stat kind=flow 执行的命令是：cat flow.stat | grep all -A 70
flow.stat 里 "all" 只出现在第 56 行的表头，concurrent_cnt 在第 113 行
→ -A 70 覆盖 56..126，**刚好包含 113**，所以能读到 ✓
```
这条**确实能凑**。但依赖 `grep -A 70` 这个魔法数字，文件若变长就断。

**`wait_pcapdump_writeover`**：
```
Python: cat pcapdump.stat |grep all |tail -n 1|awk '{print $10}'
实测该行 NF=11，$10 = "memover_loss"，不是 write_blk
```
而且 Python 原版取的是 **`savetask` 块的 `$10`（`memover_loss`）** 还是
`wtask` 块的 `$10`（`marex_amt_loss`）——取决于哪个 `all` 行是最后一行，
**两个块都有 `all` 行**，`tail -n 1` 取的是文件里靠后的那个。这本身就是
Python 原版的脆弱点。我先不判定语义，留到最后确认。

更关键的是：`parseBlocks` 对 pcapdump 产出的行名是 `detail.0` / `detail.all` / `total`，
而 `lookupField` 只认 `行名.字段` 或裸字段。
实测：

```
lookupField("all.marex_amt_loss")  → 未命中（行名实际是 "detail.all"）
```

所以 r2 里我写的 `field=all.marex_amt_loss` **不可寻址，会一直超时**。
正确写法是 `field=detail.all.marex_amt_loss`（`lookupField` 支持多段吗？——它
`strings.LastIndex(".")` 切一次，即 `rowName="detail.all"`, `field="marex_amt_loss"`，
所以**能命中**）。这个细节必须写进工具描述，否则调用方一定会踩。

### 3.2 `clean_stat` —— 真缺口（不变）

### 3.3 `boce` 拨测：`thread_count` 在浏览器模式下完全被忽略

```go
// boce.go:210
if _, ok := raw["thread_count"]; ok {   // 只有封堵分支校验
```

Python `boce.py:406` 的 pyppeteer 分支也只做 `asyncio.gather(*tasks)`，不看 thread_count。
**与 Python 一致**，不算缺陷。但 Go 侧 `boceBrowser` 的 `count` 个 goroutine
**无并发上限**，count=100 时同时起 100 个 chromedp tab。Python 的 gather 也是 100 个并发
coroutine（同 loop），所以也是保真。记录备查。

### 3.4 状态文件覆盖仍是 23/76

不变的结论。本轮补一条：设备上 `flow_filter.stat` / `updown.stat` / `event.stat` 当前为空
（0 字节或仅表头），说明它们的功能在现场没启用——接不接看用途。

---

## 四、需要你确认的（不懂的业务）

### Q1 `pcapdump.stat` 的「写文件完成」到底看哪个字段

`wait_pcapdump_writeover` 用 `awk '{print $10}'` + `tail -n 1`。两块的 `all` 行 $10
分别落在 `marex_amt_loss` 和 `memover_loss`。**哪个才是「pcapdump 写完」**，
从代码推不出来。

### Q2 `flow.stat` 的 `grep all -A 70` 是否够用

当前文件 113 行命中，`-A 70` 刚好够。生产上文件变长会不会断，取决于它是否固定
结构。需要确认。

### Q3 FTP 服务器是否在 NAT 后

决定 N12 的修法是「无条件用控制连接 IP」还是「配一个被动模式地址覆盖项」。

### Q4 `darea` 的 1/2/3（信安/数安/网安）与「入向/出向」是不是同一维度

上一轮问过，还没答复。IP 库先做机房内外四态，映射层留空。

### Q5 VLAN 报文回放时 `force_ip_*` 应当生效还是原样

N11 我是当作 bug 处理的（Python 能改，Go 不能改，是回归）。但如果业务上
「带 VLAN 的包不该改五元组」，那就是设计而非缺陷。**默认按回归修**，
你若有不同意见告诉我。

---

## 五、修复优先级（按本轮证据重排）

| 序 | 项 | 类型 | 规模 |
|---|---|---|---|
| 1 | **N10 file_put chunked** | P0 回归 | 3 行 |
| 2 | **N11 VLAN 不改写 + 短包 panic** | P1 回归 | ~30 行 |
| 3 | N13 FTP 多行响应 | P1 | ~10 行 |
| 4 | N12 PASV NAT | P1 | ~5 行 |
| 5 | N14 配置项不生效 | P1（误导） | ~30 行 |
| 6 | P1-1 帧长上限（含负数） | P1 | ~10 行 |
| 7 | P1-3 停止失败不删登记 | P1 | ~5 行 |
| 8 | P1-4 句柄关闭幂等 | P1 | ~10 行 |
| 9 | P1-6 dt200 上限 | P1 | ~15 行 |
| 10 | N1 写超时 | P1 | ~5 行 |
| 11 | N2 recvN 四处上限 | P1 | ~20 行 |
| 12 | 其余 P2/P3 | — | — |

前 5 项都是**这一轮新发现或新定位**的，且都不大。建议第一批就做这 5 个。

---

## 六、仍未覆盖

- `boce.go` 的 chromium 下载/解压链只看了 `unzipInto`（无 zip-slip，已消毒）
- `dpi_ops.go` 的 `upms_install` / `upgradeViaSystem`（1051-1150）只扫了结构
- `svc` 包完全未审
- 所有内存数字仍是代码推算，未压测
