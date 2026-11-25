# 多维度代码审查（2026-11-25，v1.9.26 基线）

范围：`internal/agent`（靶机侧）+ `internal/mcpbridge`（桥侧）+ `cmd/socketstack`，共 27k 行。
方法：逐文件读 + grep 交叉验证调用关系；**未跑压测**，性能项标注为「按代码结构推断」。

结论摘要：**没有阻断级缺陷**，但有 6 个 P1（内存放大 / 状态泄露 / 协议无上限）、7 个 P2、若干清理项。

---

## P1 级（真机可能触发，建议优先）

### P1-1 agent 收帧长度无上限（`internal/agent/server.go:58`）

```
dataLen = int32(binary.LittleEndian.Uint32(chunk[:4]))   // 客户端说了算
acc = append(acc, chunk...)                               // 无上限增长
```

`dataLen` 直接取客户端 4 字节且不校验，`acc` 可无限膨胀。畸形或错乱客户端（含协议错位）能让 agent 吃满内存 —— 82 上实测 agent 常态 RSS 已到 1 GB，再加一个伪造长度就是 OOM Kill。`defer recover` 兜不住 OOM。

桥侧 `recvN` 有 `1<<30` 保护（`protocol.go:908`），**但那是读方向**，管不到 agent 写侧。

建议：加 `maxPayload`（建议 256 MB，覆盖最大 pcap 上传的一半即可；超大文件走 :9001 分片），超限断连并记日志。Python 原版同样无上限，但 Go 侧 OOM 的直接后果是整机所有客户端断开。

### P1-2 `sortPcapByTimestamp` 三份全量内存（`internal/agent/capture.go:484`）

```go
data, err := os.ReadFile(path)            // ① 全文
records = append(... data[off+16:...] ...) // ② 每包一个切片头（引用 ①）
out.Write(data[:24]); out.Write(r.data)   // ③ 第二份完整副本
os.WriteFile(tmp, out.Bytes(), ...)       // ④ 写盘
```

峰值 ≈ 2 倍文件大小 + 包头开销。抓包 5 分钟产生 1 GB pcap 时 ≈ 2.1 GB。这与「下载慢」那份文档里测到的 3 倍内存放大是同一类问题。

建议：改为流式两遍（第一遍只统计时间戳与偏移表，第二遍按偏移重排写盘），或至少用 `out.Grow(len(data))` 复用而不是 `bytes.Buffer` 逐包 append。

### P1-3 `tcpdumpStart` 在停止失败时仍然删注册表（`internal/agent/capture.go:92-99`）

```go
if old, ok := captures[path]; ok {
    capturesMu.Unlock()
    stopCaptureEntry(old)      // 返回 false = 旧线程还在跑
    capturesMu.Lock()
    delete(captures, path)     // ← 无条件删除
}
```

`stopCaptureEntry` 返回 false 表示旧抓包线程**没有退出**（socket 强关后仍卡住）。此时注册表被删，后果：

1. `dt6` 查不到 → 永远无法再停它
2. 紧接着 `dt5` 启动新实例写**同一个 path** → 两个 goroutine 各自持有 `*os.File` 写同一文件 → pcap 交错损坏
3. CAPTURE 锁在桥侧仍是旧的那把，新启动的没有再注册

建议：`delete` 只在 `stopCaptureEntry(old)` 返回 true 时执行；false 则直接返回 `(false, error)`，让调用方知道「旧实例没停干净，不能开新的」。

### P1-4 `src.close()` 可能双关同一 fd（`capture.go:256/272/564`）

三条路径都能 close 同一个 `afpacketSource`：

- recv 循环 `isEthDownErr` 分支（256）→ `return`，此时未走 drained
- recv 循环 `drained` 收尾（272）
- `stopCaptureEntry` 超时强关（564）

`stopCaptureEntry` 强关 `e.src` 时，recv goroutine 阻塞在同一个 fd 的 `Recvmsg` 上 → 拿到 EBADF → `goto drained` → 再 close 一次。fd 号在两次 close 之间若被别的 goroutine 拿走，第二次 close 会**关掉别人的 socket**（AF_PACKET 的 close 触发 `synchronize_net`，实测 28 ms）。

建议：`afpacketSource` 加 `sync.Once`（`closeOnce`），与 `captureEntry.stopOnce` 同构。

### P1-5 桥侧下载硬上限 1 GB（`internal/mcpbridge/protocol.go:908`）

```go
if n > 1<<30 { return nil, fmt.Errorf("下载长度异常: %d", n) }
```

用户现场 pcap 已见 367 MB；抓包 10 分钟轻松超 1 GB。超限直接报「下载长度异常」，`file_get` 无法取回。

且 `file_get` 走 `downloadFile()` 强制 `gzip:true`（`protocol.go:899`），**压缩后再传**，所以 1 GB 的 pcap 实际 wire 约 120 MB —— 上限卡的是解压后的原始长度还是 wire 长度？看代码是 wire（`n` 是 8 字节前缀值 = 压缩后长度）。那么 1 GB 的原始 pcap 不会触发；但 8 GB 原始 → wire ~1 GB → 触发。

建议：改为可配置（`mcp.max_download_mb`，默认 4096），并给超限错误加上「请改用 :9001 分段下载」的指引。

### P1-6 dt200 无条目上限（`internal/agent/pcapflow.go:79-134`）

`extractPcapFlowFiveTuples` 遍历目录内**所有** pcap，把每个文件的所有流累积进 `results`，然后 `json.Marshal` 全量 → 一次返回。

桥侧虽然 `flows[:1000]` 截断（`tools_traffic.go:426`），但：

1. agent 已经算完全部流、序列化了全部 JSON
2. 传输全部字节到桥，桥再丢弃 99%
3. `pcap_extract_flows` 的默认超时只有 30 秒

大目录（`/dev/shm/sess/pcap` 下按用例分目录，几千个 pcap）会 OOM 或超时。实测 82 上该目录当前是 0 个 pcap（测试已清），但生产现场会积累。

建议：agent 侧加硬上限（如 200 000 条）+ 早停，返回 `truncated: true`；桥侧把 `total` 透出原始规模（现在 `total` 是截断前的真值，保留即可）。

---

## P2 级

### P2-1 `httpfile.go` GET 下载错误被吞（`:365`）

```go
io.CopyBuffer(w, io.LimitReader(f, fi.Size()), make([]byte, 1<<20))  // 返回值忽略
```

客户端中断、磁盘读错误全部静默。运维看到「下载失败」但服务端日志无任何记录。上一轮 pcapdump 卡死排查时，正是因为服务端日志空白才走了大弯路。

建议：检查错误并 `log.Printf`，至少留一条。

### P2-2 `.part` close 错误被忽略（`httpfile.go:443-449`）

```go
fh.Close()              // 返回值忽略
fh = nil
if err := os.Rename(partPath, dest); err != nil { ... }
```

磁盘满时 `Close()` 可能返回 ENOSPC（缓冲未刷完），但 `Rename` 成功 → **半截文件被当作完整文件**，且调用方拿到 `{"ok":true,"size":N}`。

建议：检查 `fh.Close()` 错误，失败则删 `.part` 并回 500。

### P2-3 `cpuBinding` / `allocatedCPU` 永不释放（`capture.go:691-696`）

全仓无 `delete(cpuBinding...)`。网卡删除重建后旧绑定残留；网卡 A 消失后它占的 CPU 不会释放给 B。数量受网卡数限制，影响小，但语义错误。

建议：`captureEntry` 结束时释放本网卡的绑定（带引用计数，同一网卡可多路径抓包）。

### P2-4 `pickFreeCPU` 在 cpuset 受限机器上绑错 CPU（`capture.go:773,787`）

```go
n := 8                                     // 从 /sys/devices/system/cpu 数目录
if cores, err := os.ReadDir(...); err == nil { n = count }   // = 宿主机 8 个
...
cpu := n - 1                               // busy[0]=true，找不到空闲 → 7
```

82 实测：`online=0-7` 但 cpuset 只有 `0`（进程 `Cpus_allowed_list: 0`、`nproc=1`）。上面代码会算出 CPU **7**，写 `/proc/irq/N/smp_affinity_list` 为 7 —— 该 CPU 在本进程 cpuset 外，内核要么拒绝要么静默无效果，日志还会打「将网卡 ens3 的 N 个中断绑定到 CPU7」，**误导现场**。

建议：读 `sched_getaffinity`（`unix.SchedGetaffinity`）拿真正可用的 CPU 集合，不要数 `/sys` 目录。

### P2-5 版本比较两套实现语义不同

- `internal/mcpbridge/dpi_ops.go:702 parseVersionParts / compareVersions`：按 `[.\-]` 切、补零到 7 段、字母权重
- `internal/mcpbridge/tools.go:399 parseVer3 / verLess / atLeast`：只解析 `^\d+(\.\d+){1,3}$`、前缀比较

同一模块两套版本语义，`dpi_upgrade` 判版本用前者、`upgrade_run` 判 `1.8.0+` 用后者。遇到 `1.9.26-rc1` 这类字符串，两处结论可能相反。

建议：合并为一套（保留 `compareVersions` 的完整语义），`atLeast` 改为 `compareVersions(v, fmt.Sprintf("%d.%d.%d", a,b,c)) >= 0`。

### P2-6 `LkFileIO` 定义了但从未使用（`bridge.go:24`）

`file_get / file_put / file_remove / file_unzip` 全部用 `LkNone`（`tools_file.go:148,186,212,233,257,277,299`）。后果：

1. 两个并发 `file_put` 写同一远端路径 → 互相覆盖，无提示
2. **抓包/回放期间上传大 pcap 不受互斥约束** → 污染抓包（回放和抓包同机本应互斥，但 file_put 不持锁也能往里塞流量？不，file_put 是写盘不是发包，影响是「往正在写的 pcap 目录塞文件」）
3. 与 `LkCapture` 的互斥矩阵形同虚设

建议：`file_put/file_get` 至少对**同一个远端路径**用 keyed 锁（`LkFileIO` + `path` 作 key），与 capture 的 keyed 锁同构。

### P2-7 `pcap_extract_flows` 的 dt200 超时预算偏紧

`contract.go:126`：`"沿用现有 30；最多 1000 条"`。大目录实际解析时间远超 30 秒（每次 `os.Open` + 逐包解析）。配合 P1-6 的上限缺失，超时是必然结果。

建议：默认提到 120，并在工具描述里写明「目录越大越慢，大目录请先按用例目录分次提取」。

---

## P3 清理项

| 位置 | 内容 |
|---|---|
| `internal/mcpbridge/tools.go:360` | `mergeMap` 零调用者 |
| `internal/mcpbridge/tools.go:385` | `renameField` 零调用者 |
| `internal/agent/afpacket_linux.go:177` | `syscallReadRO` 只有声明 + `var _ = os.Geteuid` 充数 |
| `internal/mcpbridge/tools.go:430` | `var _ = os.Getenv` 仅为保住 import |
| `internal/mcpbridge/dpi_ops.go:28` | `readFileB64` 名字错：它做的是 dt3 下载后转 string，**没有 base64** |
| `internal/mcpbridge/protocol.go:211,600,915` | `strings.NewReader(string(gz))` 每次 gzip 多一份完整字节拷贝；应改 `bytes.NewReader(gz)` |
| `internal/mcpbridge/protocol.go:927-935` | `strings.Builder` + `[]byte(buf.String())` 上传路径多两份拷贝 |
| `internal/agent/handlers.go:31` | `fp := ""` 占位再赋值，可合并 |
| `internal/mcpbridge/bridge.go:33-43` | `Lk.String()` 有 `LkFileIO`/`LkShell`…，但 `LkNone` 走 default "none"，无差 |

---

## 与「下载慢」的关系

`docs/pcap-download-speed-analysis-2026-11-03.md` 已单独成文。本文补充两条同源问题：

- `protocol.go:915` 解压后的 `io.ReadAll` 也无上限 → 压缩炸弹（恶意 1 KB gzip 解出 4 GB）
- `file_get` 强制 `gzip:true`，与本地 `curl :9001` 的 3.1 s 相比 dt3 要 9.5 s

---

## 建议的修复批次

**第一批（P1，1 个版本内）**
1. agent 帧长上限
2. `tcpdumpStart` 停止失败不删注册表
3. `src.close()` 幂等
4. dt200 条目上限

**第二批（P2）**
5. httpfile GET 错误日志 + `.part` close 检查
6. `pickFreeCPU` 改用 affinity
7. 版本比较合并
8. `LkFileIO` 落地到 file_put/file_get

**第三批（P3 + 性能）**
9. 死代码清理
10. `bytes.NewReader` 替换字符串拷贝
11. `sortPcapByTimestamp` 流式化

---

## 未覆盖 / 未验证

- `internal/agent/replayer.go`（798 行）只做了结构扫描，未逐函数审查
- `internal/agent/boce*.go`（chromium 拨测）未审
- `cmd/socketstack` 只看了 wire.go 的 install/status 段
- 全部结论基于静态阅读，除「82 单 CPU cpuset」与「agent RSS 1 GB」两项有真机实测支撑
