# pcap 下载慢的根因分析（2026-11-03）

分析对象：验收脚本 `dpiAutoExcel/business/pcapdump.py` 的 `dpi.download_pcap()` 路径，
即 Python 客户端 `socket_linux.py:getfo(gzip=True)` → 靶机 agent `dt3`。

## 结论

**慢的原因不是网络，是 dt3 下载强制整文件 gzip，且压缩在单核上串行做完才发第一个字节。**

- 网络侧实测能跑到 **95 MB/s**（≈760 Mbps，1GbE 线速），不是瓶颈。
- gzip 吃掉 dt3 总耗时的 **84%**：367 MB 文件，压缩 8.0 秒，传输 1.5 秒。
- Go 版已经比 Python 原版快 2.5 倍（同文件 Python 级别 9 要 23.8 秒，Go 级别 6 约 8 秒），
  **不是重写引入的退化**，是协议设计本身的开销。

## 实测数据（10.12.131.82，367 MB pcap）

| 通道 | 耗时 | 首字节延迟 | 有效速率 |
|---|---|---|---|
| HTTP `:9001`（不压缩、1MB 分块流式） | **3.1 s** | ~0 ms | 117 MB/s |
| dt3　`gzip=false` | 3.9 s | 0.7 s | 95 MB/s |
| dt3　`gzip=true`（客户端默认） | **9.5 s** | **8.0 s** | 18.7 MB/s |

同一台机器上单纯跑 zlib 压缩该文件（单核）：

| 压缩级别 | 耗时 | 吞吐 | 说明 |
|---|---|---|---|
| 9 | 23.8 s | 15.5 MB/s | Python 原版 `gzip.compress` 默认值 |
| 6 | 10.8 s | 34 MB/s | Go `gzip.NewWriter` 默认值 |
| 1 | 7.8 s | 47 MB/s | 压缩率从 0.117 劣化到 0.127 |

结论：**82 是单 CPU 机器**（`nproc=1`，全进程 `Cpus_allowed_list: 0`，内核虽然
`online=0-7` 但 cpuset 只给 cpu0），gzip 单线程没有任何并行余地。

35 对照（78 核，但网卡 1 GbE，本机即 35，走环回）60 MB 文件：
`gzip=false` 0.06 s / `gzip=true` 1.77 s，首字节 1.76 s——同样是压缩主导。

## 三个叠加原因

### 1. 客户端强制开启 gzip，绕不开

`socket_linux.py:652/664/675` 三处 `getfo(..., gzip=True)` 写死。payload 只有
`{"gzip": true}`，不会因为文件类型或大小改选。

### 2. 压缩是「整文件、全内存、压缩完再发」

`internal/agent/pcapflow.go:303 downloadFile()`：

```
os.ReadFile 全文 → gzip 全量写入 bytes.Buffer
                → make([]byte, 8+len) 再整体 copy 一次
                → 单次 conn.Write 发出
```

首字节延迟 = 整个文件的压缩时间。在 367 MB 文件上就是 8 秒没有任何数据发出，
客户端 `recv` 只能干等。

### 3. 单核 + 无并行

gzip 是单线程算法，82 只给 1 个 CPU。35 虽然 78 核，但 Go 侧同样只用一个核。

## 次要问题（同一路径上发现，会放大体感）

| 问题 | 实测 | 影响 |
|---|---|---|
| **内存放大 3 倍** | 367 MB 文件 → agent `VmHWM = 1.07 GB` | 原文 + 压缩结果 + 再拷贝一份。多客户端并发下大文件会 OOM |
| **失败重发整包** | `sendWithRetry` 写失败后 sleep 3s 重发同一份 177 MB | 峰值内存再翻倍，且客户端看到的是「卡住 3 秒」 |
| **无写超时** | agent 侧连接没有任何 `SetWriteDeadline` | 客户端不走，goroutine 永久持有 ~1 GB |
| **小文件固定开销** | 731 KB 文件单次 0.064 s（dt21+dt3+压缩） | pcapdump 目录 N 个文件 → N×64 ms 起，与大文件开销叠加 |
| 客户端侧 `wrpcap(append=True)` | 每追加一个文件重写整包 | O(N²)，属测试脚本自身问题，不在服务端 |

## 可选改进（未实施，按性价比排序）

1. **走 :9001 而不是 dt3**——最快见效，3.1 s vs 9.5 s（3 倍）。
   但客户端脚本写死 dt3，需要改客户端；协议本身不用动。
2. **分块并行压缩 + 多成员 gzip 拼接**——gzip 允许多个 member 顺序拼接，
   `gzip.decompress` / Go `gzip.Reader`（默认 `Multistream=true`）都能正确解。
   在 78 核的 35 上能把压缩时间近似除以核数；**但在 82 这种单核机器上完全无效**。
3. **降压缩级别到 1**——82 上 8.0 s → 约 5 s，代价是线上字节数 +8%。
   收益有限，且 pcap 压缩率本来就好（0.117），多传的字节仍在 1 GbE 能力内。
4. **流式压缩**——边压边写能消掉首字节延迟，但协议要求 8 字节长度前缀在数据之前，
   长度必须在写完才知道，**不改协议做不到**。
5. **改内存用法**——`io.Copy` 直接写 `conn`（长度已知时）或至少省掉 `copy(out[8:], content)`
   这一次全量拷贝，能把峰值内存从 3× 降到 2×。不影响速度。

## 复现命令

```bash
# 无压缩（对照）
python3 -I /tmp/dl_probe.py 10.12.131.82 /home/tmp/tmp.pcap 0
# gzip（客户端默认路径）
python3 -I /tmp/dl_probe.py 10.12.131.82 /home/tmp/tmp.pcap 1
# HTTP 通道对照
curl -o /dev/null -w '%{speed_download} B/s %{time_total}s\n' \
  "http://10.12.131.82:9001/files?path=/home/tmp/tmp.pcap"
```
