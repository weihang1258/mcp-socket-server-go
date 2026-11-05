# Python 原版 ↔ Go 复刻版 靶站功能逐项对比

审计日期：2026-11-02
基线：Python `socket_server 1.8.3`（`/home/weihang/socket_server`）+ `mcp_socket_server 0.3.2`
（`/home/weihang/mcp_socket_server`）；Go `socketstack v1.9.23`（本仓库）。
标注：`[实测]` = 本次实际运行验证；`[读码]` = 双向源码核对；`[报告]` = 子代理核对、本报告未二次运行。

> **后续**：本报告 §0/§6 列出的缺陷已在 v1.9.24 修复，并做了真机验收；
> 处置结果与证据见本文 §7（另含验收中发现的新缺陷 H9）。

---

## 0. 结论摘要（先看这段）

### 0.1 弹窗 / 重定向——你的怀疑点，结论是「一半对、一半不是 Go 的锅」

| 项 | Python 原版 | Go 版 | 判定 |
|---|---|---|---|
| **弹窗模式** | `boce.py:367-370` 明确写「弹窗模式未实现，判定为失败」→ 恒 `False` | `boce_browser.go:163-167` 非「重定向」直接返回 `false` | **两版都恒失败**。这是 Python 原版就没实现的功能，不是 Go 回归。客户端 `eu_policy.py:554-560` 对「重定向/弹窗」要求成功率 > 0.90，所以**弹窗用例在 Python 上也必然判红** |
| **重定向判定** | `jumped_urls` 非空 或 `request_count > 1` → 成功（`boce.py:350-366`） | `jumped \|\| requests > 1`（`boce_browser.go:236-238`） | **判定逻辑一致**。`[实测]` 用本地 HTTP 服务验证：302 链 → 成功；无跳转 → 失败；`location.href` JS 跳转 → 成功 |
| **弹窗的流量副作用** | 先真开浏览器 + `goto` + `sleep(3)`，再判失败（`boce.py:318-370`） | 预检模式后**零流量**直接返回 | **有意差异**（设计文档 §12#17）。对客户端断言无影响（弹窗用例只查成功率，两版都是 0%） |
| **count > 1 的执行方式** | `asyncio.gather` **并行**（`boce.py:401-407`） | `for i := 0; i < count; i++` **串行**（`boce_browser.go:107-113`） | ⚠️ **真实回归**。`[实测]` count=1 约 7.75s，count=3 约 12.43s（≈串行叠加）；Python 三项并行约 3-8s。count 越大差距越大，会撞穿桥的 `timeout+10` 外层超时 |

**一句话**：弹窗不是 Go 的问题（Python 也没实现）；重定向判定本身没问题；真正该修的是**重定向模式 count>1 的串行循环**。

### 0.2 另外确认的高危缺陷（与弹窗无关，但会影响真机）

| # | 缺陷 | 证据 | 后果 |
|---|---|---|---|
| H1 | `buildModifiedPacket` 短传输层 panic | `[实测]` 探针复现 `index out of range [1] with length 0`（`replayer.go:250,257`） | `handleConn` 无 recover → **整个 agent 进程崩溃**。Python 同路径有 `except → 返回原包` |
| H2 | 抓包 VLAN auxdata 偏移错位 | `[读码+内核头]` `capture.go:330-332` 读 `aux[12:14]`/`[14:16]`，内核 `tpacket_auxdata` 的 tci/tpid 在 16/18 | 所有带 VLAN 的帧 VID 丢失、TPID 可能写成 0 → **pcap 内容错误**；测试夹具按错误偏移构造，用例一直是绿的 |
| H3 | BPF 注入晚于 bind | `[读码]` `afpacket_linux.go:87-92` 最后 bind，`capture.go:109-118` open 返回后才 attach | `extended` 过滤存在漏包窗口（bind 到 attach 之间的帧不过滤） |
| H4 | `stopCaptureEntry` 的 `close(chan)` TOCTOU | `[读码]` `capture.go:469-473` `select{case <-stop: default: close(stop)}` | 并发 dt5 同 path / 两个 dt6 同时到 → `close of closed channel` panic，同样无 recover |
| H5 | dt5 网卡 down 时返回 `res:true` | `[读码]` `capture.go:209-216` 非超时 recv 错误直接 `goto drained`，`fatal` 未置位 | Python 返回 false，Go 返回 true 且删条目，**误报抓包成功** |
| H6 | MCP `isfile`/`isdir` 把「不存在」记成 failed | `[实测]` 真机 10.12.131.82 返回 `{"ok":0,"failed":[{...,"reason":"agent 返回 False（业务失败）"}],"results":[]}` | Python 返回 `ok:1, results:[{"target":...,"exists":false}]`。LLM 无法区分「文件不存在」与「连接失败」；且 `docs/client-response-v1.9.5.md` 声称「与 Python 一致」不成立 |
| H7 | `splitHostPort` 误拆裸 IPv6 | `[实测]` 探针：`fd00::5` → host=`fd00:` port=5；`::1` → host=`:` port=1 | 末段为纯数字的裸 IPv6 靶机连到错误地址 |
| H8 | dt20 活跃客户端检查是死代码 | `[实测]` 探针：`overrideClients=0 → activeClientsNow()=0`，`Clients()` 被绕过 | `active_clients > 1` 拒绝逻辑永不触发，升级可能打断其他客户端 |

---

## 1. 接口功能全清单

### 1.1 靶机 agent（:9000 自定义 TCP，`[4B len][4B datatype][payload]`）

| dt | 功能 | Python 出处 | Go 出处 | Go 状态 |
|---|---|---|---|---|
| 0 | pcap 回放 | `handlers.py:104` → `replayer.py` | `handlers.go:215` → `replayer.go` | 有 |
| 1 | 命令执行 | `handlers.py:122` → `netutils.py` | `handlers.go:30` | 有 |
| 3 | 文件下载 | `handlers.py:133` | `handlers.go:33` | 有 |
| 4 | 路由信息 | `handlers.py:145` | `handlers.go:40` | 有 |
| 5 | 抓包开始 | `handlers.py:153` → `capture.py` | `handlers.go:218` → `capture.go` | 有 |
| 6 | 抓包停止 | `handlers.py:163` | `handlers.go:244` | 有 |
| 7 | 是否文件 | `handlers.py:171` | `handlers.go:48` | 有 |
| 8 | 是否目录 | `handlers.py:181` | `handlers.go:66` | 有 |
| 9 | 创建目录 | `handlers.py:190` | `handlers.go:84` | 有 |
| 10 | 改 MTU | `handlers.py:201` | `handlers.go:105` | 有 |
| 11 | 取字节数 | `handlers.py:213` | `handlers.go:141` | 有 |
| 14 | 版本号 | `handlers.py:219` | `handlers.go:157` | 有 |
| 15 | 解压 zip | `handlers.py:362` | `handlers.go:164` | 有 |
| 16 | python_cmd | `handlers.py:369` | `handlers.go:161` → `pythoncmd.go` | 有（受限，见 §3.3） |
| 18 | ensure_command | `handlers.py` | `handlers.go:188` | 有 |
| 19 | 版本详情 | `handlers.py` | `handlers.go:206` | 有 |
| 20 | 升级落地 | `handlers.py:352` | `handlers.go:259` → `upgrade.go` | 有 |
| 131 | 拨测 | `handlers.py:256` → `boce.py` | `handlers.go:266` → `boce.go` | 有 |
| 171-175 | socket 监听五连 | `handlers.py:379-463` | `handlers.go:173-187` → `listen.go` | 有 |
| 200 | pcap 五元组 | `handlers.py:438` | `handlers.go:273` | 有 |
| 21/22/23/24 | 文件上传状态机 | `protocol.py:66-118` | `server.go:94-199` | 有 |
| 121/122/123 | scapy 抓包三连 | **源码已整段注释**（`handlers.py:226-254`） | 无 | 有意不复刻（§12） |
| 161/162/163 | DPI 启停重启 | **handlers.py 无分支**（`commands.py:20` 注释「死代码」） | 无 | **两侧行为一致**：都是无响应、连接继续 |

> dt161-163 说明：客户端 `device/socket_linux.py:385` 的 `dpi_operation()` 会发这三个 dt，但 Python 服务端 `else: pass` → 返回 None → 不回包。Go 未实现 → `return nil, nil` → 同样不回包。**逐字节等价**，不是缺陷；是客户端侧的废弃 API。

### 1.2 :9001 HTTP 文件服务（`http_file.py` ↔ `httpfile.go`）

GET 下载、POST multipart 上传、`http_port` 配置、全盘 realpath、目录自动创建、`^$` 空文件、跨盘 move 兜底。

### 1.3 MCP 桥（15 工具）

`list_targets` / `add_target` / `remove_target` / `version` / `file_transfer` / `isfile` / `isdir` / `pcap_flow_extract` / `cmd_exec` / `capture_start` / `capture_stop` / `boce_run` / `replay_run` / `socket_listen` / `upgrade_run`。

---

## 2. 已确认缺陷明细

### 2.1 H1 重放器 panic（最高优先级）

`internal/agent/replayer.go:250-258`：

```go
if (modSport != nil || modDport != nil) && len(trans) < 2 {
    return nil
}
...
if modDport != nil {
    binary.BigEndian.PutUint16(trans[2:], *modDport)   // len(trans)==2/3 时 trans[2:] 长度 0/1 → panic
}
```

触发条件（三者同时满足）：
1. `force_ip_src` 或 `force_ip_dst` 非空（否则不进改写分支）；
2. `force_dport` 非空；
3. 某个报文的传输层不足 4 字节（畸形/截断 pcap 很常见）。

`[实测]` 探针输出：

```
len(transport)=2 PANIC CONFIRMED: runtime error: index out of range [1] with length 0
len(transport)=3 PANIC CONFIRMED: runtime error: index out of range [1] with length 1
```

Python 对照（`replayer.py:331-569`）：整个 `build_modified_packet` 包在 `try/except` 里，异常时 `logger.error` 后 `return eth_bytes`（原包）。**Go 的 `handleConn` 没有 recover，panic 会带走整个 agent 进程。**

同族问题：`replayer.go:394-401`（v4↔v6 分支）有同样的 `len(trans) < 2` 守卫缺陷。

### 2.2 H2/H3/H5 抓包三连

- **VLAN 偏移**：内核 `struct tpacket_auxdata`（`/usr/include/linux/if_packet.h:97-105`）为 `tp_status u32 / tp_len u32 / tp_snaplen u32 / tp_mac u16 / tp_net u16 / tp_vlan_tci u16 / tp_vlan_tpid u16`，即 tci@16、tpid@18。Go 读 `aux[12:14]`（tp_mac）当 tci、`aux[14:16]`（tp_net）当 tpid。`capture_test.go:93-98` 的夹具把 tci 写在 12，**按错误偏移构造**，所以单测永远绿。
- **BPF 顺序**：`afpacket_linux.go:87-88` 注释写「bind 最后做……杜绝未过滤窗口」，但 bind 是 open 的最后一步，`capture.go:109` 才 attach BPF —— 注释与实际相反。
- **网卡 down**：`capture.go:209-216` 非超时 recv 错误直接 `goto drained`，`fatal` 保持 nil，0.5s 稳定窗（`capture.go:137-149`）判不出失败 → dt5 回 `{"res":true}`。Python 在 `capture.py:224-228` 置 `_exc`，`capture.py:450-460` 判失败。

### 2.3 H4 `close(chan)` TOCTOU

```go
select {
case <-e.stop:      // 已关
default:
    close(e.stop)   // 另一 goroutine 同时走到这里 → panic: close of closed channel
}
```

两个 dt6 并发、或 dt5 与 dt6 针对同一 path 并发即可触发。该 panic 不在 capture goroutine 的 recover 范围内。

### 2.4 H6 MCP isfile/isdir 语义反转

Python 侧 `isfile`/`isdir` **不走 `_run_batch`**，走 `get_scheduler().batch()`（`server.py:357,369`）；`pool.py:146` 对任何返回值都记 `ok=True`，所以 `False` 结果表示为：

```json
{"ok": 1, "failed": [], "results": [{"target": "10.12.131.82", "exists": false}]}
```

Go 侧走 `runBatch`，`tools.go:179-184` 的 `case bool: if !v { ok=false; failed }` 把 `false` 变成失败：

```json
{"ok": 0, "failed": [{"target": "10.12.131.82", "reason": "agent 返回 False（业务失败）"}], "results": []}
```

`[实测]` 真机 `/home/tmp/__no_such_file_probe__` 复现 Go 行为，与 Python 语义相反。

> 注意：`docs/client-response-v1.9.5.md` 把它列为「契约」并声称「与 Python 一致」。该说法只在 agent dt7/dt8 层成立，在 MCP 工具层不成立。

### 2.5 H7 IPv6 拆分

`tools.go:238-247` 用 `LastIndex(':')` + 末段全数字判定。`[实测]`：

```
fd00::5          -> host="fd00:"      port=5     ← 错
::1              -> host=":"          port=1     ← 错
10.12.131.82:9100 -> host=10.12.131.82 port=9100  ← 对
[fd00::5]:9000    -> host="fd00::5"   port=9000   ← 对
```

Python 桥不做这一步（`server.py:181` 直接把 resolve 结果当 host），且 Python 客户端 `socket.AF_INET` only，本来就连不了 IPv6 —— 所以 Python 是「明确报错」，Go 是「连到错误地址」。Go 宣称支持 IPv6（§12#10），这条路径与该宣称不符。

### 2.6 H8 dt20 死代码

```go
// overrideClients 测试注入活跃客户端数；默认 -1 = 用真实 Clients()。
var overrideClients atomic.Int64          // 零值 0，没有任何地方 set 成 -1
func activeClientsNow() int64 {
    if n := overrideClients.Load(); n >= 0 { return n }   // 恒 true → 恒 0
    return Clients()
}
```

`[实测]` 探针：`overrideClients=0 activeClientsNow=0 Clients=0`。→ `upgrade.go:239` 的 `n > 1` 永不成立，**「还有 N 个其它客户端连接，拒绝升级」这条保护从未生效**。

### 2.7 其余已验证的中低危项

| 项 | Python | Go | 影响 |
|---|---|---|---|
| dt20 畸形 JSON | `json.loads` 抛异常 → 断连 | `return nil, ""` → **不回包也不断连** | 客户端永久等；`[实测]` 复现 |
| `Agent.LogFile` 配置 | — | `setup.go:53` 固定传 `""`，配置项是死代码 | 指定日志文件无效 |
| dt171 无 pid | `[]`（`handlers.py:390-393`） | `pids()` 命令失败返回 nil → `{"pid":null}` | 严格客户端遍历会炸；`[读码]` |
| `:9001` 有 path 无 file | `os.replace(None, dest)` → TypeError → 连接被丢 | `httpfile.go:431-455` 两分支都不进 → **200 `{"ok":true,"size":0}`** | 静默吞错；`[读码]` |
| `:9001` IPv4 起不来 | `logger.warning` | 返回 error，`main.go:126` 丢弃返回值、函数内无日志 | 完全静默 |
| `boce_run.timeout` | `Field(ge=10)` 默认 60、可选 | schema 实测 `"required":["targets","url","timeout"]` → **必填**；<10 走工具结果而非参数校验 | 不传 timeout 的调用方直接被 schema 拒绝；`[实测]` |
| `capture_stop` | 有 `description` 参数 | schema 实测无 `description` 属性且 `additionalProperties:false` | 带 description 的调用被 schema 校验拒绝；`[实测]` |
| 全工具 schema | Pydantic 生成 `default`/`minimum` | 实测 15 工具仅 required + description，**无任何 default/minimum** | LLM 不知道默认值；`[实测]` |
| 桥批量结果顺序 | `as_completed` 完成序 | 输入序 | 文案稳定性差异 |
| `list_targets` 空表 | `[]` | 未初始化切片 → `null` | 类型差异；`[报告]` |

---

## 3. 逐模块对比

### 3.1 弹窗/重定向（专章）

| 功能点 | Python（`boce.py`） | Go（`boce.go` / `boce_browser.go`） | 差异 |
|---|---|---|---|
| 模式分派 | `封堵`→RequestChecker；`重定向/弹窗/未知`→PyppeteerChecker（`:466-476`） | 同（`boce.go:190-215`） | 一致 |
| chromium 预检 | `isfile` → 自动下载 → dump-dom 自检 → 缺库装依赖 | 同（`boce.go:140-188`） | 一致 |
| 封堵判定 | requests 单发、`allow_redirects=False`、200 算成功 | net/http、`ErrUseLastResponse`、200 算成功（`boce.go:626-671`） | 一致 |
| 封堵并发 | ThreadPoolExecutor(thread_count)，提交间 sleep(interval) | 信号量 thread_count，提交间 sleep(interval) | 一致 |
| 重定向判定 | `jumped_urls` 非空 or `request_count>1` | `jumped \|\| requests>1` | 一致 `[实测]` |
| **重定向 count 执行** | `asyncio.gather` 并行 | **串行 for 循环** | ⚠️ 回归 |
| 弹窗判定 | 恒 False（未实现） | 恒 False（未实现） | 一致 |
| 弹窗副作用 | 真开浏览器导航 | 零流量 | 有意差异 §12#17 |
| goto 等待条件 | `waitUntil='domcontentloaded'` | `chromedp.Navigate`（等 load） | 有意差异 §12#18 |
| goto 后 | `sleep(3)` | `sleep(3)` | 一致 |
| `ERR_TOO_MANY_REDIRECTS` | 仅日志 | 仅日志 | 一致 |
| browser 关闭重试 | 异常串含 `Connection is closed` 才重启重试一次 | 同 | 一致 |
| 客户端期望 | `eu_policy.py:554-560` 要求成功率 > 90% | 同 | **弹窗用例两版都必红** |

**结论**：弹窗「有问题」是 Python 原版就没实现（客户端业务却按 90% 成功率验收），Go 忠实复刻了这个能力缺口；重定向判定一致；唯一真实回归是 count>1 串行。

### 3.2 抓包 dt5/dt6

一致项（`[读码]` 双向核对）：wire 形态 `{"res":bool}` 无 error 字段；dt6 未在抓幂等 true；同 path 先停旧；清旧 pcap 失败仅 warn；BPF 编译失败 = res:false；pcap 纳秒 magic `0xA1B23C4D`/snaplen 65535/DLT 1；4 种 magic 稳定排序 + 原子 replace；时间戳四级降级；promisc/SO_RCVBUF 失败仅 warn；stop 2s drain 上限（有意差异 §12#41）。

差异：H2/H3/H5 三项、`close(chan)` TOCTOU（H4），另加：

| 项 | Python | Go |
|---|---|---|
| 注册表写入时机 | 就绪后才写 | goroutine 启动前就写 → 启动窗口内并发 dt6 会真停掉 |
| `path:""` / `path:null` | 空串 → open 失败 false；null → TypeError 断连 | 一律归一为默认路径 |
| `single_queue:null` | None 为假 → 不动网卡 | nil → 默认 true → 改网卡队列 |
| 写盘错误 | 异常置 `_exc`，stop 报失败 | `f.Write` 返回值全部忽略 → 磁盘满仍报成功 |
| stop 超时 | join 30s 后 terminate | 无法强制终止，goroutine 残留持 socket |
| `extended:"   "` | strip 后为空 → 抓全量 | 原样编译 → 编译失败 res:false |
| userspace 时间戳基准 | `time.monotonic_ns()`（开机基准） | 进程启动基准 → 无 cmsg 时 ts_sec 接近 0 |
| cmsg ABI | Python 按平台 | 硬编码 64 位布局 |

### 3.3 dt16 python_cmd

Python 原版是 `eval(args[0])` + `eval("res."+arg)`，等于在靶机执行任意 Python。Go 没有解释器，v1.9.23 按验收客户端的两个极窄用法实现白名单（`os.popen('字面量')` + `read()/strip()` 等）。**有意差异**，但残留风险：

| 输入 | Python | Go |
|---|---|---|
| 白名单内表达式 | 正常 | 正常 |
| 其他表达式 | 正常执行 | 回 `{"error":...}` JSON |
| 非字符串 arg | `eval` 报错 → 断连 | 同（Unmarshal 失败） |
| `readlines()` | 返回 list | **不支持**（只支持字符串链）→ error JSON |

> 客户端目前只用 `read()`/`strip()`，未见问题；但白名单一旦不覆盖新用法，客户端会拿到 error JSON 而非挂死——这是 v1.9.23 的设计取舍。

### 3.4 :9001 HTTP 文件服务

一致项：`http_port` 读取（首条匹配、非法→9001、0=关）、IPv6 降级、路径不校验（只按 method 分派）、GET 三态（400/404/500）与 200 头、POST multipart 全部 quirk（多 file 续写、size 只报最后段、path 4096 上限、缺 path 全量消费后 400）、`.part` 原子 rename、临时文件清理、跨盘兜底、全盘 realpath（v1.9.22 撤销白名单）。

差异：见 §2.7 两条，另加 HTTP/1.0（Python 每响应断连）vs HTTP/1.1 keep-alive、`Server` 头少了 `Python/3.9.9` 后缀、401 体 JSON vs HTML、realpath 对多级不存在路径的解析深度不同、临时文件前缀 `socket_server-upload-` vs `socketstack-upload-`。

### 3.5 socket_listen dt171-175

一致项（`[读码]`）：dt171 三分支与键校验时机、启动后 sleep(5) 验 pid、无条件回 `{"pid":[...]}`、dt172/173 判活与未启动裸 `b"error"`、dt173 先解析后判活、dt174 仅 `ss is None` 判活、dt175 三态文案与 0.5s 轮询、`ss -lptn | grep users | awk` 管道逐字一致、cleandata 不清 cachedata 局部缓冲。

差异：

| 项 | Python | Go |
|---|---|---|
| 无 pid 时字段 | `[]` | `null`（H 级，见 §2.7） |
| 显式 `port:0` | 绑临时端口 | 一律改 30001 |
| dt173 / socketbin 权限 | 0666 & ~umask | 硬编码 0644 |
| dt172 排空 | 无上限（持续流量永不返回） | 10s 上限（未登记的有意加固） |
| 并发 | 模块级 ss 无锁 | 全 171-175 持锁（更安全，但 dt171 的 5s sleep 期间全部监听操作阻塞） |
| dt174 gzip | level 9 + mtime=now | level 6 + mtime=0（帧长度数值不同，解压一致） |

### 3.6 MCP 桥 15 工具

一致项：15 工具注解语义、锁类集合与「CAPTURE 成功保留锁」、池参数 5/600/10/50、`{"_error"}`/None/False 三条通用通道、cmd_exec 白名单与 stdout rune 截断、pcap 1000 条截断、boce_run 内层 `max(3,timeout-10)` 与外层 `timeout+10`、socket_listen fetch 首字节 `{` 判错、审计表结构与保留期、日检线程节奏。

差异分档：

| 严重度 | 项 |
|---|---|
| 高 | isfile/isdir 语义反转（H6）；`boce_run.timeout` 必填（§2.7）；`splitHostPort` 误拆 IPv6（H7） |
| 中 | `capture_stop` 缺 `description`；socket_listen stop 失败仍清 liveness；schema 缺 `default` + `additionalProperties:false` 拒未知参数；锁冲突文案 key 表示不同 |
| 低 | 建连 3 次退避重试 vs 单次；池复用前双探针；`connErrText` 分档文案；审计 200 **字节** vs 200 **字符**；`outcomes.error` 用 `""` vs `null`；审计 source_ip 真实 IP vs 固定 `internal`；错误态 `flows: null` vs `[]`；`exitcode=<nil>` vs `None` |
| 有意增强 | upgrade 的 `_applyLost` 竞态处理、下载失败写审计、`upgrade_mirror`/`upgrade_repo`/proxy 回退、配置误置键告警、双栈监听、upgrade 轮询 `dialOnce` |

---

## 4. 刻意差异 vs 未登记差异

设计文档 §12 已登记 67 条。本次新发现、**尚未登记**的行为差异：

1. 抓包给 goroutine 前就注册（Python 就绪后注册）
2. `path:""`/`path:null` 归一到默认路径（Python 分别 false / 断连）
3. `single_queue:null` 当 true（Python 当 false）
4. dt172 排空 10s 上限
5. dt173/socketbin 权限硬编码 0644
6. dt174 gzip level 6 + mtime 0
7. `:9001` 有 path 无 file 回 200（Python 断连）
8. `:9001` 失败体 `%q` 编码（控制字符下不是合法 JSON）
9. `:9001` HTTP/1.1 keep-alive（Python HTTP/1.0 断连）
10. dt20 畸形 JSON 静默（Python 断连）
11. `list_targets` 空表 `null`
12. 桥结果按输入序（Python 完成序）

---

## 5. 未证实项（不推测）

1. VLAN 真机 pcap 比对未做（仅核对内核头 + Python struct 偏移）。
2. BPF 漏包窗口的实际漏包量未实测。
3. `close(chan)` panic 未运行复现（代码推导）。
4. `:9001` 「有 path 无 file」Python 断连未实际执行。
5. 32 位平台 cmsg 解析影响未实测。
6. FastMCP 生成的 inputSchema 是否一定含 `default`/`minimum`：本机无 `mcp` Python 包，未运行验证（**Go 侧已实测**：无 default/minimum，见 §2.7）。
7. Python `socket_listen` 返回 `b"ok"` 在 FastMCP 序列化后的最终呈现（`"ok"` 还是 `"b'ok'"`）未实测。
8. 线上靶机部署的 Python 版本（`parse_qs` 的 `;` 分隔语义可能随版本变化）。

---

## 6. 建议修复顺序

| 优先级 | 项 | 改动量 |
|---|---|---|
| P0 | H1 重放器 panic（补 `len(trans) < 4` 守卫，v4/v6 两处） | 2 行 |
| P0 | 给 `handleConn` 加 panic recover（兜住所有未知 panic，避免单请求打死进程） | 5 行 |
| P0 | H2 VLAN 偏移 16/18 + 修测试夹具 | 3 行 |
| P1 | 弹窗/重定向 count>1 改并行（对齐 `asyncio.gather`） | 中 |
| P1 | H6 MCP isfile/isdir 语义对齐 Python（`exists:false` 不进 failed） | 小 |
| P1 | H8 dt20 活跃客户端检查（初始化 `-1` 或去掉测试注入） | 2 行 |
| P1 | H3 BPF 挪到 bind 前；H4 `close(chan)` 改 `sync.Once` | 小 |
| P2 | H5 抓包 recv 错误置 fatal；H7 IPv6 拆分改用 `net.SplitHostPort` + 方括号判定 | 小 |
| P2 | dt20 畸形 JSON 改为断连对齐；dt171 `[]` 对齐；`boce_run.timeout` 默认值 60 | 小 |
| P3 | §4 的未登记差异逐条补进设计文档 §12 | 文档 |

---

## 7. 修复与真机验收（v1.9.24，2026-11-02）

本节是上面 §0/§6 的处置结果。全部改动登记在设计文档 §12 第 68–80 条。
**验收窗口**：真机 `10.12.131.82`（联通信安EU）+ 本机；均用真实 MCP 工具
（`mcp__socketstack__*`）与真实 `:9000` 帧协议，不依赖单测结论。

### 7.1 已修并真机复验

| # | 修复 | 真机验收证据 |
|---|---|---|
| H1 | `rewritePorts` 守卫 + `handleConn` 顶层 recover | `[实测]` 造 3 帧 pcap（正常 20B / 短 2B / 短 3B 传输层），`force_ip_src`+`force_dport` 回放。**旧版 v1.9.23**：本机抓到完整 panic 栈 `index out of range [1] with length 0` @ `replayer.go:257`，进程直接死；82 部署版同样崩溃，systemd `NRestarts=9`（每次回放触发一次）。**新版 v1.9.24**：同夹具返回 `{"total_packets":3,...}` 正常 stats，进程存活 |
| H2 | VLAN auxdata 偏移改 16/18 + 夹具同步修正 | 单测 `TestCaptureVLANRestore`（去修复后失败 `tci wrong: 0000`，加回通过）。真机 pcap 内容的 VLAN 比对仍列为未证实（需现场带 VLAN 抓包） |
| H3 | BPF 注入挪到 bind 之前（`openPacketSocketFn(eth, bpf)`） | 单测覆盖 bpf 传入 open；漏包量未实测（见 §5.2） |
| H4 | `captureEntry.stopOnce` | 单测覆盖并发 dt5/dt6 不 panic |
| H5 | `isEthDownErr`：ENETDOWN/ENODEV 视为启动失败 | 单测覆盖；真机网卡 down 场景未做（需拔网卡） |
| H6 | `isfile`/`isdir` 改回 Python 语义 | `[实测]` MCP：不存在路径 → `{"ok":1,"results":[{"exists":false}]}`（旧桥同路径为 `{"ok":0,"failed":[{"reason":"agent 返回 False（业务失败）"}]}`）；存在文件/目录 → `exists:true` |
| H7 | `splitHostPort` 多冒号无方括号按裸 IPv6 处理 | 单测 `TestSplitHostPortIPv6` |
| H8 | `overrideClients` 初值 -1 | 单测 `TestActiveClientsDefaultUsesRealClients` |
| 弹窗/count | `count>1` 改 `sync.WaitGroup` 并发 | `[实测]` 同机同 URL 重定向模式：**旧版 v1.9.23 count=3 用 3.70s**（≈串行 3×1.2s），**新版 v1.9.24 count=3 用 1.27s**（count=1 为 1.82s）——并发成立 |
| dt5/dt6 默认值 | 默认值只在键缺失时生效 | `[实测]` 帧协议直连对比：旧版 `path:""`→`{"res":true}`、`path:null`→`{"res":true}`；新版 `path:""`→`{"res":false}`、`path:null`→**断连无响应**（Python `lexists(None)` TypeError 冒泡）、无 path→`{"res":true}`；dt6 同理（`path:null` 断连） |
| dt20 畸形 JSON | 返回 error → 断连 | 单测 `TestDT20MalformedJSONDisconnects` |
| dt171 pids | 无匹配返回 `[]` 非 null | 单测 + `[实测]` 82 `socket_listen start` → `{"pid":["4184686","4184686"]}`（列表而非 null） |
| `boce_run.timeout` | 改可选、默认 60 | `[实测]` MCP schema：旧桥 `required=[targets,url,timeout]`，新桥 `required=[targets,url]`；不带 timeout 调用成功（82 返回 `{"fail":1,"success":0,...}`，因封堵模式非重定向实现，行为与 Python 一致） |
| `capture_stop` description | 补 `description` 参数 | `[实测]` MCP schema：properties `+['description']`；带 description 调用成功 |
| `:9001` 无 file 字段 | 400→500 显式报错 | 单测 `TestHTTPPOSTPathWithoutFileField` |

### 7.2 验收中新发现并修复的缺陷（原审计未列）

| # | 缺陷 | 触发与后果 | 修复 |
|---|---|---|---|
| H9 | `pruneOldVersions` 只保护「正在跑的 Version + 最近 N 个」，不保护 `current` 软链目标 | `[实测]` 本机 `current → 1.8.3`（回滚态），起 v1.9.24 agent 验收，启动清理把 `/opt/socket/versions/1.8.3/` 整个删掉 → 软链悬空，`systemctl restart` 后服务起不来。二进制是从仍在运行的进程 `/proc/<pid>/exe` 捞回并恢复的 | `currentLinkTarget()` 读软链并加入保护集；回归测试 `TestPruneOldVersionsNeverDeletesCurrentLinkTarget`（去修复后失败）。设计文档 §12#80 |

### 7.3 仍为有意差异（不改）

- 弹窗模式未实现——Python 原版同样未实现，两版恒失败；客户端 `eu_policy` 对弹窗用例判红是原版既有行为。
- `:9001`「有 path 无 file」Python 是 TypeError 逃出 `except OSError` → 丢连接无响应；Go 改显式 500（不模拟静默断连，运维会误判网络故障）。
- v4↔v6 互转遇 <4 字节传输层段：Python `bytearray` 切片赋值会自动补零，Go 返回 nil = 原包回放（发畸形包不如发原包）。
- `targets` 里的 `host:port` 端口不生效——与 Python `registry.resolve` 一致（端口只由工具 `port` 参数决定），**不是缺陷**；本次验收一度误判，已用 `port` 参数复验。

### 7.4 单测稳定性说明

`TestBoceBrowserCountIsParallel` 初版用墙钟阈值（`elapsed > 3×单次`）判并行，
在满负荷跑全量测试时会误报（实测偶发 FAIL 且无测试名——命令经 `tail` 截断，
`--- FAIL:` 行被切掉，误以为是未知用例）。现改为直接统计并发峰值
（`maxInFlight >= 2`），不再依赖机器负载；去掉并发后该用例稳定报
「实际峰值并发 1（串行）」，加回即通过。

### 7.5 另修一个既有测试缺陷（非本次审计发现）

`TestPyReprPayload`（v1.9.23 引入的日志保真用例）本身是 flaky 的：
`pyReprPayload` 先把 JSON Unmarshal 成 `map[string]any`，再遍历 map 输出——Go map
迭代顺序随机，而 Python dict 保插入序。实测 30 次单跑失败 3 次（约 10%），
全量跑偶发 `--- FAIL: TestPyReprPayload`（got/want 键序不同，内容一致）。

修复：`pyReprPayload` 改为走 `json.Decoder` token 流，键按 JSON 原文顺序输出，
并 `UseNumber()` 保住整数原样（Python `repr(9000)` 是 `9000`）。嵌套对象/数组/
转义/非法 JSON 回落均有临时用例核过 20 次稳定。

---

## 8. 抓包（dt5/dt6）专项补完（v1.9.25，2026-11-03）

§3.2 列的抓包差异本次全部处置。**真机验收环境**：82（联通 EU，ens3，virtio），
v1.9.25 以 `systemd-run` + `unshare -m` 跑在 **:19000**，生产 9000/9001 全程未动。

### 8.1 内核 offload（本次新增，Python 原版也没有）

全仓 grep 确认：Python `socket_server` / `mcp_socket_server` 与 Go `internal/`
都**没有任何** `ethtool -K` / GRO / GSO / TSO / LRO 处理。Python 只用到
`ethtool -l`（:774/:1042 查队列）、`-L`（:847 设队列）、`-T`（:285 查时间戳能力）。

帧长实测（35 → 82 拉 20MB，AF_PACKET，MTU 1500）：

| 配置 | IPv4 帧数 | 最大帧 | >9000B 帧 |
|---|---|---|---|
| 全开 | 3535 | **21786** | 1221 |
| 仅关收侧 GRO | 17083 | 2974 | 0 |
| 收发两侧 GRO/LRO/TSO/GSO 全关 | 2815 | **1514** | 0 |

即：不关 offload，同一个报文在分流两端会抓成不同长度——业务按包比对必然判不一致。
TSO/GSO 是反方向（本机发出的"一帧"到线上被拆成多段），tx/rx-checksumming 同理
（校验和由网卡后填，抓包看到的是坏包）。

**v1.9.25 改动**：`tcpdumpStart` 在配置单队列之后调
`ethtool -K <eth> gro off lro off tso off gso off`。best-effort（设备 `off [fixed]`
或 ethtool 缺失仅 warn），**不随 stop 恢复**——比对窗口内多次抓包必须保持一致。

`[实测]` 82 ens3：抓包前四项全 `on` → capture_start 后全 `off` → 日志
「已关闭网卡 ens3 的 GRO/LRO/TSO/GSO」→ 抓到的 pcap **18617 包，最大帧 1514，
超 MTU 帧 0**。

### 8.2 其余抓包差异处置

| # | 项 | 处置 | 验证 |
|---|---|---|---|
| B1 | 注册表提前写 | 改到稳定窗确认存活之后（对齐 Python `ready` 后写表） | `[实测]` :19000 帧协议：启动窗口内并发 dt6 为 no-op（00:15:28），抓包继续跑到 00:15:30 由窗口后 dt6 正常停止，48 包 |
| B2 | stop 超时无强制终止 | 超时后 `src.close()`，再给 5s 收尾（对齐 `proc.terminate()`） | 单测 `TestStopCaptureEntryTerminatesStuckLoop`（去修复后失败「强关 socket 后 stop 应成功」） |
| B3 | 写盘错误被吞 | `writePacket` 返回 error，写失败即停采集 → dt6 `res:false` | 单测 `TestWritePacketSurfacesError`（`/dev/full`）；去修复后报「n=1 err=nil」 |
| B4 | 时间戳进程基准 | `unix.ClockGettime(CLOCK_MONOTONIC)` = 开机基准 | `[实测]` 对照：旧版首包 ts=**11764**（进程跑了 3h）；新版 ts=**2212759**（`/proc/uptime` 2213183） |
| B5 | 时间戳档位无追踪 | 记 `tsModeNow`，hw 档 ts[0]=0 时告警一次 | 与 Python capture.py:280-287 同语义 |
| B6 | cmsg ABI 硬编码 64 位 | 改 `unix.Cmsghdr` / `CmsgLen` / `CmsgSpace` | 编译期按平台；32 位无部署 |
| B7 | 空帧写入 | `n == 0` 跳过（Python `if not data: break`） | 单测 `TestCaptureEmptyFrameSkipped`（去修复后「记录区 92 字节，应为 76」） |
| B8 | 0 包跳过重排 | 无条件重排 | 与 Python 一致 |
| B9 | CPU 分配无跨网卡记录 | `cpuBinding` + `allocatedCPU`（Python `_allocated_cpus`） | 单测 `TestPickFreeCPUDistinctPerIface`（去去重后「两网卡分到同一 CPU1」） |
| B10 | 死代码 | 删 `readFirstLine`、`_ = divisor` | — |
| B11 | 日志缺口 | 补 IRQ 绑定逐条 / RPS/RFS / 重排完成 / 完成带 eth+path+包数+drops | `[实测]` 82 日志已见「已将…绑定到 CPU」「已禁用…RPS」「pcap 时间戳重排完成（18617 包）」「抓包完成 ens3 -> …：18617 包，内核丢弃 0 包」 |

### 8.3 仍为有意差异

- 抓包在进程内 goroutine，不落子进程（Go 无 GIL；v1.6.0 的子进程架构是为绕 GIL）
- stop 后 drain 有 2s 硬上限（Python 无上限，持续流量下会永不返回）
- dt6 wire 仍只回 `{"res":bool}`——与 Python handler 一致，四态由桥层构造

### 8.4 本次未做的验证（不推测）

1. 32 位平台 cmsg 解析：无部署环境。
2. 真机拔网卡触发 ENETDOWN→dt5 res:false：需现场操作。
3. stop 超时强制终止的真机路径：会让 pcap 不完整，只用单测覆盖。
