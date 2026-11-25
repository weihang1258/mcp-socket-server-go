# 代码审查第四轮（2026-11-25）

基线：v1.9.27（HEAD `3a5c64a`）
方法：前三轮 45 项结论逐条回验；补读 `tools_bridge.go`、`cmd/socketstack/main.go`、`wire.go`、
`upgrades.go`（下载/推送链）、连接池全文、`upgradeViaSystem` 全文；回放改写边界用探针逐段实测。
本轮无真机操作（上轮已在 82 实测 file_put/uploadFile 两个 P0）。

---

## 零、结论速览

| 类别 | 结果 |
|---|---|
| 前三轮发现 | **全部确认为真**（无一条被证伪），两处历史修正维持不变 |
| 新增发现 | **2 项**：N19（CLI）、N20（N11 的panic面比说的更宽） |
| 修复方案 | 全部维持；两处补了细节 |
| 业务待确认 | Q1–Q5 原样保留，在清单最后 |

---

## 一、新增发现

### N19（P2）`socketstack mcp restart` 会掉进 stdio 模式卡死

`mcpAction`（`cmd/socketstack/main.go:155`）的白名单是
`start|stop|status|enable|disable`，**没有 `restart`**——而 agent 侧有（`main.go:52`）。
`svcDispatch` 的 mcp 分支同样没有 restart（svc 层其实有 `svc.MCPRestart`，只是没接）。

实测：

```
mcpAction([]string{"restart"}) → "stdio"
```

后果：运维在终端敲 `socketstack mcp restart`，进程不报错、不重启，**转入 stdio
MCP 模式阻塞读 stdin**，看起来像卡死。Ctrl+C 退出后什么都没发生。
`agent restart` 是好的，所以这个坑只在 mcp 侧。

**最优方案**（3 行）：`mcpAction` 白名单加 `restart`；`svcDispatch` mcp 分支加
`case target == "mcp" && action == "restart": err = svcMCPRestartFn()`。
svc 层函数已存在（`svc.go:230`），纯接线。

### N20（P3）回放改写的 panic 面比 R3 说的更宽（与 N11 同一修复）

R3 只实测了 14B/15B 两种。本轮补测：

```
v6 包 payload=10B / 39B（< 40B 头）  → PANIC: slice bounds out of range [:40]
v4 包 payload=10B（ihl 声称 20）     → PANIC: slice bounds out of range [:20]
v4→v6 / v6→v4 互转短传输层           → 不 panic（已有 len<4 守卫，返回 nil）
v4→v6 ICMP 3B                        → 不 panic
```

即 panic 只集中在 `buildModifiedPacket` 顶部的三处切片
（`payload[:40]`、`payload[:20]`、`payload[0]`），互转分支已经守好了。
**不改变 N11 的修复方案**（顶部加长度守卫 + 整段 defer recover → nil），
只是说明：修复范围覆盖 `ver==6` 分支，不止 IPv4。

### 本轮审过、确认没问题的（防止下轮再怀疑）

- `tools_bridge.go`：bridge_upgrade 全链（版本校验→下载 sha 校验→推送 multipart
  带真实 ContentLength→dt20 竞态标记→180s 轮询确认→审计终态一条）逻辑闭合；
  IPv6 拆分用 LastIndex 是文档写明的 rpartition quirk，非 bug。
- `PushBinary` 用 `strings.NewReader` → 自带 ContentLength，不受 file_put 那个
  chunked 问题影响（两个上传通道只有 `httpUpload` 坏了）。
- `EnsureReleaseBinary`：失败不建目录（防空壳）、tmp+rename 原子落盘、远端 sha
  可选降级本地计算——都对。
- `upgradeViaSystem`：预算耗尽后不把「还在跑」当「跑完了」、不确定时不 pkill
  agent、结果文件格式校验，全部正确。
- `Scheduler.Batch`：结果按索引写入无竞争；全局 50 并发闸门是进程级单例。
- `main.go`/`wire.go`：install/uninstall 的 help/unknown 都不执行实际操作；
  二进制漂移检测（/proc/<pid>/exe）闭环。
- `v4→v6`/`v6→v4` 半成品照抄分支：注释如实、守卫到位（短段返回 nil 不产出畸形包）。

---

## 二、前三轮结论回验

| 项 | 回验结论 |
|---|---|
| **N10 file_put chunked（P0）** | ✅ 真。`tools_file.go:688` io.Pipe → 无 Content-Length → agent 400。上轮真机已实测；`dpi_prepare_package` 同根因 |
| **uploadFile dt24 应 sendRaw（P0）** | ✅ 真。`protocol.go:947` `send(24,...)` 多 4B 帧头，agent 日志「接收46，原始42」。真机实测 `sendRaw` 后端到端成功；`dpi_policy_write` 被它带坏（读路径正常） |
| N11 VLAN 改写失效 + 短包 panic（P1） | ✅ 真，本轮再次探针复现（VLAN+仅端口 → nil）；panic 面见 N20（同一修复） |
| N12 PASV NAT（P1） | ✅ 真（业务面待 Q3） |
| N13 FTP 多行响应（P1） | ✅ 真 |
| N14 配置项不生效（P1） | ✅ 真。`BridgeConfig` 仍无 Pool 字段，`wire.go` 两处 Init 均未传池参数 |
| P1-1~P1-6、N1~N9、P2-1~P2-7、P3 系 | ✅ 全部维持原判（R3 已逐条回验过，本轮无新证据推翻） |
| 历史修正：P2-4 是 CPU1、P2-5 是三套比较器 | 维持 |
| N16 审计清理只在启动跑一次 | ✅ 真（长期驻留场景） |
| N17 listen 队列满窗口 | ✅ 真（P2，低概率） |

**没有一条被证伪。**

## 三、解决方案复核（是否最优）

| 项 | 方案 | 结论 |
|---|---|---|
| N10 | 桥侧 `req.ContentLength = len(head)+fi.Size()+len(tail)`，3 行，流式不变 | **维持最优**。本轮核对 `PushBinary` 的 multipart 构造方式，证实 head/tail 定长、ContentLength 可精确预算，方案成立 |
| uploadFile | `send(24,...)` → `sendRaw(...)`，1 行 | **维持**。真机已验证修正后 21/22/24 全通过、内容读回正确 |
| N11/N20 | 顶部守卫（v4 `<20`、v6 `<40`、`len(payload)<1`）+ 整段 defer recover → nil | **维持**。N20 证实守卫要覆盖 v6 分支；recover 是对齐 Python `except → eth_bytes` 的兜底 |
| N19 | 白名单 + svcDispatch 各加 1 行 | **维持**（svc 层函数已在，纯接线） |
| N13 | `expect` 读到 `code-` 续读至 `code ` | 维持 |
| N12 | 无条件用控制连接对端 IP 替换 PASV IP（curl 同款） | 维持，最终形态看 Q3 |
| N14 | 4 个池参数 + behind_proxy 接上或删除 | 维持 |
| P1-1 | 负数断连 + 可配置上限默认 2GB | 维持 |
| P1-2 | isMonotonic 早退跳过排序 | 维持 |
| P1-5 | dt3 拿到长度后流式落盘解压 | 维持 |

---

## 四、修复优先级（累计，本轮重排）

| 序 | 项 | 级别 | 规模 |
|---|---|---|---|
| 1 | N10 file_put ContentLength | P0 | 3 行 |
| 2 | uploadFile dt24 sendRaw | P0 | 1 行 |
| 3 | N11+N20 改写守卫 + recover | P1 | ~25 行 |
| 4 | N13 FTP 多行 | P1 | ~10 行 |
| 5 | N12 PASV | P1 | ~5 行 |
| 6 | N14 配置接线 | P1 | ~30 行 |
| 7 | P1-1 帧长上限（含负数） | P1 | ~10 行 |
| 8 | P1-3 / P1-4 / P1-6 / N1 / N2 | P1 | 各 5~20 行 |
| 9 | N19 mcp restart | P2 | 3 行 |
| 10 | 其余 P2/P3（含 N3/N16/N17/N15） | P2/P3 | — |

---

## 五、业务问题 Q1–Q5 —— 已完成答复（2026-11-25）

依据业务仓库源码 + 真机实测，五条全部有了结论，详见
`docs/business-answers-2026-11-25.md`。要点：

1. **Q1**：等的是 savetask 块的 `openfile_now`（当前未关闭文件数归零）。
   R3 报告里「$10 是 marex_amt_loss/memover_loss」的前提**数错了列**，已修正。
   桥侧写法：`dpi_wait_stat kind=pcapdump field=total.openfile_now value=0`。
2. **Q2**：`-A 70` 当前够用（余量 13 行），源头是业务 flow2dict 照抄；
   Python 的 wait_flow_timeout 其实是 `grep concurrent_cnt` 直取，与窗口无关。
   建议 `dpi_wait_stat` 的 flow 等待路径改直取（待你拍板）。
3. **Q3**：Python 原版走 wget（数据连接天然用控制连接 IP），Go 版自写客户端
   才有此问题。建议无条件改用「控制连接 IP + PASV 端口」（wget 同款），
   从「待确认」降级为「直接修」。
4. **Q4**：**不是同一维度**。darea=业务域（信安/数安/网安/深度合成，marex_helper
   注释明确，4 还有第四个值）；「入向/出向」在业务里是另一套（actdomain 表
   logtype 25/28）。IP 库四态直接落地，映射层留空。
5. **Q5**：应当生效，N11 按回归修。Python 先解 VLAN 再改写，业务传参无
   「VLAN 不改」约束，Go 是移植疏漏。

---

## 六、本轮覆盖范围

新读：`tools_bridge.go`（206 行全文）、`cmd/socketstack/main.go`（341 行全文）、
`wire.go`（343 行全文）、`upgrades.go` 版本查询/下载/推送链、连接池+调度器全文、
`upgradeViaSystem` 全文。探针实测 8 项（VLAN 端口改写、v6/v4 短包、互转短传输层、
mcp restart 分派等）。

**至此仓库内全部生产代码已至少审过一遍。** 若无新代码合入，下一轮审查
预期不会再有结构性新发现；建议转入修复验证（上表 1–9 项）与 Q1–Q5 业务答复。
