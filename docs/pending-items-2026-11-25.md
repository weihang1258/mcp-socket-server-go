# 问题与待处理项总台账（2026-11-25，五轮审查收敛版）

来源：R1–R4 审查 + Q1–Q5 业务答复 + IP 库设计修订。
每项标注：状态（待修/已确认不修/文档化）、级别、规模。
**本台账是唯一的执行清单**，与各轮报告冲突处以本文件为准。

---

## A. 必修项（代码缺陷，按优先级排序）

| # | 项 | 级别 | 规模 | 状态 | 一句话描述 |
|---|---|---|---|---|---|
| A1 | file_put chunked | **P0** | 3 行 | ✅已完成 | `tools_file.go:688` io.Pipe 无 Content-Length → agent 400 empty body，file_put/dpi_prepare_package 全断。修法：`req.ContentLength = len(head)+fi.Size()+len(tail)` |
| A2 | uploadFile dt24 用 send | **P0** | 1 行 | ✅已完成 | `protocol.go:947` 多 4B 帧头 → agent「接收46原始42」断连，dpi_policy_write/dpi_policy_put 坏。修法：`send(24,…)` → `sendRaw(…)`（真机已验证正确序列） |
| A3 | N11+N20 回放改写 | P1 | ~25 行 | ✅已完成 | buildModifiedPacket 不解 VLAN（force_ip 对 VLAN 包失效）+ 顶部三处短包 panic（v4 <20B、v6 <40B）。修法：顶部长度守卫 + 整段 defer recover→nil（对齐 Python except→原样发送） |
| A4 | N13 FTP 多行响应 | P1 | ~10 行 | ✅已完成 | expect 只读首行，多行 banner 后续错位。修法：读到 `code-` 续读到 `code ` |
| A5 | N12 PASV 采信服务器 IP | P1 | ~5 行 | ✅已完成 | Q3 已答复：Python 原版走 wget 天然用控制连接 IP。修法：无条件用控制连接对端 IP + PASV 端口（wget/curl 同款） |
| A6 | N14 配置项不生效 | P1 | ~30 行 | ✅已完成 | mcp.pool.* 4 项 + behind_proxy 解析了但没传进 BridgeConfig。修法：接入或从配置删除 |
| A7 | P1-1 帧长无上限 | P1 | ~10 行 | ✅已完成 | dataLen int32 负数=静默僵死、超大值吃内存。修法：负数断连 + 可配置上限默认 2GB |
| A8 | P1-3 停止失败仍删登记 | P1 | ~5 行 | ✅已完成 | `capture.go:94-97` stopCaptureEntry 返回值被忽略，超时实例被删导致锁泄漏 |
| A9 | P1-4 句柄双关 | P1 | ~10 行 | ✅已完成 | recv 循环 256/272 与 stopCaptureEntry:564 三路径都会 src.close()，unix.Close 重复关可能关掉复用的 fd。修法：src 内部 sync.Once |
| A10 | P1-6 dt200 无上限 | P1 | ~15 行 | ✅已完成 | pcap 流提取无条目上限，大目录吃内存。修法：条目上限+早停 |
| A11 | N1 agent 无写超时 | P1 | ~5 行 | ✅已完成 | 全包 0 处 SetWriteDeadline，客户端不读时 goroutine 永久持有数百 MB。修法：handleConn 设 SetDeadline |
| A12 | N2 桥侧 4 处 recvN 无上限 | P1 | ~20 行 | ✅已完成 | protocol.go:206/237/311/596（596 处已核，dt174 fetch 走 recvN(int(n))）。修法：抽 recvNChecked(n,max) 统一走 |
| A13 | N19 mcp restart 卡 stdio | P2 | 3 行 | ✅已完成 | mcpAction 白名单无 restart，实测掉 stdio 阻塞。svc.MCPRestart 已存在，纯接线 |

## B. 应修项（P2/P3，资源与健壮性）

| # | 项 | 级别 | 规模 | 状态 |
|---|---|---|---|---|
| B1 | P1-2 排序双倍内存 | P1(内存) | ~40 行 | ✅已完成：isMonotonic 早退，跳过全量排序 |
| B2 | P1-5 dt3 下载整文件进内存 | P1(内存) | ~30 行 | ✅已完成：拿到长度后流式落盘解压（影响面=readFileB64 配置读取） |
| B3 | P2-1 下载 CopyBuffer 错误被吞 | P2 | 2 行 | ✅已完成 |
| B4 | P2-2 .part 关盘错误不查 | P2 | 2 行 | ✅已完成（与 A1 同路径） |
| B5 | P2-3 CPU 绑定不释放 | P2 | ~10 行 | ✅已完成：抓包结束恢复原 affinity |
| B6 | P2-4 选核错 CPU1 + 日志误导 | P2 | ~10 行 | ✅已完成：cpuset 交集为空时明说 |
| B7 | P2-5 三套版本比较器 | P2 | ~40 行 | ✅已完成：统一到 compareVersions 一套 |
| B8 | P2-6 文件锁未落地 | P2 | ~15 行 | ✅已完成 |
| B9 | N3 每帧重分配 acc | P2 | 1 行 | ✅已完成：`acc = acc[:0]` |
| B10 | N4 listen data 无上限 | P2 | ~8 行 | ✅已完成：默认 256MB 上限+warn（Python 同为无上限，保真可暂缓） |
| B11 | N5 replayer 整文件读 | P2 | ~30 行 | ✅已完成：os.Open 逐记录读 |
| B12 | N6 cleanEnv 原地复用 | P2 | 1 行 | ✅已完成：make 新切片 |
| B13 | N15 probeAlive 留死 deadline | P2 | 1 行 | ✅已完成：探针后恢复 |
| B14 | N16 审计清理只启动跑一次 | P2 | ~10 行 | ✅已完成：Write 内计数触发或日级 timer |
| B15 | N17 listen 队列满窗口 | P2 | — | 观察：实测推演能退出，风险低，暂不动 |
| B16 | P3 系（N7 frame.Read 死代码注释、N8 stripSudoPrefix、N9 关防火墙显式日志、N18 origLen） | P3 | 各≤5 行 | ✅已完成/文档化 |

## C. 功能缺口（新增能力）

| # | 项 | 状态 |
|---|---|---|
| C1 | **IP 库 + 方向判定** | ✅已完成（2026-11-25）：internal/ipdb 三文件 + tools_ipdb.go 两工具（ip_db_load/ip_lookup），47 工具；82 真机验收通过——默认库 9 段/53 前缀，四态判定全对，第二独立库互不干扰，sha 未变跳过重建，变更后重载判定跟随。部署 1.9.27-ipdb |
| C2 | stat 覆盖 23/76：raw_text 兜底 kind + 10 个高价值结构化 kind（tcpsegment/ring/malicious/evilblock/proto_public/mirrorvlan_limit/pcapdump_storage/eu_overseaip/sysinfo/ext_xrt） | ✅已完成（2026-11-25）：dpi_read_stat 33 种 kind；新增 mvlimit/portkv/rawtext 三种解析模式 + splitCols 多空白切列；82 真机验收 10 个 kind 全部出正确字段（tcpsegment 17 字段、ext_xrt 按端口行、evilblock 36 个 sts、mirrorvlan_limit 两段含 speed 带单位、pcapdump_storage 空表头返 0 行、raw_text 按行号原样） |
| C3 | dpi_clean_stat 未实现（cmdmsg xsa 1 + wait_flow_timeout + xrt total==0 三轮编排，dpi.py:190） | ✅已完成（2026-11-25）：48 工具；对齐 Python 三轮编排（等 concurrent_cnt==0 → 查 xrt total → 非 0 重下发 + 5s）；82 真机验收 cleaned=true rounds=2 elapsed=5s，清空后 concurrent_cnt=0、xrt total=0 |
| C4 | dpi_wait_stat 的 flow 等待路径改 `grep concurrent_cnt` 直取（Q2 答复，摆脱 -A70 窗口依赖） | ✅已完成（2026-11-25，随 C3）：新增 flow_wait kind（`grep concurrent_cnt` 直取）；82 真机验证 concurrent_cnt=0 正确解析；dpi_clean_stat 内部等流超时已走该路径 |
| C5 | pcap_flow_extract 结果补方向字段（C1 的联动落点） | ✅已完成（2026-11-25，随 C1）：pcap_extract_flows 每条流附加 src_ip_in/dest_ip_in/direction（默认库未建库则省略）；82 真机验证 outbound/external 正确 |

## D. 业务答复（已全部完成）

Q1 pcapdump 写完 = total.openfile_now（R3 数错列已修正）；
Q2 -A70 够用但建议直取（→C4）；
Q3 wget 语义无条件修（→A5）；
Q4 darea 与方向正交，IP 库四态直接做（→C1）；
Q5 VLAN 包 force_ip 应生效（→A3 按回归修）。
详见 docs/business-answers-2026-11-25.md。

## E. 明确不修（既定决策/保真）

- :9000/:9001/:9010 无鉴权全地址监听——既定设计，不动。
- dt6 布尔返回——协议契约。
- N9 关防火墙/SELinux——Python 原版一致（保真），仅在启动日志加一句提示（B16 内）。
- N17 listen 队列窗口——推演能退出，观察。
- v4↔v6 半成品分支照抄语义——注释已如实，守卫已到位（R4 确认）。

## F. 执行顺序建议

1. **A1+A2**（4 行，修完真机回归 file_put / dpi_policy_write / dpi_prepare_package）
2. **A3–A13**（P1 批 + N19，~130 行）
3. **发版 v1.9.28**（scripts/release.sh，全量测试 + 真机验收）
4. **C1 IP 库**（新功能，与修复解耦）
5. **C2/C3**（DPI 缺口）
6. **B 批**（可随下一版捎带）

---

## G. 复核增补（本台账写成后的一轮专项复查，2026-11-25）

对 A–F 全部条目回溯了代码证据行，另查了此前未覆盖的面，新增 2 项：

| # | 项 | 级别 | 规模 | 描述 |
|---|---|---|---|---|
| G1 | force_sport/dport 类型截断无校验 | P3 | 2 行 | `tools_traffic.go:237/241`：`uint16(a.ForceSport)` 静默截断，传 70000 会变成 4464 并按 4464 改写，无告警。修法：>65535 时直接报业务错误 |
| G2 | chromium zip 无完整性校验 | 观察 | — | `downloadChromiumZip` 只看 HTTP 200，断流会得到半截 zip，随后 unzip 失败（可自愈重下），与 Python iter_content 一致（Python 也无校验）。**保真，不修** |

复查确认无问题的（防再查）：
- backupDPI force 时间戳：Python 用 gettime(6)=`%Y%m%d`（年月日），Go 用 `150405`（时分秒）。**两者不同但 Go 的更合理**（同日二次强备份不会重名），非 bug，记录差异。
- dt21/22/24 bin 状态机（server.go:95-215）逐行过：dt22 恰 8B 进 bin、content==length 收满回 23 ok、`^$` 空文件哨兵、收尾清 content——与 Python protocol.py 逐条对应，无偏差。
- boce 链：getBrowser 全程持 browserMu、超时兜底 closeBrowser 后回执 killed/verified、下载互斥 chromiumDownloadMu + double-check、unzipInto 消毒——闭环。
- probe_visit 超时链：timeout 下限 10s、inner=to-10、桥预算 to+10（比内部宽），与 P2-7 相关设计一致。
- pcap_extract_flows：桥侧展示层截断 1000 条 + truncated 标记；agent 侧仍全量（A10 要修的正是这一侧）。
- file_get 返回 sha256 可校验完整性；local_name 禁绝对路径。

## H. 结论

- A（必修）13 项、B（应修）16 项、C（功能）5 项、G（增补）1 项待修。
- E（不修）5 类有明确理由。
- D（业务答复）全部完成。
- 台账收口：**A 批（含 A1+A2 P0）、B 批、G1、C1+C5（IP 库）已全部完成（commits d97815e/b9900f5/a5c9c7a，2026-11-25）。C2/C3/C4 也已全部完成（2026-11-25）。

## I. R5 复审（2026-11-26，commit 06353e8）——C 批新增代码全面审查

| # | 发现 | 处置 |
|---|---|---|
| I1 | ipdb addrCountFloorBits 溢出位：diff+1==2^bits 时 carry 溢出 16B → v6 全区间错误拆 128+ 前缀 | ✅已修（返回满位宽）+ v4/v6 全空间边界测试 + 随机 3000 区间性质测试 |
| I2 | dpi_clean_stat 挂 LkNone，与 dpi_service 等设备操作不互斥 | ✅已修（LkSystem） |
| I3 | mirrorvlan_limit：真机每 worktask 段的 "vlan mirror failed" 列头行把 detail 段 seg 重置成 total，行名全错 | ✅已修（只有 worktask:/per-g 行切 seg），82 真机复验行名正确 |
| I4 | ip_db_load 多靶机同路径文件不同 → 后加载覆盖先加载（ip_lookup 无 host 维度） | ✅标注（描述+ponytail 注释）；单机场景无影响，多机差异化出现时再扩 key |
| I5 | Snapshot.Skipped 无出口（坏段静默消失） | ✅已修（LoadResult.Warning 字段 + 日志） |
| I6 | dpi_wait_stat/wait_file/clean_stat 负数入参无防护（every_s 负数 → 忙等烧 CPU） | ✅已修（正整数校验） |
| I7 | wait_stat 描述 operator 写 gt/lt 但实现只有 eq/ne/gte/lte | ✅已修（描述对齐） |
| I8 | contract.go ip_db_load/ip_lookup 缺 timeout_basis | ✅已补 |
| I9 | tools_traffic.go flowDirection 类型定义未使用 | ✅已删 |
| I10 | clean_stat 语义 vs Python dpi.py:190 逐行对照：cmd1 首轮不发、失败路径 cmd1+sleep5+continue 等价；Python 失败路径多发一次 cmd1（幂等，无害） | ✅确认对齐 |

**全部 A/B/C/G + R5 复审完成 → 待发版 v1.9.28（scripts/release.sh + 真机验收）。****
