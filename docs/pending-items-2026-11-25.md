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
| I10 | clean_stat 语义 vs Python dpi.py:190 逐行对照：cmd1 首轮不发、失败路径 cmd1+sleep5+continue 等价；Python 失败路径多发一次 cmd1（幂等，无害） | ✅确认对齐；**追加改良**（commit d9852db）：Python clean_stat 在 dpiAutoExcel 是从未被调用的死代码，首轮不发 cmd1 依赖调用方先手动清空——工具版改为进循环前先发 cmd1（幂等），"调用即清空"语义自洽，82 真机复验 rounds=1 通过 |
| I11 | 计数一致性 6 处：kind 枚举漏 flow_wait（三方 23/34/35 矛盾）、statKinds 注释、contract_test 注释 45、RegisterTools/transport 注释 11 类 | ✅已修（commit d9852db） |
| I12 | directionOf 与 Snapshot.Direction 四态 switch 重复（两份真相） | ✅已修：ip_lookup 与 pcap 流方向统一走 Snapshot.Direction |
| I13 | （R5-E 效率审查，commit 3459cef）Contains 线性扫：5 万前缀未命中 ~390µs，1 万对判定秒级 CPU，ponytail 注释计算偏差 150 倍 | ✅已修：mergeSegs 合并重叠段 + lastAddr 二分，实测 387ns（~1000x） |
| I14 | ip_lookup 纯内存却经 runEnvelope 逐靶机建连（@tag 批量白连、靶机宕机反报 network 错） | ✅已修：预计算后直接组装信封 |
| I15 | parseHeaderZipKind 每行 3 次分词（2 次 strings.Fields + 全 kind splitCols） | ✅已修：复用 fields，splitCols 仅 3 个 kind |
| I16 | bitsSpan 死代码 ~30 行 | ✅已删 |
| I17 | （R5-D Go 陷阱审查，commit 9ea17bf）**Contains 漏 v4-mapped**：::ffff:x.x.x.x Is4()==false 走 v6 列表 → mapped 查询全 false；agent 双栈抓包有意回 mapped 串，此类流方向全错 | ✅已修：Contains 无原则 Unmap；82 真机复验 mapped/plain 同判 |
| I18 | lookupField 裸 row 名 fallback 返回随机 map 值（迭代序）→ mirrorvlan_limit 等多字段行 wait 判定非确定 | ✅已修：多字段行命中 row 名返回 false，歧义显式失败 |
| I19 | Loader.Load 锁跨远端 IO → 全进程 ip_db_load 串行化到 socket 超时量级 | ✅已修：下载/解析移出锁，mu 只护 swap |
| I20 | clean_stat 内部编排 rounds×(timeout+5) 可超信封预算（BudgetEnd 钳 1s 中途死） | ✅已修：入参加大时校验预算报业务错误 + 描述补耗时公式 |
| I21 | （R5-A 逐行审查，commit a5600ac）**dpiCleanStatIn.Timeout 遮蔽 BaseIn.Timeout**（同 json:"timeout" 键，外层胜出）→ 信封超时永久默认 300s、预算校验死代码 | ✅已修：单轮等待改名 round_timeout_s |
| I22 | xrt total 读取不查 code：文件缺失静默重发破坏性 cmdmsg；空输出（cmdmsg 清空瞬间 xrt.stat 重建窗口，82 实测）按 Python except 语义归入重试 | ✅已修：code!=0 报错、空输出重试 |
| I23 | ip_lookup resolve 0 台伪造 targets 填 Ok=true 绕过失败行契约 | ✅已修：走 emptyResolveEnvelope |
| I24 | parseLine 无脑取最左两个 IP 列：ID 列为 IP 形态时真实区间被错建成 ID 段（静默错判） | ✅已修：按列数定起止列（4+列取 3/4、2 列取 1/2、3 列回退）+ 脏列回退，补回归测试 |
| I25 | loadOne sha 命中路径 mgr.Get 在锁外：并发 Set 竞态 → skipped=true 报另一份统计 | ✅已修：cache 查与 Get 同 mu 区间 |
| I26 | （R6 自复审，不使用子代理，commit 972690e）**clean_stat 预算校验死区**：BaseIn.Timeout==0（调用方只加 round_timeout_s 不动信封 timeout）时校验被跳过，默认 300s 预算下 round_timeout_s=120×3 仍中途死 | ✅已修：budget 缺省回落 toolDefaultTimeout，默认场景也校验 |
| I27 | waitFlowTimeout 对 concurrent_cnt 空读（文件缺失/格式变更）白等到超时 | ✅已修：首轮与循环内空值直接报错 |
| I28 | 流超时/预算报错文案不含 actionable 信息（活流提示、实际预算值） | ✅已修 |
| — | 复审点 13-25 逐项确认无问题：mergeSegs 相邻不合并无害（不重叠前提不破）、跨族交错排序下每族 lastAddr 仍全序、ext_xrt 分隔线 58 字符匹配、mvl speed 列保住、flow_wait 多行覆盖语义与 Python 一致、ip_lookup 审计路径与其它工具一致 | ✅确认 |
| — | （R7 二轮自复审，不使用子代理）真机 MCP 协议实测：10001 对边界报业务错、10000 对 0.28s 完成（二分实锤）、错误 @tag 走 noResolveReason、非法 IP 报 pairs[N].src、mapped IP 命中、schema 里 timeout/round_timeout_s 双键分离、预算校验实测拦截 390s>300s、timeout=400 放行执行、审计链完整（含失败路径）、跨族段 Skipped 计数有出口（补 TestCrossFamilySeg 验证）、TryAcquire/Release 互斥语义与 LkSystem 相容、agent 侧零改动、部署与 HEAD 一致；已知无害预留：StatData.Truncated 从不设置（现实 stat 最大 34KB，CmdExec 64KB 截断兜底） | ✅确认，无新缺陷 |

**全部 A/B/C/G + R5 复审完成。**

## J. 发版（2026-11-26）

**v1.9.28 已发版**：scripts/release.sh 通过（静态链接闸门 + sha 923abde3… + gh-proxy 镜像回源验证 OK）。
82 bridge_upgrade 1.9.26→1.9.28 成功（bridge_version 复核 1.9.28），升级后真机复验全部通过：
ip_db_load（9 段/53 前缀）、ip_lookup 六对四态（含 mapped）、dpi_clean_stat（cleaned=true），
tcpsegment/mirrorvlan_limit 新 kind、pcap_extract_flows S4 方向字段（outbound/external）。
35 仍为 1.9.21（另行安排）。

## K. 全量铺开（2026-11-26 续）

三台靶机全部升级至 v1.9.28：35（bridge_upgrade，apply 阶段 ECONNRESET 为 dt20 自杀式重启竞态，
轮询确认 1.9.28；本机桥 systemctl restart 加载新二进制——**发现本机工作站就是 35**），
32（1.9.21→1.9.28），82（1.9.26→1.9.28，见 J 节）。bridge_version 三台复核全 1.9.28。
本机 /opt/socket/versions/1.9.28 sha 与 release 资产一致（923abde3…）；
1.9.26/27/27-ipdb/27-p0fix 目录保留作回滚锚点。**v1.9.28 铺开完成，台账全部收口。**

## L. 桥版本补 bump 与快照对齐（2026-11-26，follow 侧复审引出）

BridgeVersion 0.4.0→0.5.0（c77eb39）：自 S4 起工具集 15→48 未动版本号，按「能力变更升版本」补齐；
target_add/target_remove 的 port 描述统一括号风格（e6ee81f），其余 46 工具本就一致。
本机源码已 bump 但**尚未构建部署**（运行中的桥实测仍报 0.4.0，需 go build + systemctl restart 后生效）；
follow 平台 mcp_tool 快照按页面「测试连接」同口径刷新至 48 工具（ip_db_load/ip_lookup/dpi_clean_stat
入库，行级启停保留；port 描述仍为旧文案，随下次桥部署自然对齐）。

## M. P-INSTR 服务级说明瘦身与 0.5.1 bump（2026-11-27，follow 侧方案 A）

ServerInstructions 2,716→约 1.6k rune：能力总览压成 12 类一行式（48 工具名一个不少，TestServerInstructionsExist
继续逐名校验），触发词合一行，典型序列留五条，结果约定保留信封/error_type/cleanup.verified/@tag/不可逆确认。
新增 TestServerInstructionsSlim：>1500 rune 直接红（重写压缩，不许抬线）。
BridgeVersion 0.5.0→0.5.1：说明面变更 + 线上桥仍在跑 0.4.0，本次随部署一并到位；部署判据=
:9010 initialize 的 serverInfo.version=0.5.1 且 instructions≤1500。go test mcpbridge + cmd 全绿。

## N. 恢复客户端 curl 直传接口（2026-11-28）

原 Python `file_transfer` 的设计是返回客户端直连靶机 :9001 的 curl 方法，明确客户端文件不经
远端 MCP 桥中转。Go v3 工具面改造新增桥侧 `file_get/file_put`，把原工具降级为 `file_transfer_hint`，
并在抓包/回放/命令等描述里默认桥中转，违背了原设计。现删除公开 `file_get/file_put`，恢复
`file_transfer`，输出 `target/ip/http_port/download/upload`；curl 增加 `-f` 避免把 HTTP 错误体当文件。
桥侧内部 `httpUpload/httpDownload` 保留，升级和 DPI 安装包流程不受影响。

- 工具总数 48→46，BridgeVersion 0.5.1→0.6.0；服务说明与 replay/shell/pcap 引用同步。
- 新契约测试覆盖：IP/端口/命令、IPv6 URL、未知标签、无网络生成；`go test ./... -count=1`、
  `go vet ./...` 通过。
- 82 真机 curl 往返通过：客户端 `/tmp` → 82 `/home/tmp` → 客户端 `/tmp`，61B 三份文件
  sha256 均 `48428bf3da41ed9f48c3f0a4b6a478b26107be9d2ae4b477bf300689dceac375`；靶机测试文件已删除。
- :9001 GET/POST 行为不变；直接 curl 要求靶机 1.7.0+、`http_port` 非 0、客户端到该端口可达。
- **已发布 v1.9.29**（commit 2724e2c，BridgeVersion 0.6.0）：release 资产 23,906,397B，sha256
  `4b0a44671fa87d39c9071ec451f637e4ecdbf79e384a74ac431dbef9c01948f2`；gh-proxy 镜像回源校验通过。
- 本机桥已切换 `/opt/socket/versions/1.9.29/socket_server`（与 release sha 相同）并重启。
  新 MCP initialize 实测 serverInfo.version=0.6.0、46 工具；旧 file_get/file_put/file_transfer_hint
  均消失，file_transfer 实调返回正确 ip/http_port/download/upload。
- 本机 35 的 agent 也随 current 切至 v1.9.29；其他靶机未在本次指令中要求铺开。
