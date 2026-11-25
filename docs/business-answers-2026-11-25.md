# Q1–Q5 业务答复梳理（2026-11-25）

依据：dpiAutoExcel 业务仓库源码 + 82/81 真机实测。以下每条都给了**证据**；
标注【我的结论】处是按证据推导的答案，最终仍以你确认为准。

---

## Q1：`pcapdump.stat` 的「写文件完成」看哪个字段？

**答：`savetask` 块（第二块）的 `openfile_now`，不是 `$10` 碰到的任何一个 loss 字段。**

证据链：

1. 真机 pcapdump.stat 的第二块表头（82/81 一致）：
   ```
   savetask recv write_blk recv_null fcreate_err fcreate_ok fclose_cnt st_used st_replace memover_loss openfile_now
   ```
2. 业务用例 pcapdump.py:326-331 等的是 `tail -n 1 | awk '{print $10}'` —— 由于
   `tail -n 1` 取的是**文件里最后一块（savetask）的 all 行**，$10 = **`openfile_now`**
   （savetask 块第 10 个数据列；wtask 块只有 13 列且不在最后一行）。
3. 语义自洽：`openfile_now` = 当前未关闭的文件数，归零即「所有 pcap 写完（fclose）」。
   业务同文件里日志审计的判据就是 `fopen_ok == fclose_cnt`（dpistat.py:674-696），
   同一套「文件开关配对」语义。

**上一轮报告说错了**：我说 $10 落在 `marex_amt_loss` / `memover_loss`，
那是按「tail 取到 wtask 块的 all 行」或「数错列」推的。实际 savetask 块 all 行
$10 = openfile_now。**R3 报告 Q1 的前提错误，以本答复为准。**

R3 报告里的另一个细节维持：桥侧解析后该字段的可寻址写法是
`field=total.openfile_now`（块 2 行名 total；`detail.all.*` 只能取块 1 的列）。
探针实测：`lookupField("total.write_blk")` 命中、`detail.all.write_blk` 不命中。

顺带修正：Python `wait_pcapdump_writeover`（dpi.py:1327）用的
`grep all | tail -n 1` 与业务用例（`tail -n 1`）取的是同一行（savetask.all），
两处一致，都是 openfile_now。

## Q2：`flow.stat` 的 `grep all -A 70` 够不够？

**答：当前够，但比 Python 原版脆；建议桥侧改用 concurrent_cnt 直取。**

证据：

1. 82 实测：`all` 行在第 56 行，`concurrent_cnt` 在第 113 行，间隔 57 行，
   `-A 70` 覆盖到 126 行，当前余量 13 行。✔ 能取到（实测命中）。
2. 这个 `grep all -A 70` 本来就来自业务仓库 dpistat.py:105（flow2dict），
   不是桥自创——业务的魔法数字，桥照抄了。
3. 但 Python `wait_flow_timeout`（dpi.py:236）**不用这个窗口**，它直接
   `grep concurrent_cnt | awk '{print $2}'`，与文件行数无关。

**结论**：`dpi_read_stat kind=flow` 保持现状没问题（与业务 flow2dict 对齐）；
但 `dpi_wait_stat` 等 concurrent_cnt=0 的场景，建议在 flow kind 的等待路径改用
`grep concurrent_cnt` 直取（一处小改），彻底摆脱窗口依赖。是否改，等你拍板。

## Q3：FTP 服务器是否在 NAT 后？

**答：按证据推断「不需要 NAT 修正也大概率能用」，但最终取决于你部署的 FTP 地址类型。**

证据：

1. 业务原版 `wget_ftp`（socket_linux.py:588）根本不用 FTP 协议栈——它直接
   `wget` 命令行下载。wget 的被动模式处理与 curl 同款（数据连接默认用控制连接
   的对端 IP），所以 Python 版天生免疫 PASV NAT 问题。
2. 桥侧 Go 版是自己写的 FTP 客户端（dpi_ops.go:780），PASV 原样采信服务器返回
   的 IP——这是我提 N12 的原因。
3. FTP 地址来自 versions.json（运维侧维护），形如 `ftp://主机/路径`。现场
   FTP 服务器与靶机/中央的相对位置我从代码里推不出来。

**建议**：无需你答复即可安全落地——桥侧无条件改用「控制连接对端 IP + PASV
端口号」（wget/curl 同款行为，NAT 内外都正确，且对无 NAT 场景零影响）。
这条从「待确认」降级为「直接修」，除非你明确知道现场有「PASV 返回地址与
控制连接地址不同且必须按返回地址连」的服务器（很少见）。

## Q4：`darea` 1/2/3 与「入向/出向」是否同一维度？

**答：不是同一维度。darea 是业务域（信安/数安/网安/深度合成），入向/出向是
流量方向，两套正交。IP 库四态设计可直接落地，映射层留空的做法正确。**

证据：

1. marex_helper.py:78-81 明确注释：darea 1=信安、2=数安、3=网安、**4=深度合成**
   ——四个值都是「业务域」而非方向。
2. darea 决定的是 XDR 日志类型（PCAPDUMP_IS/DS/NS）与上传路径里的 pcaptype
   （0x04a1/0x04a5/0x04a3）（pcapdump.py:218、marex_helper.py:70-77）。
3. 「入向/出向」在业务里确实存在，但出现在**另一张表**：log_active.py:68 的
   `actdomain入向` / `actdomain出向`（logtype 25/28），与 darea 无任何交集——
   两套维度在同一个 config 里并列出现。
4. DPI 工作模式名 `com_cmcc_is` / `com_cucc_isbns`（dpi.py:561）里的 is/b/ns
   同样是域（信安/信安+数安+网安?），不是方向。

**结论**：IP 库按「机房内外四态」（internal/inbound/outbound/external）实现，
不与 darea 做映射。若未来发现 XDR 上传路径需要方向维度，再在映射层加。

## Q5：VLAN 报文回放时 `force_ip_*` 应当生效还是原样？

**答：应当生效。N11 按回归修（而非设计），证据充分。**

证据：

1. Python 原版 `modify_packet`（replayer.py:585-589）**先解 VLAN** 再取
   payload 做 IP 解析——即 Python 的 force_ip 对 VLAN 包是生效的。
2. 业务用例传参链（pcap_send → replayer）中 force_ip_src/dst/sport/dport
   与 vlan 无联动约束，没有「VLAN 包不改写」的设计痕迹。
3. Go 版 `buildModifiedPacket` 漏了解 VLAN 这一步（调用链 R3 已实证），
   是移植疏漏，不是口径选择。

结论维持：N11 按 P1 回归修复。

---

## 附：本轮连带修正的历史结论

| 项 | 修正 |
|---|---|
| R3-Q1 前提 | `$10` 实际是 `openfile_now`（savetask 块），不是 marex_amt_loss/memover_loss；「Python 原版脆弱」的结论保留，但脆弱点在 `grep all` 可能命中两块，当前取到的是最后一块即 savetask |
| R3-3.1 | `wait_pcapdump_writeover` 的桥侧等价写法确定为 `dpi_wait_stat kind=pcapdump field=total.openfile_now value=0` |
