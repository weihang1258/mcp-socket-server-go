# 反向对拍 oracle（设计 §9.3）

Python 官方 test_e2e.py 不改一行作 oracle；以下两个脚本是基于其 recv 语义的派生：

- `e2e_go.py`：test_e2e.py 逐用例移植 + 三处修正（live Python 实测校准）
  - dt16 剔除（§12#1 有意不复刻）；HOST/PORT 头部可改
  - 版本断言改格式校验（1.3.0 为陈旧值）；dt9 路径每轮唯一（已存在 → makedirs FileExistsError → 断连 quirk）
  - dt122 现行 Python 已注释停用 → 断言空响应
- `e2e_go_extra.py`：test_e2e.py 未覆盖 dt（10/15/19/5/6/200/0）真机对拍
- `restart_window_barrier.py`：六轮验收 P2 复测脚本（v1.9.13 依据，回函 §十四）。
  走真 MCP（`MCP` 常量，默认 `http://127.0.0.1:9010/mcp`）对指定靶机做
  「systemd-run 定时重启 + 5 路栅栏齐发对准 TERM±偏移」的并发复现：
  `python3 restart_window_barrier.py <target> <并发> <偏移ms>`
  （偏移负=TERM 前正=TERM 后；三组参考：-50 全活 / +15 在途跨 TERM / +300 空窗）。
  结论（2026-11-01 实测）：TERM 后 ≥几 ms 的调用毫秒级自愈，「在途跨 TERM 全败」
  为物理不可救，命中窗口 <3ms 难以稳定复现。

运行：先停本机 socket_server 服务，Go agent 监听 :9000/:9001，`python3 e2e_go.py`（需 root 的 dt 走 sudo）。
