# 反向对拍 oracle（设计 §9.3）

Python 官方 test_e2e.py 不改一行作 oracle；以下两个脚本是基于其 recv 语义的派生：

- `e2e_go.py`：test_e2e.py 逐用例移植 + 三处修正（live Python 实测校准）
  - dt16 剔除（§12#1 有意不复刻）；HOST/PORT 头部可改
  - 版本断言改格式校验（1.3.0 为陈旧值）；dt9 路径每轮唯一（已存在 → makedirs FileExistsError → 断连 quirk）
  - dt122 现行 Python 已注释停用 → 断言空响应
- `e2e_go_extra.py`：test_e2e.py 未覆盖 dt（10/15/19/5/6/200/0）真机对拍

运行：先停本机 socket_server 服务，Go agent 监听 :9000/:9001，`python3 e2e_go.py`（需 root 的 dt 走 sudo）。
