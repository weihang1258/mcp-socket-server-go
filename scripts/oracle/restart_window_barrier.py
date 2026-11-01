#!/usr/bin/env python3
"""验收场景精确复刻（六轮验收 P2 复测）：真 MCP + 计时栅栏。

用法: barrier_reuse_test.py <target> <并发> <offset_ms>
  offset_ms: 5 路齐发时刻相对靶机 TERM 的偏移（负=TERM 前，正=TERM 后）

三组偏移覆盖三种物理状态：
  -50  连接全活：正常齐发（回归确认）
  +15  请求在途跨 TERM：物理不可救，v1.9.13 只改进文案
  +300 重启空窗（监听已关、FIN 已达、服务未回）：
       v1.9.12 = 探针判死→新建 refused×3 失败
       v1.9.13 = dial 判死→弃复用→connectWithRetry 吃窗口→成功
"""
import json
import sys
import threading
import time
import urllib.request

MCP = "http://127.0.0.1:9010/mcp"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.12.131.82"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 5
OFFSET_MS = int(sys.argv[3]) if len(sys.argv) > 3 else 15
DELAY = 6  # systemd-run --on-active 秒数

session_id = None
req_id = 100


def post(payload, timeout=90):
    req = urllib.request.Request(
        MCP, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"})
    global session_id
    if session_id:
        req.add_header("Mcp-Session-Id", session_id)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        sid = r.headers.get("Mcp-Session-Id")
        if sid:
            session_id = sid
        body = r.read().decode()
    for line in body.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    if not body.strip():
        return {}
    return json.loads(body)


def handshake():
    post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "barrier-test", "version": "0"}}})
    post({"jsonrpc": "2.0", "method": "notifications/initialized"})


def call_tool(name, args, timeout=90):
    global req_id
    req_id += 1
    r = post({"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
              "params": {"name": name, "arguments": args}})
    if "error" in r:
        raise RuntimeError(r["error"])
    sc = r["result"].get("structuredContent")
    if sc is not None:
        return sc
    return json.loads(r["result"]["content"][0]["text"])


def target_clock_offset():
    out = call_tool("cmd_exec", {"targets": [TARGET], "args": "date +%s.%N"})
    return float(out["results"][0]["stdout"].strip()) - time.time()


def svc_start_time():
    out = call_tool("cmd_exec", {"targets": [TARGET],
                                 "args": "systemctl show socket_server -p ExecMainStartTimestamp --value"})
    res = out.get("results") or out.get("failed")
    return res[0].get("stdout", res[0].get("reason", "?")).strip() if res else "?"


def main():
    handshake()
    offset = target_clock_offset()
    before = svc_start_time()
    print(f"clock offset(82-35): {offset*1000:+.1f} ms | svc started: {before}")

    # 预热 2 轮齐发：N 条连接入池
    for i in range(2):
        barrier_round(None)
    print(f"warmup x2 done ({N} conns pooled)")

    t0 = time.time()
    call_tool("cmd_exec", {"targets": [TARGET],
                           "args": f"systemd-run --on-active={DELAY} systemctl restart socket_server"})
    t1 = time.time()
    term_35 = (t0 + t1) / 2 + offset + DELAY
    fire_at = term_35 + OFFSET_MS / 1000.0
    print(f"TERM in {term_35 - time.time():.2f}s, firing at {OFFSET_MS:+d}ms -> {fire_at - time.time():.2f}s")

    results = [None] * N
    barrier = threading.Barrier(N)

    def one(idx):
        s = fire_at - time.time()
        if s > 0:
            time.sleep(s)
        t_start = time.time()
        t_done = None
        try:
            out = call_tool("version", {"targets": [TARGET]})
            t_done = time.time()
            ok = not out.get("failed") and out.get("results")
            results[idx] = (t_start - term_35, ok, t_done - term_35,
                            json.dumps(out, ensure_ascii=False)[:200])
        except Exception as e:
            t_done = time.time()
            results[idx] = (t_start - term_35, False, t_done - term_35, str(e)[:200])

    threads = [threading.Thread(target=one, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"\n--- 齐发 @TERM{OFFSET_MS:+d}ms ---")
    fails = 0
    for r in sorted(results):
        mark = "OK  " if r[1] else "FAIL"
        if not r[1]:
            fails += 1
        print(f"[start TERM{r[0]:+.3f}s done{r[2]:+.3f}s] {mark} {r[3]}")
    print(f"failures: {fails}/{N}")

    time.sleep(2)
    after = svc_start_time()
    print(f"82 svc: {before} -> {after}  " + ("RESTART CONFIRMED" if before != after else "!!! NO RESTART !!!"))


def barrier_round(fire_at):
    barrier = threading.Barrier(N)

    def one():
        if fire_at:
            s = fire_at - time.time()
            if s > 0:
                time.sleep(s)
        barrier.wait()
        call_tool("version", {"targets": [TARGET]})

    ts = [threading.Thread(target=one) for _ in range(N)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


if __name__ == "__main__":
    main()
