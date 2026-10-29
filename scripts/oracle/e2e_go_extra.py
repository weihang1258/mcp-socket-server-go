"""socketstack 补充真机对拍：test_e2e.py 未覆盖的 dt（10/15/19/5/6/200/0）。
前置：root + Go agent 在 :9000/:9001 + tcpdump 可用。"""
import socket, struct, json, time, os, subprocess, sys

HOST = "127.0.0.1"
PORT = 9000
TIMEOUT = 30
passed = failed = 0

def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1; print(f"  PASS  {name}")
    else:
        failed += 1; print(f"  FAIL  {name}  {detail}")

def new_sock():
    s = socket.socket(); s.settimeout(TIMEOUT); s.connect((HOST, PORT)); return s

def send_request(sock, dt, payload=b""):
    body = struct.pack("i", dt) + payload
    sock.sendall(struct.pack("i", len(body)) + body)

def recv_all(sock, grace=0.5, first=TIMEOUT):
    data = b""
    sock.settimeout(first)
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk: break
            data += chunk
            sock.settimeout(grace)
            try:
                extra = sock.recv(65536)
                if not extra: break
                data += extra
            except socket.timeout:
                break
    except socket.timeout:
        pass
    return data

# ===== dt19 版本详情 =====
s = new_sock(); send_request(s, 19)
r = json.loads(recv_all(s)); s.close()
check("dt19 键序齐全", list(r.keys()) == ["version", "repo", "release_notes", "latest_version", "has_upgrade"], r)
check("dt19 has_upgrade=false", r.get("has_upgrade") is False, r)

# ===== dt15 解压(恒 ok；键名 file，netutils.unzip 签名) =====
s = new_sock(); send_request(s, 15, json.dumps({"file": "/tmp/no_such.zip"}).encode())
r = recv_all(s); s.close()
check("dt15 恒 b'ok'", r == b"ok", r)

# ===== dt10 改MTU(同值no-op；Python mtu() 无返回值 → {"res":null}) =====
cur = int(open("/sys/class/net/lo/mtu").read())
s = new_sock(); send_request(s, 10, json.dumps({"eth": "lo", "value": cur}).encode())
t0 = time.time(); r = recv_all(s); dt = time.time() - t0; s.close()
check("dt10 同值 res:null", json.loads(r) == {"res": None}, r)
check("dt10 同值不 sleep(5)", dt < 3, f"{dt:.1f}s")

# ===== dt5/6 抓包闭环 + dt200 五元组 + dt0 回放 =====
cap_dir = "/tmp/e2e_go_flows"
subprocess.run(["rm", "-rf", cap_dir]); os.makedirs(cap_dir)
cap_path = f"{cap_dir}/e2e_cap.pcap"
s = new_sock()
send_request(s, 5, json.dumps({"eth": "lo", "path": cap_path, "extended": "", "single_queue": False}).encode())
r = recv_all(s)
check("dt5 启动 res:true", json.loads(r) == {"res": True}, r)
subprocess.run(["ping", "-c", "4", "-i", "0.2", "127.0.0.1"], capture_output=True)
time.sleep(1)
send_request(s, 6, json.dumps({"path": cap_path}).encode())
r = recv_all(s)
check("dt6 停止 res:true", json.loads(r) == {"res": True}, r)
s.close()
sz = os.path.getsize(cap_path)
magic = open(cap_path, "rb").read(4)
check("dt6 pcap 纳秒魔数 0xA1B23C4D", magic == b"\x4d\x3c\xb2\xa1", f"magic={magic.hex()} size={sz}")

# dt200：[4B i][JSON 数组]
s = new_sock(); send_request(s, 200, json.dumps({"pcap_dir": cap_dir}).encode())
raw = recv_all(s); s.close()
flen = struct.unpack("i", raw[:4])[0]
flows = json.loads(raw[4:4+flen])
check("dt200 返回数组", isinstance(flows, list), f"{type(flows).__name__}")
check("dt200 lo 流量非空", len(flows) > 0, flows)
ok_keys = all(set(f.keys()) == {"pcap", "srcIp", "srcPort", "destIp", "destPort", "protoType"} for f in flows)
check("dt200 五元组键", ok_keys, flows[:1])

# dt0：回放到 lo（bare JSON stats；replayer.py:803 11 键逐字对齐）
s = new_sock()
send_request(s, 0, json.dumps({"pcaps": [cap_path], "uplink_iface": "lo", "downlink_iface": "lo"}).encode())
r = recv_all(s, grace=2.0, first=60); s.close()
stats = json.loads(r)
want_keys = ["total_files", "total_packets", "total_bytes", "uplink_packets", "uplink_bytes",
             "downlink_packets", "downlink_bytes", "flow_count", "duration_seconds", "target_mbps", "actual_mbps"]
check("dt0 stats 11 键且序对齐", list(stats.keys()) == want_keys, list(stats.keys()))
check("dt0 total_packets>0", stats.get("total_packets", 0) > 0, stats)

print(f"\n{'='*50}")
print(f"补充对拍: {passed} PASS, {failed} FAIL, 共 {passed+failed} 项")
sys.exit(1 if failed else 0)
