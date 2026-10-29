"""socket_server 端到端测试客户端 v2
服务端响应不带长度前缀，直接 sendall 原始字节。
客户端针对每种 datatype 用不同的接收策略。"""
import socket
import struct
import json
import gzip
import sys

HOST = "127.0.0.1"
PORT = 9000
TIMEOUT = 10

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def new_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((HOST, PORT))
    return s


def send_request(sock, datatype, payload_bytes=b""):
    """发送: [4字节总长度 i][4字节类型 i][载荷]"""
    body = struct.pack("i", datatype) + payload_bytes
    msg = struct.pack("i", len(body)) + body
    sock.sendall(msg)


def recv_raw(sock, close_after=True):
    """接收原始响应（无长度前缀），关闭连接后读取全部数据"""
    if close_after:
        # 先 shutdown 写端，让服务端知道客户端发完了
        # 但不关闭读端，这样还能接收数据
        # 服务端 recv 返回空后 break，但 sendall 已经发出了
        # 我们需要等服务端发完响应后再关闭
        # 用多次 recv 来收集数据
        data = b""
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
                # 如果数据看起来完整了（收到一些数据后短暂等待）
                # 小响应通常一次就到
                if len(data) > 0:
                    # 试试再收一点看有没有更多
                    sock.settimeout(0.5)
                    try:
                        extra = sock.recv(65536)
                        if extra:
                            data += extra
                        else:
                            break
                    except socket.timeout:
                        break
        except socket.timeout:
            pass
        sock.close()
        return data
    else:
        data = b""
        sock.settimeout(2)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
                sock.settimeout(0.5)
                try:
                    extra = sock.recv(65536)
                    if extra:
                        data += extra
                    else:
                        break
                except socket.timeout:
                    break
        except socket.timeout:
            pass
        return data


def recv_text_response(sock, close_after=True):
    """接收文本类响应（直接 recv，解析为 UTF-8 文本）"""
    data = recv_raw(sock, close_after)
    return data


def recv_gzip_response(sock, close_after=True):
    """接收 gzip 响应: [4字节gzip长度 i][gzip数据]"""
    data = recv_raw(sock, close_after)
    if len(data) < 4:
        return None
    gzip_len = struct.unpack("i", data[:4])[0]
    gzip_data = data[4:4 + gzip_len]
    return json.loads(gzip.decompress(gzip_data))


def recv_file_response(sock, close_after=True):
    """接收文件下载响应: [8字节长度 Q][文件内容]"""
    data = recv_raw(sock, close_after)
    if len(data) < 8:
        return None, None
    file_len = struct.unpack("<Q", data[:8])[0]
    file_content = data[8:8 + file_len]
    return file_len, file_content


def recv_inline_text(sock):
    """在同一连接上接收短文本响应（如 '21 ok', '22 ok' 等）
    服务端 sendall 后继续等待下一个请求，不会关闭连接。
    客户端 recv 后继续发送下一个请求。"""
    sock.settimeout(5)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            # 短响应通常一次到齐
            if len(data) > 0:
                sock.settimeout(0.3)
                try:
                    extra = sock.recv(4096)
                    if extra:
                        data += extra
                    else:
                        break
                except socket.timeout:
                    break
    except socket.timeout:
        pass
    return data


def do_file_upload(sock, filepath_remote, content, use_gzip=False):
    """文件上传 21→22→23→24，在同一连接上"""
    raw_content = content
    if use_gzip:
        raw_content = gzip.compress(content)

    # Step 1: 文件名
    fileinfo = json.dumps({"filepath": filepath_remote, "gzip": use_gzip}).encode()
    send_request(sock, 21, fileinfo)
    resp = recv_inline_text(sock)
    check("文件名上传(21)", resp == b"21 ok", f"got {resp}")

    # Step 2: 文件长度
    send_request(sock, 22, struct.pack("<Q", len(raw_content)))
    resp = recv_inline_text(sock)
    check("文件长度上传(22)", resp == b"22 ok", f"got {resp}")

    # Step 3: 文件内容 — bin_recv_flag=True 时服务端跳过类型解析
    # 发送格式: [4字节长度][原始内容]，不带类型前缀
    length_prefix = struct.pack("i", len(raw_content))
    sock.sendall(length_prefix + raw_content)
    resp = recv_inline_text(sock)
    check("文件内容上传(23)", resp == b"23 ok", f"got {resp}")

    # Step 4: 写文件
    send_request(sock, 24, b"")
    resp = recv_inline_text(sock)
    check("写文件(24)", resp == b"24 ok", f"got {resp}")


# ===== Test 1: datatype 14 版本号 =====
print("\n[Test 1] datatype 14 - 获取版本号")
s = new_sock()
send_request(s, 14)
resp = recv_text_response(s)
try:
    version = json.loads(resp)
    check("版本号返回", isinstance(version, str), f"raw={resp[:50]}, parsed={version}")
    check("版本号值", isinstance(version, str) and version.count(".") == 2, f"got {version}")
except Exception as e:
    check("版本号", False, f"raw={resp[:50]}, err={e}")

# ===== Test 2: datatype 7 文件存在 =====
print("\n[Test 2] datatype 7 - 文件存在(真)")
s = new_sock()
send_request(s, 7, json.dumps({"file": "/etc/hostname"}).encode())
resp = recv_text_response(s)
try:
    r = json.loads(resp)
    check("/etc/hostname存在", r.get("res") is True, f"got {r}")
except Exception as e:
    check("文件存在", False, f"raw={resp[:50]}, err={e}")

# ===== Test 3: datatype 7 文件不存在 =====
print("\n[Test 3] datatype 7 - 文件存在(假)")
s = new_sock()
send_request(s, 7, json.dumps({"file": "/tmp/no_such_xyz_999"}).encode())
resp = recv_text_response(s)
try:
    r = json.loads(resp)
    check("不存在文件false", r.get("res") is False, f"got {r}")
except Exception as e:
    check("文件不存在", False, f"raw={resp[:50]}, err={e}")

# ===== Test 4: datatype 8 目录存在 =====
print("\n[Test 4] datatype 8 - 目录存在")
s = new_sock()
send_request(s, 8, json.dumps({"dir": "/tmp"}).encode())
resp = recv_text_response(s)
try:
    r = json.loads(resp)
    check("/tmp目录存在", r.get("res") is True, f"got {r}")
except Exception as e:
    check("目录存在", False, f"raw={resp[:50]}, err={e}")

# ===== Test 5: datatype 1 执行命令(成功) =====
print("\n[Test 5] datatype 1 - 执行命令(成功)")
s = new_sock()
send_request(s, 1, json.dumps({"args": "echo hello_e2e"}).encode())
result = recv_gzip_response(s)
if result:
    check("返回码0", result.get("code") == 0, f"got code={result.get('code')}")
    check("stdout包含hello_e2e", "hello_e2e" in (result.get("stdout") or ""), f"got stdout={result.get('stdout')}")
else:
    check("执行命令成功", False, "recv failed")

# ===== Test 6: datatype 1 执行命令(失败) =====
print("\n[Test 6] datatype 1 - 执行命令(失败)")
s = new_sock()
send_request(s, 1, json.dumps({"args": "ls /nonexistent_xyz"}).encode())
result = recv_gzip_response(s)
if result:
    check("返回码非0", result.get("code") != 0, f"got code={result.get('code')}")
else:
    check("执行命令失败", False, "recv failed")

# ===== Test 7: datatype 4 路由信息 =====
print("\n[Test 7] datatype 4 - 路由信息")
s = new_sock()
send_request(s, 4)
resp = recv_text_response(s)
try:
    r = json.loads(resp)
    check("返回路由字典", isinstance(r, dict), f"type={type(r).__name__}")
except Exception as e:
    check("路由信息", False, f"raw={resp[:80] if resp else 'empty'}, err={e}")

# ===== Test 8: datatype 11 文件大小 =====
print("\n[Test 8] datatype 11 - 文件大小")
s = new_sock()
send_request(s, 11, json.dumps({"path": "/etc/hostname"}).encode())
resp = recv_text_response(s)
try:
    r = json.loads(resp)
    check("文件大小>0", isinstance(r.get("res"), int) and r["res"] > 0, f"got {r}")
except Exception as e:
    check("文件大小", False, f"raw={resp[:50] if resp else 'empty'}, err={e}")

# ===== Test 9: datatype 18 命令存在 =====
print("\n[Test 9] datatype 18 - 命令是否存在")
s = new_sock()
send_request(s, 18, json.dumps({"cmd": "ls"}).encode())
resp = recv_text_response(s)
try:
    r = json.loads(resp)
    check("ls存在", r.get("res") is True, f"got {r}")
except Exception as e:
    check("命令存在", False, f"raw={resp[:50] if resp else 'empty'}, err={e}")

# ===== Test 10: datatype 9 创建目录 =====
print("\n[Test 10] datatype 9 - 创建目录")
test_dir = "/tmp/socket_e2e_test_v2_%d" % __import__("os").getpid()  # 已存在 → makedirs FileExistsError → 断连（quirk），路径须每轮唯一
s = new_sock()
send_request(s, 9, json.dumps({"dir": test_dir}).encode())
resp = recv_text_response(s)
try:
    r = json.loads(resp)
    check("创建目录返回", r == {"res": None}, f"got {r}")
except Exception as e:
    check("创建目录", False, f"raw={resp[:50] if resp else 'empty'}, err={e}")

# 验证目录存在
s2 = new_sock()
send_request(s2, 8, json.dumps({"dir": test_dir}).encode())
resp2 = recv_text_response(s2)
try:
    r2 = json.loads(resp2)
    check("目录确实存在", r2.get("res") is True, f"got {r2}")
except Exception as e:
    check("目录验证", False, f"raw={resp2[:50] if resp2 else 'empty'}, err={e}")

# ===== Test 11: 文件上传 21→22→23→24 =====
print("\n[Test 11] 文件上传协议(非压缩)")
test_content = b"e2e v2 test file - hello world"
remote_path = "/tmp/socket_e2e_upload_v2.txt"
s = new_sock()
do_file_upload(s, remote_path, test_content, use_gzip=False)
s.close()

# 验证上传的文件内容
s2 = new_sock()
send_request(s2, 1, json.dumps({"args": f"cat {remote_path}"}).encode())
result = recv_gzip_response(s2)
if result:
    check("上传文件内容正确", test_content.decode() in (result.get("stdout") or ""),
          f"got stdout={result.get('stdout')[:50]}")
else:
    check("上传文件验证", False, "recv failed")

# ===== Test 12: 文件上传(gzip) =====
print("\n[Test 12] 文件上传协议(gzip压缩)")
test_content = b"e2e v2 gzip test - compressed upload"
remote_path = "/tmp/socket_e2e_gzip_v2.txt"
s = new_sock()
do_file_upload(s, remote_path, test_content, use_gzip=True)
s.close()

# 验证
s2 = new_sock()
send_request(s2, 1, json.dumps({"args": f"cat {remote_path}"}).encode())
result = recv_gzip_response(s2)
if result:
    check("gzip上传内容正确", test_content.decode() in (result.get("stdout") or ""),
          f"got stdout={result.get('stdout')[:50]}")
else:
    check("gzip上传验证", False, "recv failed")

# ===== Test 13: datatype 3 文件下载 =====
print("\n[Test 13] datatype 3 - 文件下载")
# 先上传已知文件
test_content_dl = b"download e2e v2 test 1234567890"
remote_path_dl = "/tmp/socket_e2e_download_v2.txt"
s = new_sock()
do_file_upload(s, remote_path_dl, test_content_dl, use_gzip=False)

# 同一连接发下载请求 - 但 datatype 3 需要 filepath 参数
# 看看 handlers.py: datatype 3 用 kwargs["filepath"]
# filepath 来自 self.filepath（协议层状态），不是 JSON 参数
# 所以 filepath 是上传文件时设置的 self.filepath
# 下载需要先上传文件名(datatype 21)，然后发 datatype 3
# 让我重新看 handlers.py datatype 3

# datatype 3 的 data 是 json.loads(data)，然后用 kwargs["filepath"]
# kwargs["filepath"] 来自 protocol.py 的 on_data(datatype, data, filepath=self.filepath)
# self.filepath 在 setup() 中初始化为 "tmp"
# 如果之前没有 21 上传，filepath 就是 "tmp"

# 先用新连接，filepath 默认是 "tmp"，下载不存在的文件会失败
# 换个策略：上传文件后在同一连接下载
send_request(s, 3, json.dumps({"gzip": False}).encode())
file_len, file_content = recv_file_response(s)
check("下载文件长度", file_len is not None and file_len == len(test_content_dl),
      f"expect {len(test_content_dl)}, got {file_len}")
check("下载文件内容", file_content == test_content_dl,
      f"content mismatch, got {file_content[:30] if file_content else None}")
s.close()

# ===== Test 15: datatype 122 停止抓包(未启动) =====
print("\n[Test 15] datatype 122 - 停止抓包(未启动)")
s = new_sock()
send_request(s, 122)
resp = recv_text_response(s)
check("返回未在抓包(空响应)", resp == b"", f"got {resp!r}")

# ===== Test 16: datatype 174 socket监听(未启动) =====
print("\n[Test 16] datatype 174 - socket监听(未启动)")
s = new_sock()
send_request(s, 174)
resp = recv_text_response(s)
try:
    r = json.loads(resp)
    check("返回未启动监听", "error" in r, f"got {r}")
except Exception as e:
    check("socket监听", False, f"raw={resp[:50] if resp else 'empty'}, err={e}")

# ===== Test: datatype 175 停止监听 =====
print("\n[Test] datatype 175 - socket监听停止")
s = new_sock()
send_request(s, 171, json.dumps({"host": None, "port": 39011}).encode())
r = recv_text_response(s)
check("171 start", "pid" in json.loads(r), r)
s.close()

s = new_sock()
send_request(s, 175)
r = recv_text_response(s)
check("175 stop", r == b"ok", r)
s.close()

s = new_sock()
send_request(s, 175)
r = recv_text_response(s)
check("175 re-stop error", "未启动监听".encode("utf-8") in r, r)
s.close()

# ===== Test: capture_stop(1.7.0 形态,回退后) =====
print("\n[Test] capture_stop 幂等")
s = new_sock()
send_request(s, 6, json.dumps({"path": "/tmp/e2e_never.pcap"}).encode())
r = recv_text_response(s)
check("never-started res:true(幂等)", json.loads(r).get("res") is True, r)
s.close()

# ===== Test: datatype 20 升级落地(1.8.0+,错误路径,不触发重启) =====
print("\n[Test] datatype 20 - 升级落地(错误路径)")
s = new_sock()
send_request(s, 20, json.dumps({"version": "../evil", "sha256": "0" * 64}).encode())
r = recv_text_response(s)
check("dt20 非法版本拒绝", b"error" in r, r)
s.close()

s = new_sock()
send_request(s, 20, json.dumps({"version": "9.9.9", "sha256": "short"}).encode())
r = recv_text_response(s)
check("dt20 非法 sha 拒绝", b"error" in r, r)
s.close()

s = new_sock()
send_request(s, 20, json.dumps({"version": "9.9.9", "sha256": "a" * 64}).encode())
r = recv_text_response(s)
# 前序 socket 的 FIN 可能尚未被服务端回收 → 此时 "其它客户端" 错误先于 "未找到"（两实现同语义）
check("dt20 无推送包拒绝", b"error" in r and ("未找到".encode("utf-8") in r or "客户端".encode("utf-8") in r), r)
s.close()

# ===== 汇总 =====
print(f"\n{'='*50}")
print(f"测试完成: {passed} PASS, {failed} FAIL, 共 {passed+failed} 项")
if failed:
    sys.exit(1)
