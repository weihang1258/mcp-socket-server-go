package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// socket_listen（dt171-175，socket_listen.py 移植，设计 §3 listen 段）。
// 全局单例 ss（Python 模块级变量）+ mutex；Python 子进程模型改 goroutine（§12#2）。
// quirk 逐条保真：默认端口 30001、pid()=ss -lptn 管道解析、无条件回 {"pid":[...]}
// （bind 失败也回空列表）、cleandata 排空等待、stop 的 kill -9 清扫、
// 轮询后 ss=None 无条件清、失败回 {"error":"停止监听失败，端口仍被占用"}。

var (
	listenMu    sync.Mutex
	ss          *listenInstance
	fakePidsStr string // 测试注入：非空时 pid() 返回它（绕过 ss 管道）
)

// socketbinDir 落盘目录（测试可注入）。
var socketbinDir = func() string { return "/tmp/socketbin" }

func socketbinDirForTest(dir string) {
	socketbinDir = func() string { return dir }
}

// setFakePids 测试注入 pid 解析结果。
func setFakePids(s string) {
	listenMu.Lock()
	defer listenMu.Unlock()
	fakePidsStr = s
}

func stopListenForTest() {
	listenMu.Lock()
	defer listenMu.Unlock()
	if ss != nil {
		ss.shutdown()
		ss = nil
	}
}

type listenInstance struct {
	port    int
	mu      sync.Mutex
	lns     []net.Listener
	conns   map[net.Conn]struct{}
	q       chan []byte
	dataMu  sync.Mutex // 保护 data（cachedata 写 / fetch/save 读）
	data    []byte
	stopped atomic.Bool // shutdown 置位 / cachedata 轮询（-race 复审）
	wg      sync.WaitGroup
}

// appendData cachedata 侧追加（持 dataMu）。
func (li *listenInstance) appendData(chunk []byte) {
	li.dataMu.Lock()
	li.data = append(li.data, chunk...)
	li.dataMu.Unlock()
}

// dataCopy 读取侧快照（持 dataMu）。
func (li *listenInstance) dataCopy() []byte {
	li.dataMu.Lock()
	defer li.dataMu.Unlock()
	out := make([]byte, len(li.data))
	copy(out, li.data)
	return out
}

// listenStart 实现 dt171：ss 存活跳过 / 死了重启 / 无则新建。
// 无条件回 {"pid":[...]}——bind 失败也回（可能为空）列表，不报错（回退后契约）。
func listenStart(payload []byte) ([]byte, error) {
	var p struct {
		Host *string `json:"host"`
		Port int     `json:"port"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	if p.Port == 0 {
		p.Port = 30001 // SocketServerListen 默认端口
	}

	listenMu.Lock()
	defer listenMu.Unlock()
	if ss != nil && len(ss.pids()) > 0 {
		// 存活：跳过
	} else if ss != nil {
		ss.shutdown()
		ss = nil
	}
	if ss == nil {
		inst, err := newListenInstance(p.Host, p.Port)
		if err != nil {
			log.Printf("listen start 失败: %v", err)
			ss = &listenInstance{port: p.Port, conns: map[net.Conn]struct{}{}, q: make(chan []byte, 1024)}
			// start_server 吞异常返回 None；ss 残留死对象 → pid() 照常解析（quirk）
		} else {
			ss = inst
		}
		time.Sleep(5 * time.Second) // Python start_server 同步 sleep(5) 再验 pid（wire 可观察）
	}
	pidList := ss.pids()
	return json.Marshal(map[string]any{"pid": pidList})
}

func newListenInstance(host *string, port int) (*listenInstance, error) {
	inst := &listenInstance{
		port:  port,
		conns: map[net.Conn]struct{}{},
		q:     make(chan []byte, 1024),
	}
	// 双栈必须 tcp4/tcp6 分开绑：net.Listen("tcp","0.0.0.0:p") 实际生成 AF_INET6
	// 通配 socket，v6 再绑必 EADDRINUSE（复审 F1 实测复现）。
	if host == nil {
		ln4, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			inst.shutdown()
			return nil, err
		}
		inst.lns = append(inst.lns, ln4)
		if ln6, err := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port)); err == nil {
			inst.lns = append(inst.lns, ln6) // IPv6 失败降级仅 IPv4（对齐 Python）
		}
	} else if *host != "" {
		ln, err := net.Listen("tcp", net.JoinHostPort(*host, strconv.Itoa(port)))
		if err != nil {
			inst.shutdown()
			return nil, err
		}
		inst.lns = append(inst.lns, ln)
	}
	// host 非空但非法（如 ""）：无监听 → 死对象（Python detect_ip_version ValueError）
	// accept 循环 + 每连接收包 goroutine（每连接一线程，对齐注释语义）
	inst.wg.Add(1)
	go func() {
		defer inst.wg.Done()
		for _, ln := range inst.lns {
			go func(ln net.Listener) {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					inst.wg.Add(1)
					go func() {
						defer inst.wg.Done()
						inst.mu.Lock()
						inst.conns[conn] = struct{}{}
						inst.mu.Unlock()
						buf := make([]byte, 10240)
						for {
							n, err := conn.Read(buf)
							if n > 0 {
								chunk := make([]byte, n)
								copy(chunk, buf[:n])
								inst.q <- chunk
							}
							if err != nil {
								break
							}
						}
						inst.mu.Lock()
						delete(inst.conns, conn)
						inst.mu.Unlock()
						conn.Close()
					}()
				}
			}(ln)
		}
	}()
	// cachedata：队列空且有待写块 → 整块落 <epoch_us>.bin；1s 轮询（quirk 节奏）
	os.MkdirAll(socketbinDir(), 0o755)
	clearDir(socketbinDir()) // Python rm -rf /tmp/socketbin/*：只清内容保目录
	inst.wg.Add(1)
	go func() {
		defer inst.wg.Done()
		var pending []byte
		for {
			select {
			case chunk := <-inst.q:
				pending = append(pending, chunk...)
				inst.appendData(chunk)
				continue
			case <-time.After(1 * time.Second):
			}
			if inst.stopped.Load() {
				return
			}
			if len(pending) > 0 {
				name := filepath_join(socketbinDir(), fmt.Sprintf("%d.bin", time.Now().UnixNano()/1000))
				os.WriteFile(name, pending, 0o644)
				pending = pending[:0]
			}
		}
	}()
	return inst, nil
}

func filepath_join(dir, name string) string { return dir + "/" + name }

// pids 复刻 pid()：`ss -lptn 'sport = :PORT'|grep users|awk -F',' '{print $2}'|awk -F'=' '{print $2}'`
// 输出按行拆为列表（空行过滤）。
func (li *listenInstance) pids() []string {
	if fakePidsStr != "" {
		return strings.Fields(fakePidsStr)
	}
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf(
		"ss -lptn 'sport = :%d'|grep users|awk -F ',' '{print $2}'|awk -F '=' '{print $2}'", li.port))
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var pids []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			pids = append(pids, line)
		}
	}
	return pids
}

// shutdown 关监听与连接 + 对端口残留者 kill -9 清扫（stop_server 链）。
func (li *listenInstance) shutdown() {
	li.stopped.Store(true)
	for _, ln := range li.lns {
		ln.Close()
	}
	li.mu.Lock()
	for c := range li.conns {
		c.Close()
	}
	li.mu.Unlock()
	li.wg.Wait()
	// 清扫：解析 pid 输出，逐个 kill -9（陈旧占端口场景仍能停成）
	for _, pid := range li.pids() {
		if n, err := strconv.Atoi(pid); err == nil {
			if p, err := os.FindProcess(n); err == nil {
				p.Kill()
			}
		}
	}
}

// listenClean dt172：判活 ss!=nil 且有 pid；cleandata = 排空队列等待 + 1s +
// 清 data + rm -rf socketbin（quirk 节奏）。未启动 → 裸 b"error"。
func listenClean() ([]byte, error) {
	listenMu.Lock()
	defer listenMu.Unlock()
	if ss == nil || len(ss.pids()) == 0 {
		return []byte("error"), nil
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(ss.q) > 0 && time.Now().Before(deadline) {
		time.Sleep(1 * time.Second)
	}
	time.Sleep(1 * time.Second)
	ss.dataReset()
	clearDir(socketbinDir())
	return []byte("ok"), nil
}

// listenSave dt173：未启动 → b"error"；成功写盘 → b"ok"；缺 file 键 → error 断连。
func listenSave(payload []byte) ([]byte, error) {
	var p struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	listenMu.Lock()
	defer listenMu.Unlock()
	if ss == nil || len(ss.pids()) == 0 {
		return []byte("error"), nil
	}
	if err := os.WriteFile(p.File, ss.dataCopy(), 0o644); err != nil {
		return nil, err
	}
	return []byte("ok"), nil
}

// listenFetch dt174：判活仅 ss!=None（quirk：死对象照常回 gzip(data) 流）；
// 未启动 → 裸 JSON {"error":"未启动监听"}；正常 [8B <Q][gzip(data)]。
func listenFetch() ([]byte, error) {
	listenMu.Lock()
	defer listenMu.Unlock()
	if ss == nil {
		return json.Marshal(map[string]string{"error": "未启动监听"})
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(ss.dataCopy())
	zw.Close()
	out := make([]byte, 8+buf.Len())
	binary.LittleEndian.PutUint64(out, uint64(buf.Len()))
	copy(out[8:], buf.Bytes())
	return out, nil
}

// listenStop dt175：stop_server（shutdown 含 kill -9 清扫）→ 3 轮查 pid（有才 sleep 0.5）
// → ss=None 无条件清（成功失败都清）→ ok / {"error":"停止监听失败，端口仍被占用"}。
func listenStop() ([]byte, error) {
	listenMu.Lock()
	defer listenMu.Unlock()
	if ss == nil {
		return json.Marshal(map[string]string{"error": "未启动监听"})
	}
	inst := ss
	inst.shutdown()
	stopped := false
	for i := 0; i < 3; i++ {
		if len(inst.pids()) == 0 {
			stopped = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	ss = nil // 无条件清（quirk）
	if stopped {
		log.Printf("socket监听已停止")
		return []byte("ok"), nil
	}
	return json.Marshal(map[string]string{"error": "停止监听失败，端口仍被占用"})
}

// dataReset 清空已收数据（dt172，持锁）。
func (li *listenInstance) dataReset() {
	li.dataMu.Lock()
	li.data = nil
	li.dataMu.Unlock()
}

// clearDir 清目录内容保目录（Python rm -rf dir/* 语义）。
func clearDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		os.RemoveAll(filepath.Join(dir, e.Name()))
	}
}
