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
	"strconv"
	"strings"
	"sync"
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
	data    []byte
	stopped bool
	wg      sync.WaitGroup
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
	addrs := []string{fmt.Sprintf("0.0.0.0:%d", port)}
	if host == nil {
		addrs = append(addrs, fmt.Sprintf("[::]:%d", port))
	} else if *host != "" {
		addrs = []string{net.JoinHostPort(*host, strconv.Itoa(port))}
	}
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a) // Go tcp6 自动 V6ONLY=1（复审已核）
		if err != nil {
			inst.shutdown()
			return nil, err
		}
		inst.lns = append(inst.lns, ln)
	}
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
	os.RemoveAll(socketbinDir())
	os.MkdirAll(socketbinDir(), 0o755)
	inst.wg.Add(1)
	go func() {
		defer inst.wg.Done()
		var pending []byte
		for {
			select {
			case chunk := <-inst.q:
				pending = append(pending, chunk...)
				inst.data = append(inst.data, chunk...)
				continue
			case <-time.After(1 * time.Second):
			}
			if inst.stopped {
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
	li.stopped = true
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
	ss.data = nil
	os.RemoveAll(socketbinDir())
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
	if err := os.WriteFile(p.File, ss.data, 0o644); err != nil {
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
	zw.Write(ss.data)
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
