package mcpbridge

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/weihang1258/mcp-socket-server-go/internal/frame"
)

// 协议客户端（socket_client.py 逐条移植，设计 §2 五类响应）+ 连接池（pool.py 语义）。

// DefaultTimeout 优先级：MCP_DEFAULT_TIMEOUT env > 30（socket_client.py:22-24）。
var DefaultTimeout = func() int {
	if v := envInt("MCP_DEFAULT_TIMEOUT"); v > 0 {
		return v
	}
	return 30
}()

func envInt(k string) int {
	v := os.Getenv(k)
	n, _ := strconv.Atoi(v)
	return n
}

// Client 单靶机客户端（持久连接，池管理生命周期）。
type Client struct {
	Host    string
	Port    int
	Timeout int
	conn    net.Conn
}

func NewClient(host string, port, timeout int) *Client {
	return &Client{Host: host, Port: port, Timeout: timeout}
}

// 连接建立失败的重试。**只重试建连**，绝不重试已发出的请求——
// cmd_exec 之类非幂等，重试会执行两次。
var (
	dialFn               = net.DialTimeout
	dialBackoffSleepFn   = time.Sleep
	dialRetryAttempts    = 3
	dialRetryBaseBackoff = 500 * time.Millisecond
	// dialConnectTimeout 建连单次超时上限。
	//
	// 不能直接用 c.Timeout：那是业务 socket 超时（cmd_exec 默认 60s、
	// boce_run 是 timeout+10）。拿它当 dial 超时，靶机不可达时
	// 3 次重试会把 60s 放大成 ~181s——重试本是为吃 5~15s 的重启窗口，
	// 反而让每次失败等待更久。
	dialConnectTimeout = 5 * time.Second
)

// dialTimeout 建连超时：取 min(业务超时, dialConnectTimeout)。
func (c *Client) dialTimeout() time.Duration {
	t := time.Duration(c.Timeout) * time.Second
	if c.Timeout <= 0 || t > dialConnectTimeout {
		return dialConnectTimeout
	}
	return t
}

// dialOnce 单次建连（不重试）。供轮询类调用方使用——它们自己就有循环。
func (c *Client) dialOnce() error {
	if c.conn != nil {
		return nil
	}
	conn, err := dialFn("tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), c.dialTimeout())
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

// connectWithRetry 建连失败时退避重试（靶机重启窗口用）。
//
// 为什么要有：upgrade_run 推包后靶机 systemd RestartSec=5，期间端口无人监听，
// 客户端只拿到裸 "not connected" / "connection refused"，看起来像故障。
//
// 注意：**轮询类调用（upgrade_run 等靶机重启）不要用这个**——它自带重试，
// 会把「3s 一轮」拖成「18s 一轮」，把 180s 预算白白耗掉。轮询用 dialOnce()。
func (c *Client) connectWithRetry() error {
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	timeout := c.dialTimeout()
	var lastErr error
	backoff := dialRetryBaseBackoff
	for i := 0; i < dialRetryAttempts; i++ {
		conn, err := dialFn("tcp", addr, timeout)
		if err == nil {
			c.conn = conn
			return nil
		}
		lastErr = err
		if i < dialRetryAttempts-1 {
			dialBackoffSleepFn(backoff)
			backoff *= 2
		}
	}
	return fmt.Errorf("连接 %s 失败（已重试 %d 次，靶机可能正在重启，请稍后重试）: %w",
		addr, dialRetryAttempts, lastErr)
}

func (c *Client) Connect() error {
	if c.conn != nil {
		return nil
	}
	return c.connectWithRetry()
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// SetTimeout 更新 socket_timeout（N8：复用连接同步超时）。
func (c *Client) SetTimeout(sec int) { c.Timeout = sec }

// send [4B len][4B dt][payload]；每次发送前重置 deadline（防 0.5s 短探泄漏）。
func (c *Client) send(dt int32, payload []byte) error {
	if c.conn == nil {
		return errors.New("未连接到靶机（连接已断，请重试）")
	}
	c.conn.SetDeadline(time.Now().Add(time.Duration(c.Timeout) * time.Second))
	return writeFull(c.conn, frame.Encode(dt, payload))
}

// sendRaw step23 裸帧 [4B len][content]。
func (c *Client) sendRaw(content []byte) error {
	c.conn.SetDeadline(time.Now().Add(time.Duration(c.Timeout) * time.Second))
	return writeFull(c.conn, frame.EncodeRaw(content))
}

// recvN 精确读 n 字节。
func (c *Client) recvN(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// recvUntilTimeout 首 chunk 后 0.5s 短探（裸 JSON/inline）。
//
// 错误区分（六轮验收 P2）：只有超时走「空/已收即返回」（Python except
// socket.timeout: return）；reset/EOF 冒泡——Python 里 ConnectionResetError
// 同样冒泡，吞掉会让上层拿空/残缺字节去 json.Unmarshal，报成
// "unexpected end of JSON input"，误导往协议不兼容排查。
func (c *Client) recvUntilTimeout(probe time.Duration) ([]byte, error) {
	var out []byte
	c.conn.SetReadDeadline(time.Now().Add(time.Duration(c.Timeout) * time.Second))
	buf := make([]byte, 65536)
	n, err := c.conn.Read(buf)
	if err != nil {
		if isTimeout(err) {
			return out, nil // 超时即空（Python except socket.timeout: return）
		}
		return nil, err // reset/EOF 冒泡
	}
	out = append(out, buf[:n]...)
	c.conn.SetReadDeadline(time.Now().Add(probe))
	for {
		n, err = c.conn.Read(buf)
		if err != nil {
			if isTimeout(err) {
				break // 短探超时结束
			}
			return nil, err // 数据中途 reset/EOF：冒泡，让调用方看到真实原因
		}
		out = append(out, buf[:n]...)
	}
	return out, nil
}

// recvGzipRaw 保留原始解析值（cmd_exec 可能收到 "null"）。
func (c *Client) recvGzipRaw() (any, error) {
	head, err := c.recvN(4)
	if err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(head)
	gz, err := c.recvN(int(n))
	if err != nil {
		return nil, err
	}
	zr, _ := gzip.NewReader(strings.NewReader(string(gz)))
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "null" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// recvLenPrefixedJSON [4B i][JSON]（131/200）。
func (c *Client) recvLenPrefixedJSON() (map[string]any, error) {
	head, err := c.recvN(4)
	if err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(head)
	body, err := c.recvN(int(n))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	err = json.Unmarshal(body, &m)
	return m, err
}

// decodeListenError 172/173/175 错误解码：{"error"} JSON → 文案；裸字节原样（B09/N4 双兼容）。
func decodeListenError(resp []byte) string {
	var m map[string]string
	if err := json.Unmarshal(resp, &m); err == nil {
		if msg, ok := m["error"]; ok {
			return msg
		}
	}
	return string(resp)
}

// ---- 只读便捷 ----

func (c *Client) Version() (string, error) {
	if err := c.send(14, nil); err != nil {
		return "", err
	}
	b, err := c.recvUntilTimeout(500 * time.Millisecond)
	if err != nil {
		return "", err
	}
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	return v, nil
}

func (c *Client) Isfile(path string) (bool, error) { return c.resBoolReq(7, "file", path) }
func (c *Client) Isdir(path string) (bool, error)  { return c.resBoolReq(8, "dir", path) }

func (c *Client) resBoolReq(dt int32, key, path string) (bool, error) {
	p, _ := json.Marshal(map[string]string{key: path})
	if err := c.send(dt, p); err != nil {
		return false, err
	}
	b, err := c.recvUntilTimeout(500 * time.Millisecond)
	if err != nil {
		return false, err
	}
	var m struct {
		Res bool `json:"res"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return false, err
	}
	return m.Res, nil
}

// PcapFlowExtractRaw dt200（数组响应）。
func (c *Client) PcapFlowExtractRaw(dir string) ([]any, error) {
	p, _ := json.Marshal(map[string]string{"pcap_dir": dir})
	if err := c.send(200, p); err != nil {
		return nil, err
	}
	return c.recvLenPrefixedArray()
}

func (c *Client) recvLenPrefixedArray() ([]any, error) {
	head, err := c.recvN(4)
	if err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(head)
	body, err := c.recvN(int(n))
	if err != nil {
		return nil, err
	}
	var arr []any
	err = json.Unmarshal(body, &arr)
	return arr, err
}

// ---- 写方法 ----

// CmdExec dt1：stdout >65536 字符截断（Python str len）；wait=false 回 nil。
func (c *Client) CmdExec(args, cwd string, env map[string]string, wait bool) (map[string]any, error) {
	payload := map[string]any{"args": args, "wait": wait}
	if cwd != "" {
		payload["cwd"] = cwd
	}
	if env != nil {
		payload["env"] = env
	}
	p, _ := json.Marshal(payload)
	if err := c.send(1, p); err != nil {
		return nil, err
	}
	raw, err := c.recvGzipRaw()
	if err != nil {
		return nil, err
	}
	if raw == nil { // wait=false: "null" → None
		return nil, nil
	}
	m := raw.(map[string]any)
	if s, ok := m["stdout"].(string); ok && runeLen(s) > 65536 {
		m["stdout"] = truncateRunes(s, 65536)
		m["stdout_truncated"] = true
	}
	return m, nil
}

func runeLen(s string) int { return len([]rune(s)) }
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// CaptureStart dt5：统一 {res, error?}（1.7.2 error 通道为兼容死代码）。
func (c *Client) CaptureStart(eth, path, extended string, singleQueue bool) (map[string]any, error) {
	payload := map[string]any{"extended": extended, "single_queue": singleQueue}
	if eth != "" {
		payload["eth"] = eth
	}
	if path != "" {
		payload["path"] = path
	}
	p, _ := json.Marshal(payload)
	if err := c.send(5, p); err != nil {
		return nil, err
	}
	b, err := c.recvUntilTimeout(500 * time.Millisecond)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if _, has := m["error"]; has {
		return m, nil
	}
	res, _ := m["res"].(bool)
	return map[string]any{"res": res}, nil
}

// CaptureStop dt6：新形态直出；旧 {"res"} → legacy 映射。
func (c *Client) CaptureStop(path string) (map[string]any, error) {
	p, _ := json.Marshal(map[string]string{"path": path})
	if err := c.send(6, p); err != nil {
		return nil, err
	}
	b, err := c.recvUntilTimeout(500 * time.Millisecond)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if _, has := m["stopped"]; has {
		return m, nil
	}
	if res, has := m["res"].(bool); has {
		if res {
			return map[string]any{"stopped": true, "legacy": true}, nil
		}
		return map[string]any{"stopped": false, "legacy": true, "error": "停止未完成（旧版语义），可重试"}, nil
	}
	return map[string]any{"stopped": false, "error": fmt.Sprintf("无法解析的服务端响应: %v", m)}, nil
}

// BoceRun dt131：error → 抛错（判失败而非透传）。
func (c *Client) BoceRun(url string, count, interval, threadCount, timeout int, mode, chromiumPath string) (map[string]any, error) {
	payload := map[string]any{"url": url, "count": count, "interval": interval,
		"thread_count": threadCount, "timeout": timeout, "mode": mode}
	if chromiumPath != "" {
		payload["chromium_path"] = chromiumPath
	}
	p, _ := json.Marshal(payload)
	if err := c.send(131, p); err != nil {
		return nil, err
	}
	m, err := c.recvLenPrefixedJSON()
	if err != nil {
		return nil, err
	}
	if msg, has := m["error"].(string); has {
		return nil, fmt.Errorf("boce failed: %s", msg)
	}
	return m, nil
}

// ReplayRun dt0：status=error → 抛错。
func (c *Client) ReplayRun(pcaps []string, upIface, downIface string, upVlan, downVlan *uint16, mbps int,
	forceIpSrc, forceIpDst *string, forceSport, forceDport *uint16) (map[string]any, error) {
	payload := map[string]any{"pcaps": pcaps, "uplink_iface": upIface, "downlink_iface": downIface, "mbps": mbps}
	if upVlan != nil {
		payload["uplink_vlan"] = *upVlan
	}
	if downVlan != nil {
		payload["downlink_vlan"] = *downVlan
	}
	if forceIpSrc != nil {
		payload["force_ip_src"] = *forceIpSrc
	}
	if forceIpDst != nil {
		payload["force_ip_dst"] = *forceIpDst
	}
	if forceSport != nil && *forceSport != 0 {
		payload["force_sport"] = *forceSport
	}
	if forceDport != nil && *forceDport != 0 {
		payload["force_dport"] = *forceDport
	}
	p, _ := json.Marshal(payload)
	if err := c.send(0, p); err != nil {
		return nil, err
	}
	b, err := c.recvUntilTimeout(500 * time.Millisecond)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m["status"] == "error" {
		msg, _ := m["message"].(string)
		return nil, fmt.Errorf("replay failed: %s", msg)
	}
	return m, nil
}

// SocketListen 171-175 编排（start/clean/save/fetch/stop）。
// fetch 返回 []byte；其余 ok 等。
func (c *Client) SocketListen(action string, listenPort int, file string, maxBytes int) (any, error) {
	switch action {
	case "start":
		p, _ := json.Marshal(map[string]any{"host": nil, "port": listenPort})
		if err := c.send(171, p); err != nil {
			return nil, err
		}
		b, err := c.recvUntilTimeout(500 * time.Millisecond)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		pids, _ := m["pid"].([]any)
		if len(pids) == 0 {
			return nil, fmt.Errorf("listen start failed: pid empty, resp=%v", m)
		}
		return m, nil
	case "clean":
		if err := c.send(172, nil); err != nil {
			return nil, err
		}
		return c.okOrErr("clean")
	case "stop":
		if err := c.send(175, nil); err != nil {
			return nil, err
		}
		return c.okOrErr("stop")
	case "save":
		if file == "" {
			return nil, errors.New("save requires file")
		}
		p, _ := json.Marshal(map[string]string{"file": file})
		if err := c.send(173, p); err != nil {
			return nil, err
		}
		return c.okOrErr("save")
	case "fetch":
		if err := c.send(174, nil); err != nil {
			return nil, err
		}
		// 首字节探测：'{' → 错误 JSON；否则 [8B Q][gzip]
		head, err := c.recvN(8)
		if err != nil {
			return nil, err
		}
		if head[0] == '{' {
			rest, _ := c.recvUntilTimeout(500 * time.Millisecond)
			raw := string(head) + string(rest)
			msg := raw
			var m map[string]string
			if json.Unmarshal([]byte(raw), &m) == nil {
				if e, ok := m["error"]; ok {
					msg = e
				}
			}
			return nil, fmt.Errorf("listen fetch failed: %s", msg)
		}
		n := binary.LittleEndian.Uint64(head)
		body, err := c.recvN(int(n))
		if err != nil {
			return nil, err
		}
		zr, err2 := gzip.NewReader(strings.NewReader(string(body)))
		if err2 != nil {
			return nil, err2
		}
		return io.ReadAll(zr)
	}
	return nil, fmt.Errorf("unknown action: %s", action)
}

func (c *Client) okOrErr(op string) (string, error) {
	b, err := c.recvUntilTimeout(300 * time.Millisecond)
	if err != nil {
		return "", err
	}
	if string(b) != "ok" {
		return "", fmt.Errorf("listen %s failed: %s", op, decodeListenError(b))
	}
	return "ok", nil
}

// UpgradeApply dt20（1.8.0+）：同步终态。
func (c *Client) UpgradeApply(version, sha256 string, force bool) (map[string]any, error) {
	p, _ := json.Marshal(map[string]any{"version": version, "sha256": sha256, "force": force})
	if err := c.send(20, p); err != nil {
		return nil, err
	}
	b, err := c.recvUntilTimeout(500 * time.Millisecond)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("无法解析的 dt20 响应: %q", b)
	}
	return m, nil
}

func writeFull(conn net.Conn, b []byte) error {
	_, err := conn.Write(b)
	return err
}

// ---- 连接池（pool.py 语义）----

const (
	poolMaxConnPerTarget = 5
	poolIdleTimeoutSec   = 600
	poolBorrowTimeoutSec = 10
)

type pooledConn struct {
	c        *Client
	lastUsed time.Time
}

// TargetPool 每靶机连接池。
type TargetPool struct {
	host, port string
	portN      int
	mu         sync.Mutex
	cond       *sync.Cond
	idle       []*pooledConn
	inuse      int
}

func NewTargetPool(host string, port int) *TargetPool {
	p := &TargetPool{host: host, portN: port, port: fmt.Sprintf("%s:%d", host, port)}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// isTimeout 网络超时判定（net.Error.Timeout()）。
func isTimeout(err error) bool {
	ne, ok := err.(interface{ Timeout() bool })
	return ok && ne.Timeout()
}

// probeAlive 空闲连接存活探针：1ms 读探针，零协议开销。
// 静默（i/o timeout）= 活；EOF/reset = 对端已死；读到数据 = 上次响应残留
// 协议错位，同样视为死。复用前先验，死的丢弃——否则靶机重启后池里每条
// 半开连接各吞一次请求（六轮验收 P2）。
func probeAlive(c *Client) bool {
	if c.conn == nil {
		return false
	}
	c.conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	buf := make([]byte, 1)
	_, err := c.conn.Read(buf)
	if err == nil {
		return false
	}
	return isTimeout(err)
}

// targetReachable 服务端进程存活验证（TCP 握手，不发数据，300ms 上限）。
//
// 为什么读探针不够（六轮验收 P2 复测）：服务端收到 TERM 退出后，旧连接的
// FIN 需经网络到达中央，这期间客户端侧 socket 仍 ESTABLISHED——1ms 读探针
// 无数据即判活，复用即 EOF，并发 N 路同时全败。读探针在原理上覆盖不了这个
// 窗口。新 dial 不受 FIN 传播影响：进程死=监听 socket 关=SYN 即刻 RST。
func targetReachable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Acquire 借出（borrow 超时）；复用同步 socket_timeout（N8）；connect 失败回滚计数。
func (p *TargetPool) Acquire(borrowTimeout, socketTimeout int) (*Client, error) {
	deadline := time.Now().Add(time.Duration(borrowTimeout) * time.Second)
	p.mu.Lock()
	for p.inuse >= poolMaxConnPerTarget {
		remain := time.Until(deadline)
		if remain <= 0 {
			p.mu.Unlock()
			return nil, fmt.Errorf("靶机 %s 连接池满,等待超时", p.host)
		}
		p.condWait(remain)
	}
	// 复用空闲连接；过期/探针判死的收集锁外关闭
	var reuse *Client
	var expired []*Client
	now := time.Now()
	for len(p.idle) > 0 {
		pc := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if now.Sub(pc.lastUsed) > poolIdleTimeoutSec*time.Second || !probeAlive(pc.c) {
			expired = append(expired, pc.c)
			continue
		}
		reuse = pc.c
		break
	}
	p.inuse++
	p.mu.Unlock()
	for _, c := range expired {
		c.Close()
	}
	if reuse != nil {
		if targetReachable(p.port) { // FIN 窗口：探针判活但服务端已死 → 弃复用走新建
			reuse.SetTimeout(socketTimeout) // N8
			return reuse, nil
		}
		// 弃复用，落入下方新建：connectWithRetry 自带退避，专吃 5~15s 重启窗口
		// （只重试建连、绝不重发请求）。借出计数不重复扣——新建失败路径统一
		// 负责 --；dial 判死到新建之间服务端恰好回来由 connectWithRetry 首次
		// 尝试自然覆盖。
		reuse.Close()
	}
	c := NewClient(p.host, p.portN, socketTimeout)
	if err := c.Connect(); err != nil {
		p.mu.Lock()
		p.inuse--
		p.mu.Unlock()
		p.cond.Broadcast()
		return nil, err
	}
	return c, nil
}

// Release 归还（healthy → 入池；否则锁外关闭）。
func (p *TargetPool) Release(c *Client, healthy bool) {
	p.mu.Lock()
	p.inuse--
	if healthy {
		p.idle = append(p.idle, &pooledConn{c: c, lastUsed: time.Now()})
	}
	p.mu.Unlock()
	p.cond.Broadcast()
	if !healthy {
		c.Close()
	}
}

// TargetResult 批量结果（_run_batch 用）。
type TargetResult struct {
	Target string
	Ok     bool
	Data   any
	Err    string
}

// Scheduler 全局池表 + 并发上限 50。
type Scheduler struct {
	mu    sync.Mutex
	pools map[string]*TargetPool
	sem   chan struct{}
}

func NewScheduler() *Scheduler {
	return &Scheduler{pools: map[string]*TargetPool{}, sem: make(chan struct{}, 50)}
}

func (s *Scheduler) GetPool(host string, port int) *TargetPool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s:%d", host, port)
	p := s.pools[key]
	if p == nil {
		p = NewTargetPool(host, port)
		s.pools[key] = p
	}
	return p
}

// connErrText 连接级错误语义化（六轮验收 P2 复测）：裸 EOF/reset 无地址无
// 上下文，现场无法判断「等一秒重试即可」。包装成可判读文案，原始原因保留在尾
// 部供定位。
func connErrText(err error) string {
	msg := err.Error()
	if msg == io.EOF.Error() || strings.Contains(msg, "connection reset") {
		return "靶机连接已断（靶机可能正在重启，请稍后重试）: " + msg
	}
	return msg
}

// Batch 并发执行（全局 50 并发上限）。
func (s *Scheduler) Batch(targets []string, port int, timeout int, fn func(c *Client) (any, error)) []TargetResult {
	var wg sync.WaitGroup
	results := make([]TargetResult, len(targets))
	for i, host := range targets {
		wg.Add(1)
		s.sem <- struct{}{}
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-s.sem }()
			pool := s.GetPool(host, port)
			c, err := pool.Acquire(poolBorrowTimeoutSec, timeout)
			if err != nil {
				results[i] = TargetResult{Target: host, Ok: false, Err: err.Error()}
				return
			}
			healthy := true
			data, err := fn(c)
			if err != nil {
				healthy = false
				results[i] = TargetResult{Target: host, Ok: false, Err: connErrText(err)}
			} else {
				results[i] = TargetResult{Target: host, Ok: true, Data: data}
			}
			pool.Release(c, healthy)
		}(i, host)
	}
	wg.Wait()
	return results
}

// condWait 带 deadline 的 cond 等待（pool borrow 超时语义）。
func (p *TargetPool) condWait(remain time.Duration) {
	timer := time.AfterFunc(remain, func() { p.cond.Broadcast() })
	defer timer.Stop()
	p.cond.Wait()
}
