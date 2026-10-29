package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 抓包（capture.py 移植，设计 §3 抓包段）。
// AF_PACKET 真实现见 afpacket_linux.go（build tag linux，root/CAP_NET_RAW）；
// 本文件：注册表 / dt5/6 wire 契约 / recv 循环 / VLAN 还原 / 时间戳降级 /
// 停止 drain / tpacket_stats / pcap 纳秒写 / 4 magic 时间戳重排 / BPF tcpdump -ddd。
// socket 层经 pktSource 接口注入（测试 fake / Linux 真实现）。

// pktSource 包源抽象（recvFrame 带超时；oob 为内核控制消息）。
type pktSource interface {
	recvFrame(buf []byte, deadline time.Time) (n int, oob []byte, err error)
	close() error
	// stats tpacket_stats（close 前读；fake 源返 0）。
	stats() (packets, drops uint64)
}

// openPacketSocketFn 打开 AF_PACKET socket（Linux 实现注入点）。
var openPacketSocketFn = defaultOpenPacketSocket

// bpfCaptureFn BPF 注入观测点（测试用）。
var bpfCaptureHook func([]bpfInstr)

func setBPFCapture(f func([]bpfInstr)) { bpfCaptureHook = f }

type bpfInstr struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

var (
	capturesMu sync.Mutex
	captures   = map[string]*captureEntry{} // path → entry
)

type captureEntry struct {
	stop   chan struct{}
	wg     sync.WaitGroup
	done   chan struct{} // 收尾完成（对齐子进程退出语义）
	result bool          // sort/收尾成败（dt6 四态中的 pcap_complete 等价物）
	fatal  error         // 启动期/运行期致命错误
}

// tcpdumpStart dt5 实现：eth 空 → routeinfo 默认路由网卡（route 失败 → error 冒泡断连，
// 仅"无 Iface"→ false）；清旧文件；同 path 先停旧；BPF；启动 recv goroutine；
// 稳定窗 0.5s 查启动期致命错误（复审 P1-4）。
// 返回 (res, err)：err 非空 = Python RuntimeError 冒泡断连。
func tcpdumpStart(eth, path, extended string, singleQueue bool) (bool, error) {
	if eth == "" {
		rt, err := routeinfo()
		if err != nil {
			return false, err // Python routeinfo() 异常冒泡 → 断连
		}
		if def := rt["0.0.0.0"]; def != nil {
			if iface, ok := def["Iface"].(string); ok {
				eth = iface
			}
		}
		if eth == "" {
			log.Printf("未指定网卡且系统无默认路由，无法确定抓包网卡")
			return false, nil
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("清理旧 pcap %s 失败: %v", path, err)
	}

	capturesMu.Lock()
	if old, ok := captures[path]; ok {
		log.Printf("path %s 已有抓包在运行，先停止旧实例", path)
		capturesMu.Unlock()
		stopCaptureEntry(old)
		capturesMu.Lock()
		delete(captures, path)
	}
	capturesMu.Unlock()

	if singleQueue {
		log.Printf("配置网卡 %s 为单队列模式（默认开启）", eth)
		configureSingleQueue(eth, 1) // best-effort：失败仅 warn
	}

	var bpfInstrs []bpfInstr
	if extended != "" {
		var err error
		bpfInstrs, err = compileBPF(extended, eth)
		if err != nil {
			log.Printf("BPF 过滤编译失败(%s): %v", extended, err)
			return false, nil // 失败视为启动失败，不静默抓全部
		}
	}
	src, err := openPacketSocketFn(eth)
	if err != nil {
		log.Printf("启动抓包失败 %s -> %s: %v", eth, path, err)
		return false, nil
	}
	if err := attachBPFIfAvailable(src, bpfInstrs); err != nil {
		log.Printf("BPF 注入失败: %v", err)
		src.close()
		return false, nil
	}

	entry := &captureEntry{stop: make(chan struct{}), done: make(chan struct{})}
	capturesMu.Lock()
	captures[path] = entry
	capturesMu.Unlock()

	entry.wg.Add(1)
	go func() {
		defer entry.wg.Done()
		defer close(entry.done)
		defer func() {
			if r := recover(); r != nil { // §12#2：长驻 goroutine 强制 recover
				entry.fatal = fmt.Errorf("recv panic: %v", r)
				log.Printf("抓包 recv panic(已隔离): %v", r)
			}
		}()
		entry.result, entry.fatal = captureRecvLoop(src, path, bpfInstrs, entry.stop)
	}()
	// 稳定窗：0.5s 内查致命错误（网卡 down/文件打不开等 → 启动失败）
	time.Sleep(500 * time.Millisecond)
	select {
	case <-entry.done:
		capturesMu.Lock()
		delete(captures, path)
		capturesMu.Unlock()
		if entry.fatal != nil {
			log.Printf("启动抓包失败 %s -> %s: %v", eth, path, entry.fatal)
			return false, nil
		}
	default:
	}
	log.Printf("已开启抓包 %s -> %s（extended=%q, single_queue=%v）", eth, path, extended, singleQueue)
	return true, nil
}

// captureRecvLoop recv 循环：时间戳解码 → VLAN 还原 → 纳秒落盘；
// 停止 = 置 stop → drain 完缓冲帧 → stats → close（drain 语义 §3）。
func captureRecvLoop(src pktSource, path string, bpf []bpfInstr, stop chan struct{}) (bool, error) {
	_ = bpf // 已在 open 后 attachBPFIfAvailable 注入
	f, err := os.Create(path)
	if err != nil {
		return false, fmt.Errorf("创建 pcap 失败: %w", err)
	}
	defer f.Close()
	// pcap 全局头：纳秒 magic、snaplen 65535、Ethernet
	gh := make([]byte, 24)
	binary.LittleEndian.PutUint32(gh, 0xA1B23C4D)
	binary.LittleEndian.PutUint16(gh[4:], 2)
	binary.LittleEndian.PutUint16(gh[6:], 4)
	binary.LittleEndian.PutUint32(gh[16:], 65535)
	binary.LittleEndian.PutUint32(gh[20:], 1)
	if _, err := f.Write(gh); err != nil {
		return false, err
	}

	var pktCount uint64
	buf := make([]byte, 65535)
	deadline := time.Now().Add(1 * time.Second)
	// 停止语义（设计 §3）：置 stop 后必须 drain 完队列剩余帧再退出。
	// recv 超时 1s 保证循环及时看到 stop。
	for {
		select {
		case <-stop:
			// drain：继续收，1s 无新帧即空
			for {
				n, oob, err := src.recvFrame(buf, time.Now().Add(1*time.Second))
				if err != nil {
					goto drained
				}
				pktCount += writePacket(f, restoreVLAN(buf[:n], oob), decodeTimestampNs(oob))
			}
		default:
		}
		n, oob, err := src.recvFrame(buf, deadline)
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				deadline = time.Now().Add(1 * time.Second)
				continue
			}
			goto drained
		}
		deadline = time.Now().Add(1 * time.Second)
		pktCount += writePacket(f, restoreVLAN(buf[:n], oob), decodeTimestampNs(oob))
	}
drained:
	// tpacket_stats 在 close 前读（真实 drops；fake 源无此步）
	if _, drops := src.stats(); drops > 0 {
		log.Printf("抓包 %s 内核丢弃 %d 包", path, drops)
	}
	src.close()
	log.Printf("抓包完成：%d 包", pktCount)
	if pktCount > 0 {
		return sortPcapByTimestamp(path), nil
	}
	return true, nil
}

func writePacket(f *os.File, data []byte, tsNs uint64) uint64 {
	sec := tsNs / 1e9
	nsec := tsNs % 1e9
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr, uint32(sec))
	binary.LittleEndian.PutUint32(hdr[4:], uint32(nsec))
	binary.LittleEndian.PutUint32(hdr[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(hdr[12:], uint32(len(data)))
	f.Write(hdr)
	f.Write(data)
	return 1
}

// cmsgAlign CMSG_ALIGN（64 位 = 8 字节对齐，复审 P2-7）。
func cmsgAlign(n int) int { return (n + 7) &^ 7 }

// monotonicNs 单调纳秒（对齐 time.monotonic_ns：不随 NTP 回退，复审 P2-8）。
var startMono = time.Now()

func monotonicNs() uint64 { return uint64(time.Since(startMono).Nanoseconds()) }

// cmsgIter 逐条遍历 oob（64 位 ABI：len u64@0 / level i32@8 / type i32@12 / data@16）。
// 返回 (level, type, data)；next 为剩余切片。clen<16 或越界即停（畸形防护，复审 P1-6）。
func cmsgIter(oob []byte) (lvl, ctype uint32, data, next []byte, ok bool) {
	if len(oob) < 16 {
		return 0, 0, nil, nil, false
	}
	clen := int(binary.LittleEndian.Uint64(oob[:8]))
	if clen < 16 || clen > len(oob) {
		return 0, 0, nil, nil, false
	}
	lvl = binary.LittleEndian.Uint32(oob[8:])
	ctype = binary.LittleEndian.Uint32(oob[12:])
	data = oob[16:clen]
	if a := cmsgAlign(clen); a <= len(oob) {
		next = oob[a:]
	} // 尾条无对齐填充时 next=nil（遍历自然结束）
	return lvl, ctype, data, next, true
}

// decodeTimestampNs 时间戳四级降级（设计 §3）：
// SCM_TIMESTAMPING(SOL_SOCKET=1,type=37)：ts[0] hw 非 0 用 hw；否则 ts[1] sw；
// SO_TIMESTAMPNS(type=35)：单 timespec；无 cmsg → monotonic。
func decodeTimestampNs(oob []byte) uint64 {
	for len(oob) >= 16 {
		lvl, ctype, data, next, ok := cmsgIter(oob)
		if !ok {
			break
		}
		oob = next
		if lvl != 1 { // SOL_SOCKET
			continue
		}
		switch ctype {
		case 37: // SCM_TIMESTAMPING：3×timespec(@ll,16B each)
			if len(data) >= 48 {
				hwSec := binary.LittleEndian.Uint64(data)
				hwNsec := binary.LittleEndian.Uint64(data[8:])
				swSec := binary.LittleEndian.Uint64(data[16:])
				swNsec := binary.LittleEndian.Uint64(data[24:])
				if hwSec != 0 || hwNsec != 0 {
					return hwSec*1e9 + hwNsec
				}
				if swSec != 0 || swNsec != 0 {
					return swSec*1e9 + swNsec
				}
			}
		case 35: // SO_TIMESTAMPNS：单 timespec
			if len(data) >= 16 {
				sec := binary.LittleEndian.Uint64(data)
				nsec := binary.LittleEndian.Uint64(data[8:])
				if sec != 0 || nsec != 0 {
					return sec*1e9 + nsec
				}
			}
		}
	}
	return monotonicNs() // monotonic 兜底（time.monotonic_ns 对齐）
}

// restoreVLAN auxdata（SOL_PACKET=263,type=8）VLAN_VALID → offset 12 插 TPID+TCI。
// 返回原帧或还原帧；<12B 原样。
func restoreVLAN(data, oob []byte) []byte {
	for len(oob) >= 16 {
		lvl, ctype, auxFull, next, ok := cmsgIter(oob)
		if !ok {
			break
		}
		oob = next
		if lvl != 263 || ctype != 8 { // SOL_PACKET / PACKET_AUXDATA
			continue
		}
		{
			aux := auxFull
			if len(aux) < 20 {
				continue
			}
			tpStatus := binary.LittleEndian.Uint32(aux)
			tci := binary.LittleEndian.Uint16(aux[12:14])
			tpid := binary.LittleEndian.Uint16(aux[14:16])
			if tci == 0 && tpStatus&0x10 == 0 {
				return data
			}
			if tpid == 0 && tpStatus&0x40 == 0 {
				tpid = 0x8100
			}
			if len(data) < 12 {
				return data
			}
			out := make([]byte, 0, len(data)+4)
			out = append(out, data[:12]...)
			var tag [4]byte
			binary.BigEndian.PutUint16(tag[:2], tpid)
			binary.BigEndian.PutUint16(tag[2:], tci)
			out = append(out, tag[:]...)
			out = append(out, data[12:]...)
			return out
		}
	}
	return data
}

// writePacket 的 VLAN 感知版本（recv 循环调用）：注 writePacket 之上由循环先 restore。
// （recv 循环内直接 restoreVLAN(buf[:n], oob) 后写盘。）

// compileBPF `tcpdump -ddd <expr> -i <eth>`：首行条数 + 逐行 code jt jf k。
// tcpdump 缺失/编译失败 → error（= 抓包启动失败）。
func compileBPF(expr, eth string) ([]bpfInstr, error) {
	cmd := exec.Command("tcpdump", "-ddd", expr, "-i", eth)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("tcpdump -ddd: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	lines := strings.Fields(strings.TrimSpace(stdout.String()))
	if len(lines) < 1 {
		return nil, errors.New("tcpdump -ddd empty output")
	}
	var n int
	if _, err := fmt.Sscanf(lines[0], "%d", &n); err != nil || n <= 0 {
		return nil, fmt.Errorf("tcpdump -ddd bad count %q", lines[0])
	}
	vals := lines[1:]
	if len(vals) < n*4 {
		return nil, errors.New("tcpdump -ddd truncated program")
	}
	ins := make([]bpfInstr, n)
	for i := 0; i < n; i++ {
		var code, jt, jf uint64
		var k uint64
		fmt.Sscanf(vals[i*4], "%d", &code)
		fmt.Sscanf(vals[i*4+1], "%d", &jt)
		fmt.Sscanf(vals[i*4+2], "%d", &jf)
		fmt.Sscanf(vals[i*4+3], "%d", &k)
		ins[i] = bpfInstr{Code: uint16(code), Jt: uint8(jt), Jf: uint8(jf), K: uint32(k)}
	}
	if bpfCaptureHook != nil {
		bpfCaptureHook(ins)
	}
	return ins, nil
}

// sortPcapByTimestamp 时间戳稳定重排（4 magic 识别；不识别跳过；原子 replace）。
func sortPcapByTimestamp(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 24 {
		return true // 全局头不完整：跳过重排
	}
	magic := binary.LittleEndian.Uint32(data[:4])
	var divisor uint64
	var endian binary.ByteOrder = binary.LittleEndian
	switch magic {
	case 0xA1B2C3D4:
		divisor = 1e6
	case 0xD4C3B2A1:
		divisor = 1e6
		endian = binary.BigEndian
	case 0xA1B23C4D:
		divisor = 1e9
	case 0x4D3CB2A1:
		divisor = 1e9
		endian = binary.BigEndian
	default:
		log.Printf("pcap magic 不识别(%x)，跳过重排：%s", magic, path)
		return true
	}
	type rec struct {
		sec, frac uint32
		idx       int
		data      []byte
	}
	var records []rec
	for off := 24; off+16 <= len(data); {
		sec := endian.Uint32(data[off:])
		frac := endian.Uint32(data[off+4:])
		incl := endian.Uint32(data[off+8:])
		if off+16+int(incl) > len(data) {
			log.Printf("pcap 末尾记录截断，已读取 %d 包：%s", len(records), path)
			break
		}
		records = append(records, rec{sec, frac, len(records), data[off+16 : off+16+int(incl)]})
		off += 16 + int(incl)
	}
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.sec != b.sec {
			return a.sec < b.sec
		}
		if a.frac != b.frac {
			return a.frac < b.frac
		}
		return a.idx < b.idx
	})
	tmp := path + ".sorted"
	var out bytes.Buffer
	out.Write(data[:24])
	for _, r := range records {
		var h [16]byte
		endian.PutUint32(h[:], r.sec)
		endian.PutUint32(h[4:], r.frac)
		endian.PutUint32(h[8:], uint32(len(r.data)))
		endian.PutUint32(h[12:], uint32(len(r.data)))
		out.Write(h[:])
		out.Write(r.data)
	}
	_ = divisor
	if err := os.WriteFile(tmp, out.Bytes(), 0o644); err != nil {
		return false
	}
	return os.Rename(tmp, path) == nil
}

// stopCaptureEntry 停止单实例：close(stop) 广播 → 30s 超时（对齐 join 30s + terminate 兜底）。
// 超时返回 false（实例保留可重试）。
func stopCaptureEntry(e *captureEntry) bool {
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
	select {
	case <-e.done:
		return true
	case <-time.After(30 * time.Second):
		log.Printf("抓包停止超时(>30s)，保留实例可重试")
		return false
	}
}

// tcpdumpStop dt6：幂等（未在抓 res:true）；停止失败/收尾失败 res:false。
// 失败保留实例可重试（对齐 Python 语义）。
func tcpdumpStop(path string) bool {
	capturesMu.Lock()
	entry, ok := captures[path]
	capturesMu.Unlock()
	if !ok {
		return true // 幂等：未在抓
	}
	if !stopCaptureEntry(entry) {
		return false
	}
	capturesMu.Lock()
	delete(captures, path)
	capturesMu.Unlock()
	return entry.result
}

// 配置单队列（best-effort：任何失败仅 warn 不阻断，设计 §3 单队列段）。
func configureSingleQueue(eth string, count int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("单队列配置失败(忽略，仍可抓包): %v", r)
		}
	}()
	code, out, _ := execCmdArgs("ethtool", "-l", eth)
	if code != 0 {
		log.Printf("ethtool -l 失败(忽略): %s", eth)
		return
	}
	// 解析 Combined 当前值
	cur := -1
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Combined") {
			fmt.Sscanf(strings.TrimSpace(strings.Split(line, ":")[1]), "%d", &cur)
		}
	}
	if cur == count {
		log.Printf("网卡 %s 已是单队列，仍尝试绑定CPU", eth)
		bindIRQToFreeCPU(eth, count) // Python：已是单队列仍绑（capture.py:841-844）
		return
	}
	if c, _, err := runCombined("ethtool", "-L", eth, "combined", fmt.Sprint(count)); c != 0 || err != nil {
		// fallback：ethtool -L rx/tx（capture.py:847-848）
		if c2, _, err2 := runCombined("ethtool", "-L", eth, "rx", fmt.Sprint(count), "tx", fmt.Sprint(count)); c2 != 0 || err2 != nil {
			log.Printf("ethtool -L 失败(忽略): %s", eth)
			return
		}
	}
	time.Sleep(3 * time.Second)
	bindIRQToFreeCPU(eth, count)
	time.Sleep(2 * time.Second)
}

// bindIRQToFreeCPU IRQ 三路查找（msi_irqs → /proc/interrupts 名称匹配含 mlx5 → grep）
// + 绑非 0 空闲 CPU + 禁 RPS/RFS。全部 best-effort。
func bindIRQToFreeCPU(eth string, count int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("CPU 绑定失败(忽略): %v", r)
		}
	}()
	irqs := irqsViaSysfs(eth, count)
	if len(irqs) == 0 {
		irqs = irqsViaProcInterrupts(eth, count)
	}
	if len(irqs) == 0 {
		log.Printf("网卡 %s 无法获取中断号，跳过CPU绑定", eth)
		return
	}
	cpu := pickFreeCPU()
	for _, irq := range irqs {
		path := fmt.Sprintf("/proc/irq/%d/smp_affinity_list", irq)
		if _, err := os.Stat(path); err == nil {
			os.WriteFile(path, []byte(fmt.Sprint(cpu)), 0o644)
		}
	}
	disableRPSRFS(eth)
}

func irqsViaSysfs(eth string, count int) []int {
	entries, err := os.ReadDir(fmt.Sprintf("/sys/class/net/%s/device/msi_irqs", eth))
	if err != nil {
		return nil
	}
	var irqs []int
	for _, e := range entries {
		if n, err := fmt.Sscanf(e.Name(), "%d", new(int)); err == nil && n == 1 {
			var v int
			fmt.Sscanf(e.Name(), "%d", &v)
			irqs = append(irqs, v)
		}
	}
	sort.Ints(irqs)
	if len(irqs) > max(count*2, 4) {
		irqs = irqs[:max(count*2, 4)]
	}
	return irqs
}

func irqsViaProcInterrupts(eth string, count int) []int {
	data, err := os.ReadFile("/proc/interrupts")
	if err != nil {
		return nil
	}
	var irqs []int
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, eth) && !strings.Contains(strings.ToLower(line), "mlx5") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(line[:idx])); err == nil {
			irqs = append(irqs, n)
			if len(irqs) >= count {
				break
			}
		}
	}
	return irqs
}

func pickFreeCPU() int {
	data, _ := os.ReadFile("/proc/stat")
	busy := map[int]bool{0: true}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu") || line == "cpu " || strings.HasPrefix(line, "cpuid") {
			continue
		}
		var id int
		if _, err := fmt.Sscanf(line[:4+len(strings.TrimSpace(line[3:5]))], "cpu%d", &id); err != nil {
			continue
		}
		var user, nice, sys, idle, iowait, irq, softirq uint64
		fmt.Sscanf(line, "cpu%d %d %d %d %d %d %d %d", &id, &user, &nice, &sys, &idle, &iowait, &irq, &softirq)
		total := user + nice + sys + idle + iowait + irq + softirq
		if total > 0 && float64(total-idle)/float64(total) >= 0.99 {
			busy[id] = true
		}
	}
	n := 8
	if c, err := strconv.Atoi(readFirstLine("/sys/devices/system/cpu/present")); err == nil {
		_ = c
	}
	if cores, err := os.ReadDir("/sys/devices/system/cpu"); err == nil {
		count := 0
		for _, e := range cores {
			if strings.HasPrefix(e.Name(), "cpu") && e.Name() != "cpuidle" && !strings.Contains(e.Name(), "cpufreq") {
				if _, err := strconv.Atoi(e.Name()[3:]); err == nil {
					count++
				}
			}
		}
		if count > 0 {
			n = count
		}
	}
	for c := 1; c < n; c++ {
		if !busy[c] {
			return c
		}
	}
	return n - 1
}

func readFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if i := strings.IndexByte(string(data), '\n'); i >= 0 {
		return string(data[:i])
	}
	return string(data)
}

func disableRPSRFS(eth string) {
	for _, name := range []string{"rps_cpus", "rps_flow_cnt"} {
		p := fmt.Sprintf("/sys/class/net/%s/queues/rx-0/%s", eth, name)
		if _, err := os.Stat(p); err == nil {
			os.WriteFile(p, []byte("0"), 0o644)
		}
	}
}

// runCombined 组合执行（供 configureSingleQueue）。
func runCombined(name string, args ...string) (int, string, error) {
	c := exec.Command(name, args...)
	var out bytes.Buffer
	c.Stdout = &out
	err := c.Run()
	return exitCodeOfCmd(c, err), out.String(), err
}

func exitCodeOfCmd(c *exec.Cmd, err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return processExitCode(ee)
	}
	return -1
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// attachBPFIfAvailable BPF 注入挂载点（afpacket_linux.go init 覆盖）。
// 非 Linux 编译时保持 no-op → 抓包本就不可用（openPacketSocketFn 返回错误）。
var attachBPFIfAvailable = func(src pktSource, bpf []bpfInstr) error { return nil }

// defaultOpenPacketSocket AF_PACKET 真实现挂载点（afpacket_linux.go，Linux-only）。
// 非构建环境/无权限时返回错误 → dt5 res:false（对齐 Python 无权限场景）。
var defaultOpenPacketSocket = func(eth string) (pktSource, error) {
	return nil, errors.New("AF_PACKET 未启用（需 Linux + CAP_NET_RAW，见 afpacket_linux.go）")
}

// stopAllCapturesForTest 测试辅助：停全部实例。
func stopAllCapturesForTest() {
	capturesMu.Lock()
	entries := make([]*captureEntry, 0, len(captures))
	for _, e := range captures {
		entries = append(entries, e)
	}
	capturesMu.Unlock()
	for _, e := range entries {
		stopCaptureEntry(e)
	}
	capturesMu.Lock()
	captures = map[string]*captureEntry{}
	capturesMu.Unlock()
}
