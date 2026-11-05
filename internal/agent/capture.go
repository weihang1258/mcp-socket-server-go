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
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
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
	stop     chan struct{}
	stopOnce sync.Once // close(stop) 必须幂等：并发 dt6 走 select-default 会双关 channel → panic
	wg       sync.WaitGroup
	done     chan struct{} // 收尾完成（对齐子进程退出语义）
	result   bool          // sort/收尾成败（dt6 四态中的 pcap_complete 等价物）
	fatal    error         // 启动期/运行期致命错误
	src      pktSource     // stop 超时兜底强关（对齐 Python proc.terminate）
}

// tcpdumpStart dt5 实现：eth 空 → routeinfo 默认路由网卡（route 失败 → error 冒泡断连，
// 仅"无 Iface"→ false）；清旧文件；同 path 先停旧；BPF；启动 recv goroutine；
// 稳定窗 0.5s 查启动期致命错误（复审 P1-4）。
// 返回 (res, err)：err 非空 = Python RuntimeError 冒泡断连。
func tcpdumpStart(eth, path, extended string, singleQueue bool) (bool, error) {
	extended = strings.TrimSpace(extended) // Python capture.py:84 `(extended or "").strip()`
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
	offloadOffFn(eth) // GRO/LRO 合并大帧、TSO/GSO 拆帧：抓包比对必关

	var bpfInstrs []bpfInstr
	if extended != "" {
		var err error
		bpfInstrs, err = compileBPF(extended, eth)
		if err != nil {
			log.Printf("BPF 过滤编译失败(%s): %v", extended, err)
			return false, nil // 失败视为启动失败，不静默抓全部
		}
	}
	src, err := openPacketSocketFn(eth, bpfInstrs)
	if err != nil {
		log.Printf("启动抓包失败 %s -> %s: %v", eth, path, err)
		return false, nil
	}

	entry := &captureEntry{stop: make(chan struct{}), done: make(chan struct{}), src: src}
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
		entry.result, entry.fatal = captureRecvLoop(src, path, eth, entry.stop)
	}()
	// 稳定窗：0.5s 内查致命错误（网卡 down/文件打不开等 → 启动失败）
	time.Sleep(500 * time.Millisecond)
	select {
	case <-entry.done:
		// Python：0.5s 后线程没活着 → "抓包线程未存活" → res:false（无论有没有 _exc）
		if entry.fatal != nil {
			log.Printf("启动抓包失败 %s -> %s: %v", eth, path, entry.fatal)
		} else {
			log.Printf("抓包线程未存活 %s -> %s", eth, path)
		}
		return false, nil
	default:
	}
	// 注册表在「确认存活」之后才写：Python 是子进程回 ready 后才写 _captures
	// （capture.py:563）。提前写的话，启动窗口内的并发 dt6 会真的停掉这次抓包，
	// 而 dt5 仍回 true；Python 那边 dt6 是幂等 no-op。
	capturesMu.Lock()
	captures[path] = entry
	capturesMu.Unlock()
	log.Printf("已开启抓包 %s -> %s（extended=%q, single_queue=%v）", eth, path, extended, singleQueue)
	return true, nil
}

// drainMaxDuration 停止后 drain 队列的总时长上限（见 captureRecvLoop 注释）。
// var 仅为单测可缩短；生产恒 2s。
var drainMaxDuration = 2 * time.Second

// isEthDownErr 判断 recv 错误是否为 ENETDOWN/ENODEV（Python capture.py:222 的两个 errno）。
func isEthDownErr(err error) bool {
	return errors.Is(err, unix.ENETDOWN) || errors.Is(err, unix.ENODEV)
}

// captureCreateFn 创建 pcap 文件的注入点（测试替换以模拟磁盘满/只读）。
var captureCreateFn = func(path string) (*os.File, error) { return os.Create(path) }

// captureRecvLoop recv 循环：时间戳解码 → VLAN 还原 → 纳秒落盘；
// 停止 = 置 stop → drain 完缓冲帧 → stats → close（drain 语义 §3）。
func captureRecvLoop(src pktSource, path, eth string, stop chan struct{}) (res bool, fatal error) {
	f, err := captureCreateFn(path)
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
	// 写盘失败后续帧无意义（磁盘满），记下错误后停止采集，由 stop 报失败。
	var writeErr error
	write := func(data []byte, tsNs uint64) bool {
		n, err := writePacket(f, data, tsNs)
		pktCount += n
		if err != nil {
			writeErr = err
			return false
		}
		return true
	}
	defer func() {
		if writeErr != nil {
			res, fatal = false, fmt.Errorf("写 pcap 失败: %w", writeErr)
		}
	}()
	buf := make([]byte, 65535)
	deadline := time.Now().Add(1 * time.Second)
	// 停止语义（设计 §3）：置 stop 后必须 drain 完队列剩余帧再退出。
	// recv 超时 1s 保证循环及时看到 stop。
	//
	// **drain 必须有总时长硬上限**：只靠"1 秒内收不到新帧"判断空，在持续流量的
	// 网卡上永远不成立（真机 ens3 背景 ~10pps 实测：stop 30s 超时、pcap 无限增长、
	// 实例持锁导致同靶机 cmd_exec 全被拒，只能重启服务）。Python 版同源缺陷
	// （capture.py 的 recvmsg 1s 超时循环），只是重试时偶尔恰好抽空缓冲才成功。
	// 上限取 2s：远小于 stopCaptureEntry 的 30s，也足够把 stop 瞬间已进缓冲的
	// 在途帧读完（实测队列深度对应的排空时间 << 100ms）。
	for {
		select {
		case <-stop:
			// drain：收到 stop 后 2s 内尽可能收完，到点无条件退出
			drainDeadline := time.Now().Add(drainMaxDuration)
			for time.Now().Before(drainDeadline) {
				d := time.Now().Add(1 * time.Second)
				if d.After(drainDeadline) {
					d = drainDeadline
				}
				n, oob, err := src.recvFrame(buf, d)
				if err != nil {
					goto drained
				}
				if n == 0 {
					continue // Python `if not data: break`（空帧不是记录）
				}
				if !write(restoreVLAN(buf[:n], oob), decodeTimestampNs(oob)) {
					goto drained
				}
			}
			goto drained
		default:
		}
		n, oob, err := src.recvFrame(buf, deadline)
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				deadline = time.Now().Add(1 * time.Second)
				continue
			}
			if errors.Is(err, unix.EINTR) {
				// 被信号打断（Go runtime SIGURG 抢占等）：重试，不是终止条件。
				// 旧代码把 EINTR 当普通错误 goto drained，真机实测（35 enp94s0f0np0）
				// 回放 5 秒只抓到前 135 包、时间戳跨度 <1s，而内核 drops=0。
				continue
			}
			// Python capture.py:218-232：只有 ENETDOWN/ENODEV（网卡 down/消失）才置
			// _exc 让启动稳定窗判失败；其余错误（含 stop 关 socket）静默 break。
			// 仍走 drained 收尾以关闭 socket（f 由 defer 关）。
			if isEthDownErr(err) {
				src.close()
				return false, fmt.Errorf("抓包网卡不可用（网卡 down 或已拔出）: %w", err)
			}
			goto drained
		}
		if n == 0 {
			continue // Python `if not data: break`
		}
		deadline = time.Now().Add(1 * time.Second)
		if !write(restoreVLAN(buf[:n], oob), decodeTimestampNs(oob)) {
			goto drained
		}
	}
drained:
	// tpacket_stats 在 close 前读（真实 drops；fake 源无此步）
	_, drops := src.stats()
	src.close()
	if drops > 0 {
		log.Printf("抓包 %s 内核丢弃 %d 包", path, drops)
	}
	// Python 日志带 eth/path/包数/丢弃数（capture.py:390）
	log.Printf("抓包完成 %s -> %s：%d 包，内核丢弃 %d 包", eth, path, pktCount, drops)
	return sortPcapByTimestamp(path), nil // 0 包也重排（Python 无条件调用）；writeErr 由上面的 defer 转成失败
}

func writePacket(f *os.File, data []byte, tsNs uint64) (uint64, error) {
	sec := tsNs / 1e9
	nsec := tsNs % 1e9
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr, uint32(sec))
	binary.LittleEndian.PutUint32(hdr[4:], uint32(nsec))
	binary.LittleEndian.PutUint32(hdr[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(hdr[12:], uint32(len(data)))
	// 写盘错误必须冒泡：磁盘满/只读时原实现静默报成功，pcap 静默截断。
	if _, err := f.Write(hdr); err != nil {
		return 0, err
	}
	if _, err := f.Write(data); err != nil {
		return 0, err
	}
	return 1, nil
}

// cmsgIter 逐条遍历 oob。布局取内核/平台实际 ABI（unix.Cmsghdr），
// 不硬编码 64 位：32 位平台 Len 是 u32、对齐 4 字节，写死会全解析错。
// 返回 (level, type, data)；next 为剩余切片。clen 非法或越界即停（畸形防护）。
func cmsgIter(oob []byte) (lvl, ctype uint32, data, next []byte, ok bool) {
	hdrLen := unix.CmsgLen(0)
	if len(oob) < hdrLen {
		return 0, 0, nil, nil, false
	}
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	clen := int(h.Len)
	if clen < hdrLen || clen > len(oob) {
		return 0, 0, nil, nil, false
	}
	data = oob[hdrLen:clen]
	if a := unix.CmsgSpace(len(data)); a <= len(oob) {
		next = oob[a:]
	} // 尾条无对齐填充时 next=nil（遍历自然结束）
	return uint32(h.Level), uint32(h.Type), data, next, true
}

// monotonicNs 开机基准的单调纳秒（= Python time.monotonic_ns()）。
// 不能用 time.Since(进程启动时刻) 代替：那样无 cmsg 时 ts_sec 从 0 起跳，
// 与同机其它 pcap（含回放读取方）的时间轴对不上。
func monotonicNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return uint64(time.Since(startMono).Nanoseconds()) // 极端兜底
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// startMono 仅在 ClockGettime 不可用时兜底（正常路径永不使用）。
var startMono = time.Now()

// 时间戳档位（诊断用，见 warnHWDegraded）。
// hw 档下 ts[0] 为零说明网卡声称支持 PHC 但驱动没填，静默退化成软中断纳秒——
// Python 在同一处 warn 一次（capture.py:280-287），Go 原先无任何提示。
const (
	tsModeUser int32 = iota // 全失败：用户态单调时钟兜底
	tsModeNS                // SO_TIMESTAMPNS
	tsModeSW                // SO_TIMESTAMPING 仅 RX_SOFTWARE
	tsModeHW                // SO_TIMESTAMPING HW+SW+RAW
)

var (
	tsModeNow        atomic.Int32
	hwDegradedWarned atomic.Bool
)

// warnHWDegraded hw 档但 ts[0] 全零时告警一次（全进程一次，纯诊断）。
func warnHWDegraded() {
	if tsModeNow.Load() == tsModeHW && !hwDegradedWarned.Swap(true) {
		log.Printf("硬件时间戳未生效(ts[0]=0)，退化软中断纳秒；ethtool -T 显示 hardware-receive 但驱动未必填了 PHC")
	}
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
					warnHWDegraded() // hw 档但 ts[0]=0 → 静默退化，与 Python 一样告警一次
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
			// struct tpacket_auxdata（/usr/include/linux/if_packet.h:97-105）：
			// tp_status u32@0 / tp_len u32@4 / tp_snaplen u32@8 / tp_mac u16@12 /
			// tp_net u16@14 / tp_vlan_tci u16@16 / tp_vlan_tpid u16@18
			tci := binary.LittleEndian.Uint16(aux[16:18])
			tpid := binary.LittleEndian.Uint16(aux[18:20])
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
	var endian binary.ByteOrder = binary.LittleEndian
	switch magic {
	case 0xA1B2C3D4, 0xA1B23C4D:
		// 小端微秒/纳秒
	case 0xD4C3B2A1, 0x4D3CB2A1:
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
	if err := os.WriteFile(tmp, out.Bytes(), 0o644); err != nil {
		return false
	}
	if err := os.Rename(tmp, path); err != nil {
		return false
	}
	log.Printf("pcap 时间戳重排完成：%s（%d 包）", path, len(records))
	return true
}

// stopTimeout 停止等待上限（Python proc.join(timeout=30)）。var 仅为单测可缩短。
var stopTimeout = 30 * time.Second

// stopCaptureEntry 停止单实例：close(stop) 广播 → 超时后强关 socket 兜底
// （对齐 Python `proc.terminate()`，capture.py:583）。强关后 recv 立刻返回错误、
// goroutine 退出，再给 5s 收尾。仍超时返回 false（实例保留可重试），但 socket
// 已释放，不会再长期占着 CAPTURE 锁。
func stopCaptureEntry(e *captureEntry) bool {
	e.stopOnce.Do(func() { close(e.stop) })
	select {
	case <-e.done:
		return true
	case <-time.After(stopTimeout):
	}
	log.Printf("抓包停止超时(>%v)，强制关闭 socket（本轮 pcap 可能不完整）", stopTimeout)
	if e.src != nil {
		e.src.close()
	}
	select {
	case <-e.done:
		return true // terminate 兜底成功（对齐 Python terminate 后 join 成功）
	case <-time.After(5 * time.Second):
		log.Printf("强制关闭后仍未退出，保留实例可重试")
		return false
	}
}

// offloadOffFn 抓包前关 offload 的注入点（测试替换；默认调 ethtool -K）。
var offloadOffFn = disableOffloads

// disableOffloads 抓包前关 GRO/LRO/TSO/GSO。
//
// 为什么必须关：GRO/LRO 把同一流的多段合并成一个超大帧才交给抓包点，
// 而分流链路另一端若没合并就是原始小帧——业务按包比对时同一个报文在两处
// 抓到的长度/内容不同，必然判成不一致。TSO/GSO 是反方向：本机发出的"一帧"
// 到了线上被拆成多段，抓到的与发出的对不上。
//
// 实测（35→82 拉 20MB，AF_PACKET，MTU 1500）：
//
//	全开            最大帧 21786B，1221/3535 帧 >9000
//	仅关收侧 GRO    最大帧 2974B，无超 9000 帧
//	收发两侧全关    最大帧 1514B，无超 MTU 帧
//	（tx/rx-checksumming 同理：校验和由网卡后填，抓包看到的是未算完的坏包）
//
// best-effort：设备不支持（如 eno4 的 lro 是 off [fixed]）或 ethtool 缺失仅 warn，
// 不阻断抓包。**不随 stop 恢复**——比对窗口内多次抓包必须保持一致；要恢复请手工
// `ethtool -K <网卡> gro on tso on gso on`。
func disableOffloads(eth string) {
	if err := exec.Command("ethtool", "-K", eth, "gro", "off", "lro", "off", "tso", "off", "gso", "off").Run(); err != nil {
		log.Printf("关闭网卡 %s offload 失败(忽略；抓到的大帧可能与分流点不一致): %v", eth, err)
		return
	}
	log.Printf("已关闭网卡 %s 的 GRO/LRO/TSO/GSO（抓包停止后不自动恢复）", eth)
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
// 队列读写走 SIOCETHTOOL ioctl（ethtool -l/-L 的内核等价），capture.py 同语义。
func configureSingleQueue(eth string, count int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("单队列配置失败(忽略，仍可抓包): %v", r)
		}
	}()
	var cur ethtoolChannels
	cur.cmd = unix.ETHTOOL_GCHANNELS
	if err := ethtoolCtlFn(eth, &cur); err != nil {
		log.Printf("读取网卡 %s 队列数失败(忽略): %v", eth, err)
		return
	}
	if int(cur.combinedCount) == count {
		log.Printf("网卡 %s 已是单队列，仍尝试绑定CPU", eth)
		bindIRQToFreeCPU(eth, count) // Python：已是单队列仍绑（capture.py:841-844）
		return
	}
	// ethtool(8) 的语义：只置指定字段，其余为 0
	setReq := ethtoolChannels{cmd: unix.ETHTOOL_SCHANNELS, combinedCount: uint32(count)}
	if err := ethtoolCtlFn(eth, &setReq); err != nil {
		// fallback：rx/tx 分开设（capture.py:847-848）
		alt := ethtoolChannels{cmd: unix.ETHTOOL_SCHANNELS, rxCount: uint32(count), txCount: uint32(count)}
		if err2 := ethtoolCtlFn(eth, &alt); err2 != nil {
			log.Printf("设置网卡 %s 单队列失败(忽略，combined: %v，rx/tx: %v)", eth, err, err2)
			return
		}
	}
	queueSleepFn(3 * time.Second)
	bindIRQToFreeCPU(eth, count)
	queueSleepFn(2 * time.Second)
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
	cpu := pickFreeCPU(eth)
	log.Printf("将网卡 %s 的 %d 个中断绑定到 CPU%d", eth, len(irqs), cpu)
	for _, irq := range irqs {
		path := fmt.Sprintf("/proc/irq/%d/smp_affinity_list", irq)
		if _, err := os.Stat(path); err != nil {
			log.Printf("IRQ %d affinity 路径不存在，跳过", irq)
			continue
		}
		if err := os.WriteFile(path, []byte(fmt.Sprint(cpu)), 0o644); err != nil {
			log.Printf("IRQ %d -> CPU%d 写失败: %v", irq, cpu, err)
		} else {
			log.Printf("IRQ %d -> CPU %d", irq, cpu)
		}
	}
	disableRPSRFS(eth)
}

// cpuBinding 网卡→CPU 绑定记录（Python 的 _nic_cpu_binding/_allocated_cpus）。
// 多网卡同时抓包时必须把各自的 IRQ 绑到不同 CPU，否则软中断互抢导致乱序。
var (
	cpuBindingMu sync.Mutex
	cpuBinding   = map[string]int{}
	allocatedCPU = map[int]bool{}
)

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

// pickFreeCPU 选一个非 0 的空闲 CPU；同一网卡复用它上次绑定的 CPU，
// 不同网卡分到不同 CPU（Python _pick_target_cpu + _allocated_cpus）。
func pickFreeCPU(eth string) int {
	cpuBindingMu.Lock()
	if c, ok := cpuBinding[eth]; ok {
		cpuBindingMu.Unlock()
		log.Printf("网卡 %s 已绑定到 CPU %d，复用现有绑定", eth, c)
		return c
	}
	cpuBindingMu.Unlock()

	data, _ := os.ReadFile("/proc/stat")
	busy := map[int]bool{0: true}
	cpuBindingMu.Lock()
	for c := range allocatedCPU {
		busy[c] = true
	}
	cpuBindingMu.Unlock()
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
	cpu := n - 1
	for c := 1; c < n; c++ {
		if !busy[c] {
			cpu = c
			break
		}
	}
	cpuBindingMu.Lock()
	cpuBinding[eth] = cpu
	allocatedCPU[cpu] = true
	cpuBindingMu.Unlock()
	return cpu
}

func disableRPSRFS(eth string) {
	for _, name := range []string{"rps_cpus", "rps_flow_cnt"} {
		p := fmt.Sprintf("/sys/class/net/%s/queues/rx-0/%s", eth, name)
		if _, err := os.Stat(p); err != nil {
			continue // 网卡不支持 RPS/RFS
		}
		if err := os.WriteFile(p, []byte("0"), 0o644); err != nil {
			log.Printf("禁用网卡 %s 的 %s 失败: %v", eth, name, err)
			continue
		}
		log.Printf("已禁用网卡 %s 的 %s", eth, strings.ToUpper(strings.TrimPrefix(name, "rps_")))
	}
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

// defaultOpenPacketSocket AF_PACKET 真实现挂载点（afpacket_linux.go，Linux-only）。
// 非构建环境/无权限时返回错误 → dt5 res:false（对齐 Python 无权限场景）。
var defaultOpenPacketSocket = func(eth string, bpf []bpfInstr) (pktSource, error) {
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
