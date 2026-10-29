//go:build linux

// AF_PACKET 真实现（capture.py AFPacketCapture/_open 移植，设计 §3 抓包段）。
// proto=0 创建 → 全部 setsockopt 就位（时间戳阶梯/AUXDATA/RCVBUF/promisc/BPF）
// → 最后 bind(eth, ETH_P_ALL)（防 bind→过滤窗口）。
// 权限前提：root 或 CAP_NET_RAW。
package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// afpacketSource pktSource 的 Linux 实现统计信息承载。
type afpacketSource struct {
	fd      int
	eth     string
	ifindex int
}

var _ pktSource = (*afpacketSource)(nil)

// openPacketSocketLinux 打开 AF_PACKET（export 给 openPacketSocketFn 替换）。
func openPacketSocketLinux(eth string) (pktSource, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0) // proto=0：不注册收包
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET,RAW,0): %w", err)
	}
	s := &afpacketSource{fd: fd, eth: eth}

	// 时间戳四级降级（L0 hw → L1 sw → L2 ns → L3 userspace）
	const (
		SOF_TIMESTAMPING_RX_SOFTWARE  = 1 << 3
		SOF_TIMESTAMPING_RX_HARDWARE  = 1 << 2
		SOF_TIMESTAMPING_RAW_HARDWARE = 1 << 6
		SO_TIMESTAMPNS                = 35
		SO_TIMESTAMPING               = 37
	)
	tsFlags := SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, SO_TIMESTAMPING, tsFlags); err != nil {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, SO_TIMESTAMPING, SOF_TIMESTAMPING_RX_SOFTWARE); err != nil {
			if err2 := unix.SetsockoptInt(fd, unix.SOL_SOCKET, SO_TIMESTAMPNS, 1); err2 != nil {
				log.Printf("网卡 %s 不支持任何内核时间戳（%v），回退用户态时间戳", eth, err2)
			}
		}
	}
	// PACKET_AUXDATA（VLAN 还原；失败仅 warn）
	const SOL_PACKET = 263
	const PACKET_AUXDATA = 8
	if err := unix.SetsockoptInt(fd, SOL_PACKET, PACKET_AUXDATA, 1); err != nil {
		log.Printf("网卡 %s 不支持 PACKET_AUXDATA: %v，VLAN 标签将无法还原", eth, err)
	}
	// SO_RCVBUF 32MB + 截断验证
	const reqRCV = 32 * 1024 * 1024
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, reqRCV); err == nil {
		if actual, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil && actual < reqRCV*2 {
			log.Printf("网卡 %s SO_RCVBUF 被截断：请求 %dKB，实际 %dKB。建议 sysctl -w net.core.rmem_max=8388608",
				eth, reqRCV/1024, actual/1024)
		}
	} else {
		log.Printf("网卡 %s 设置 SO_RCVBUF 失败: %v", eth, err)
	}
	iface, err := net.InterfaceByName(eth)
	if err != nil || iface.Index == 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("网卡 %s 不存在: %w", eth, err)
	}
	s.ifindex = iface.Index
	// promisc（失败不阻断）
	const PACKET_ADD_MEMBERSHIP = 1
	const PACKET_MR_PROMISC = 1
	mreq := make([]byte, 8+8) // ifindex u32 + type u16 + pad u16 + mac[8]
	binary.LittleEndian.PutUint32(mreq, uint32(iface.Index))
	binary.LittleEndian.PutUint16(mreq[4:], PACKET_MR_PROMISC)
	if err := setsockoptBytes(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq); err != nil {
		log.Printf("网卡 %s 开启 promisc 失败: %v（仍可抓本机流量）", eth, err)
	}
	// bind 最后做：此时才注册收包 hook，杜绝未过滤窗口
	addr := &unix.SockaddrLinklayer{Protocol: htonsUint16(0x0003), Ifindex: iface.Index} // ETH_P_ALL（x/sys 不转字节序，必须 htons——真机验收实锤）
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind(%s, ETH_P_ALL): %w", eth, err)
	}
	return s, nil
}

// setsockoptBytes 字节缓冲 setsockopt（mreq 等）。
func setsockoptBytes(fd, level, opt int, b []byte) error {
	return setsockoptPointer(fd, level, opt, unsafe.Pointer(&b[0]), len(b))
}

// attachBPF 注入 BPF 程序（tcpdump -ddd 编译结果）。
func attachBPF(fd int, ins []bpfInstr) error {
	if len(ins) == 0 {
		return nil
	}
	const SO_ATTACH_FILTER = 26

	prog := unix.SockFprog{Len: uint16(len(ins))}
	// SockFilter 数组转原生
	filters := make([]unix.SockFilter, len(ins))
	for i, in := range ins {
		filters[i] = unix.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	prog.Filter = &filters[0]
	return setsockoptPointer(fd, unix.SOL_SOCKET, SO_ATTACH_FILTER,
		unsafe.Pointer(&prog), int(unsafe.Sizeof(prog)))
}

// stats tpacket_stats（SOL_PACKET=263, opt 6）：{packets u32, drops u32}。
func (s *afpacketSource) stats() (packets, drops uint64) {
	var b [8]byte
	if err := setsockoptGetBytes(s.fd, 263, 6, b[:]); err != nil {
		return 0, 0
	}
	return uint64(binary.LittleEndian.Uint32(b[:4])), uint64(binary.LittleEndian.Uint32(b[4:]))
}

func (s *afpacketSource) recvFrame(buf []byte, deadline time.Time) (int, []byte, error) {
	if dl, err := deadlineFor(deadline); err == nil {
		unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &dl)
	}
	oob := make([]byte, 1024)
	n, oobn, _, _, err := unix.Recvmsg(s.fd, buf, oob, 0)
	if err != nil {
		return 0, nil, err
	}
	return n, oob[:oobn], nil
}

func (s *afpacketSource) close() error {
	// tpacket_stats 由 captureRecvLoop 在 close 前经 stats() 读取
	return unix.Close(s.fd)
}

func deadlineFor(t time.Time) (unix.Timeval, error) {
	d := time.Until(t)
	if d < 0 {
		d = 0
	}
	return unix.NsecToTimeval(d.Nanoseconds()), nil
}

// injectBPF 编译产物注入（recv goroutine 起跑前调用）。
func injectBPF(src pktSource, bpf []bpfInstr) error {
	afp, ok := src.(*afpacketSource)
	if !ok || len(bpf) == 0 {
		return nil
	}
	return attachBPF(afp.fd, bpf)
}

var errAFNotLinux = errors.New("AF_PACKET 仅 Linux")

// syscallReadRO 只读包装（供 setsockopt* 使用，避免重复 import）。
var _ = os.Geteuid

func init() {
	openPacketSocketFn = openPacketSocketLinux
	attachBPFIfAvailable = injectBPF
}

// htonsUint16 x/sys SockaddrLinklayer.Protocol 不做字节序转换（raw 为网络序 BE16），
// 小端主机必须手动转（真机验收实锤：直传 0x0003 → 内核读到 0x0300 → 永远收不到包）。
func htonsUint16(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.LittleEndian.Uint16(b)
}

// setsockoptPointer 通用指针 setsockopt。
func setsockoptPointer(fd, level, opt int, p unsafe.Pointer, l int) error {
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(p), uintptr(l), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// setsockoptGetBytes 通用 getsockopt。
func setsockoptGetBytes(fd, level, opt int, b []byte) error {
	l := uint32(len(b))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&l)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// rawPacketSender 回放发送（AF_PACKET SOCK_RAW，replayer 用；socket 按 iface 缓存）。
type rawPacketSender struct {
	fd      int
	ifindex int
}

// sendSockets 按网卡缓存发送 socket（裸 TCP 多连接可并发发 dt0 → 必须加锁；
// 对照 capture.go 的 capturesMu）。fd 常驻不关：数量按网卡数有界（§12#26）。
var (
	sendMu      sync.Mutex
	sendSockets = map[string]*rawPacketSender{}
)

// replaySendLinux 回放发送实现（export 给 replaySendFn 替换；root/CAP_NET_RAW）。
func replaySendLinux(iface string, pkt []byte) error {
	s, err := replaySenderFor(iface)
	if err != nil {
		return err
	}
	addr := &unix.SockaddrLinklayer{Ifindex: s.ifindex}
	return unix.Sendto(s.fd, pkt, 0, addr)
}

// replaySenderFor 按网卡取/建发送 socket（缓存复用，对齐 Python _uplink_socket/_downlink_socket）。
func replaySenderFor(iface string) (*rawPacketSender, error) {
	sendMu.Lock()
	defer sendMu.Unlock()
	if s, ok := sendSockets[iface]; ok {
		return s, nil
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, err
	}
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: ifaceObj.Index}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	s := &rawPacketSender{fd: fd, ifindex: ifaceObj.Index}
	sendSockets[iface] = s
	return s, nil
}

// prepareReplaySockets 对齐 Python _setup_sockets()：上行必建；下行仅在 iface 不同时建。
func prepareReplaySockets(upIface, downIface string) error {
	if _, err := replaySenderFor(upIface); err != nil {
		return err
	}
	if downIface != upIface {
		if _, err := replaySenderFor(downIface); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	replaySendFn = replaySendLinux
	replayPrepareFn = prepareReplaySockets
}
