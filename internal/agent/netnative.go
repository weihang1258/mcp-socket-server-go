package agent

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// 原生网络操作：route / ifconfig / ethtool 三个外部命令的内核等价实现。
//
// 这三个命令本身只是内核接口的薄封装——route -n 读的就是 /proc/net/route，
// ifconfig 的 MTU 读写走 SIOCGIFMTU/SIOCSIFMTU，ethtool -l/-L 走 SIOCETHTOOL。
// 直接调内核接口：行为等价、少一次进程启动，install 也不再依赖 net-tools/ethtool
// 两个包（内网无源也能装）。

// ---- 路由表（route -n 替代）----

// routeTablePath 注入点（测试用 fixture 文件）。
var routeTablePath = "/proc/net/route"

// nativeRouteInfo 读 /proc/net/route，输出与旧 route -n 解析同构：
// 外层按 Destination（点分十进制）键控；行含 Gateway/Genmask/Flags/Metric/
// Ref/Use/Iface，值均为 route -n 的文本格式（IP 点分、Flags 字母、数字十进制）。
// /proc/net/route 的 Dest/GW/Flags/Mask 四列是 %08X 十六进制，其余列是十进制。
func nativeRouteInfo() (map[string]map[string]any, error) {
	data, err := os.ReadFile(routeTablePath)
	if err != nil {
		return nil, fmt.Errorf("读取路由表失败: %w", err)
	}
	res := map[string]map[string]any{}
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue // 头行
		}
		f := strings.Fields(line)
		if len(f) < 8 {
			continue
		}
		// 列: Iface Dest Gateway Flags RefCnt Use Metric Mask [MTU Window IRTT]
		res[hexIP(f[1])] = map[string]any{
			"Gateway": hexIP(f[2]),
			"Genmask": hexIP(f[7]),
			"Flags":   routeFlagLetters(f[3]),
			"Metric":  f[6],
			"Ref":     f[4],
			"Use":     f[5],
			"Iface":   f[0],
		}
	}
	return res, nil
}

// hexIP /proc/net/route 地址列：内核按内存字节序（小端机 = 地址字节反序）
// 打印的 %08X。FE830C0A → 10.12.131.254（真机实测）。
func hexIP(s string) string {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return s
	}
	return fmt.Sprintf("%d.%d.%d.%d", v&0xFF, v>>8&0xFF, v>>16&0xFF, v>>24&0xFF)
}

// routeFlagLetters route -n 的 Flags 列：U G H R D M 按位顺序拼接（0003 → "UG"）。
func routeFlagLetters(hex string) string {
	v, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return hex
	}
	var b strings.Builder
	for _, fl := range []struct {
		bit uint64
		ch  byte
	}{{1, 'U'}, {2, 'G'}, {4, 'H'}, {8, 'R'}, {0x10, 'D'}, {0x20, 'M'}} {
		if v&fl.bit != 0 {
			b.WriteByte(fl.ch)
		}
	}
	return b.String()
}

// ---- MTU（ifconfig eth / ifconfig eth mtu N 替代）----

// getMTUFn/setMTUFn 注入点（测试替换；生产 = SIOCGIFMTU/SIOCSIFMTU ioctl）。
var (
	getMTUFn = func(eth string) (int, error) { return ioctlMTU(eth, 0, false) }
	setMTUFn = func(eth string, mtu int) error {
		_, err := ioctlMTU(eth, mtu, true)
		return err
	}
)

// ioctlMTU SIOCGIFMTU / SIOCSIFMTU。ifreq 的 ifru_ivalue 是 union 首槽位
// （amd64 上偏移 16），MTU 读写都走它。
func ioctlMTU(eth string, mtu int, set bool) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var ifr struct {
		name [unix.IFNAMSIZ]byte
		val  int32
	}
	copy(ifr.name[:], eth)
	if set {
		ifr.val = int32(mtu)
	}
	req := uintptr(unix.SIOCGIFMTU)
	if set {
		req = unix.SIOCSIFMTU
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return 0, errno
	}
	return int(ifr.val), nil
}

// ---- 网卡队列（ethtool -l / ethtool -L 替代）----

// ethtoolChannels struct ethtool_channels（uapi/linux/ethtool.h）。
type ethtoolChannels struct {
	cmd                             uint32
	maxRx, maxTx, maxOther, maxCombined uint32
	rxCount, txCount, otherCount, combinedCount uint32
}

// ethtoolCtlFn 注入点（测试替换）。
var ethtoolCtlFn = func(eth string, ch *ethtoolChannels) error { return ioctlEthtoolChannels(eth, ch) }

// ioctlEthtoolChannels SIOCETHTOOL + struct ethtool_channels
// （ethtool -l / -L 与内核交互用的就是这一个 ioctl）。
func ioctlEthtoolChannels(eth string, ch *ethtoolChannels) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var ifr struct {
		name [unix.IFNAMSIZ]byte
		data uintptr
	}
	copy(ifr.name[:], eth)
	ifr.data = uintptr(unsafe.Pointer(ch))
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return errno
	}
	return nil
}

// queueSleepFn 注入点（单队列切换后的硬件稳定等待，测试桩掉）。
var queueSleepFn = time.Sleep
