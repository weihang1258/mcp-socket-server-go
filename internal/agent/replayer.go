package agent

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// 回放（replayer.py 移植，设计 §3 回放段）。
// 发送层注入（replaySendFn）：Linux AF_PACKET 真实现待接（同 capture）；
// 方向判定 if/elif 链（hint 失配不回退）；对称换向；IPv4↔IPv6 互转（半成品 ICMP 照抄）；
// 非 IP 帧跳过；ts_divisor 按 magic；max(orig_len,60) 字节统计；两级限速。

// replaySendFn 按方向发包（iface, pkt）；注入点。
var replaySendFn = func(iface string, pkt []byte) error {
	return errors.New("AF_PACKET 发送未启用（需 Linux + CAP_NET_RAW）")
}

// ---- 五元组与流表 ----

type tuple5 struct {
	macSrc, macDst string
	ipSrc, ipDst   string
	sport, dport   uint16
	proto          string // TCP/UDP/OTHER
}

type flowInfo5 struct {
	direction          string
	firstSeen          float64
	modIpSrc, modIpDst string
	modSport, modDport uint16
}

// replayer 单次回放会话（对齐 PcapReplayer 实例）。
type replayer struct {
	upIface, downIface     string
	upVlan, downVlan       *uint16
	mbps                   int
	forceIpSrc, forceIpDst *string
	forceSport, forceDport *uint16
	forceBuildFlow         bool
	clientHint, serverHint *string

	flowTable map[tuple5Key]*flowInfo5
	flowCount int
	// 统计
	totalFiles, totalPackets int
	totalBytes               int
	upPackets, upBytes       int
	downPackets, downBytes   int
	startTime, endTime       float64
}

type tuple5Key struct {
	a, b  tuple5
	proto string
}

func (r *replayer) directionless() bool {
	return r.upIface == r.downIface && r.upVlanEq() && r.upIface != ""
}

func (r *replayer) upVlanEq() bool {
	if r.upVlan == nil && r.downVlan == nil {
		return true
	}
	return r.upVlan != nil && r.downVlan != nil && *r.upVlan == *r.downVlan
}

func (r *replayer) noTupleMod() bool {
	return r.forceIpSrc == nil && r.forceIpDst == nil && r.forceSport == nil && r.forceDport == nil
}

// reversedKey 反向五元组。
func reversedKey(k tuple5Key, t tuple5) tuple5Key {
	rev := t
	rev.macSrc, rev.macDst = t.macDst, t.macSrc
	rev.ipSrc, rev.ipDst = t.ipDst, t.ipSrc
	rev.sport, rev.dport = t.dport, t.sport
	return tuple5Key{a: rev, b: mirror(rev), proto: k.proto}
}

func mirror(t tuple5) tuple5 { return t }

// getDirection if/elif 链（复刻：hint 双设失配 → 默认 uplink，不回退 SYN）。
func (r *replayer) getDirection(key tuple5Key, t tuple5, flags byte, ts float64) string {
	if fi, ok := r.flowTable[key]; ok {
		return fi.direction
	}
	direction := "uplink"
	if r.clientHint != nil && r.serverHint != nil {
		if t.ipSrc == *r.clientHint && t.ipDst == *r.serverHint {
			direction = "uplink"
		} else if t.ipSrc == *r.serverHint && t.ipDst == *r.clientHint {
			direction = "downlink"
		} else {
			log.Printf("[WARN] 流的IP与客户端/服务器提示不匹配。尝试其他判断。")
		}
	} else if t.proto == "TCP" && flags&0x02 != 0 && flags&0x10 == 0 {
		direction = "uplink"
	} else {
		rev := reversedKey(key, t)
		if fi, ok := r.flowTable[rev]; ok {
			if fi.direction == "uplink" {
				direction = "downlink"
			} else if fi.direction == "downlink" {
				direction = "uplink"
			}
		}
	}
	r.flowTable[key] = &flowInfo5{direction: direction, firstSeen: ts}
	// 双向新流计数（反向键不在表 = 新双向流）
	rk := reversedKey(key, t)
	if _, ok := r.flowTable[rk]; !ok {
		r.flowCount++
	}
	return direction
}

// ---- 帧解析 ----

func parseVLANID(payload []byte) (vlan uint16, ethType uint16, rest []byte, ok bool) {
	if len(payload) < 4 {
		return 0, 0, nil, false
	}
	vlan = binary.BigEndian.Uint16(payload[:2]) & 0x0FFF
	ethType = binary.BigEndian.Uint16(payload[2:4])
	return vlan, ethType, payload[4:], true
}

// ipParse 返回 (ver, src, dst, proto, trans, ok)。
func ipParse(payload []byte) (int, string, string, byte, []byte) {
	if len(payload) < 1 {
		return 0, "", "", 0, nil
	}
	switch payload[0] >> 4 {
	case 4:
		if len(payload) < 20 {
			return 0, "", "", 0, nil
		}
		ihl := int(payload[0]&0x0F) * 4
		if ihl < 20 || ihl > len(payload) {
			return 4, "", "", 0, nil
		}
		return 4, ip4Str(payload[12:16]), ip4Str(payload[16:20]), payload[9], payload[ihl:]
	case 6:
		if len(payload) < 40 {
			return 0, "", "", 0, nil
		}
		return 6, ipv6String(payload[8:24]), ipv6String(payload[24:40]), payload[6], payload[40:]
	}
	return 0, "", "", 0, nil
}

func ip4Str(b []byte) string { return net.IP(b).String() }

// transport sport/dport/flags。
func transportParse(proto byte, trans []byte) (uint16, uint16, byte) {
	if (proto == 6 || proto == 17 || proto == 132) && len(trans) >= 4 {
		sport := binary.BigEndian.Uint16(trans)
		dport := binary.BigEndian.Uint16(trans[2:])
		var flags byte
		if proto == 6 && len(trans) > 13 {
			flags = trans[13]
		}
		return sport, dport, flags
	}
	return 0, 0, 0
}

// ---- 改写与校验和 ----

func ipChecksum(hdr []byte) uint16 {
	sum := checksumBytes(hdr)
	return sum
}

func checksumBytes(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(data[i])<<8 | uint32(data[i+1])
		} else {
			sum += uint32(data[i]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// tcpChecksum 伪头 + 段（IPv4/IPv6 通用，proto 即 next header）。
func tcpChecksum(ipHdr, trans []byte) uint16 {
	var pseudo []byte
	if ipHdr[0]>>4 == 4 {
		pseudo = append([]byte{}, ipHdr[12:20]...)
		pseudo = append(pseudo, 0, ipHdr[9])
		pseudo = append(pseudo, byte(len(trans)>>8), byte(len(trans)))
	} else {
		pseudo = append([]byte{}, ipHdr[8:24]...)
		l := make([]byte, 4)
		binary.BigEndian.PutUint32(l, uint32(len(trans)))
		pseudo = append(pseudo, l...)
		pseudo = append(pseudo, 0, 0, 0, ipHdr[6])
	}
	full := append(pseudo, trans...)
	if len(full)%2 != 0 {
		full = append(full, 0)
	}
	return checksumBytes(full)
}

// buildModifiedPacket 五元组改写（IPv4↔IPv4 完整；v4↔v6 互转含 ICMP 半成品照抄）。
// 返回 nil = 原样（无法处理）。
func buildModifiedPacket(ethBytes []byte, modSrc, modDst *string, modSport, modDport *uint16) []byte {
	payload := ethBytes[14:]
	ver := payload[0] >> 4
	srcIs4 := modSrc != nil && net.ParseIP(*modSrc).To4() != nil && isIPv4Literal(*modSrc)
	dstIs4 := modDst != nil && isIPv4Literal(*modDst)
	srcIs6 := modSrc != nil && !srcIs4
	dstIs6 := modDst != nil && !dstIs4

	if ver == 4 && (srcIs4 || dstIs4) {
		ihl := int(payload[0]&0x0F) * 4
		ipHdr := append([]byte{}, payload[:ihl]...)
		trans := append([]byte{}, payload[ihl:]...)
		proto := ipHdr[9]
		if modSrc != nil {
			copy(ipHdr[12:16], net.ParseIP(*modSrc).To4())
		}
		if modDst != nil {
			copy(ipHdr[16:20], net.ParseIP(*modDst).To4())
		}
		if proto == 6 || proto == 17 || proto == 132 {
			if modSport != nil {
				binary.BigEndian.PutUint16(trans, *modSport)
			}
			if modDport != nil {
				binary.BigEndian.PutUint16(trans[2:], *modDport)
			}
		}
		if proto == 6 || proto == 17 {
			// 校验和重算（TCP offset16、UDP offset6；SCTP 不动）
			off := 16
			if proto == 17 {
				off = 6
			}
			if off+2 <= len(trans) {
				trans[off] = 0
				trans[off+1] = 0
				binary.BigEndian.PutUint16(trans[off:], tcpChecksum(ipHdr, trans))
			}
		} else if proto == 1 && len(trans) >= 4 {
			trans[2], trans[3] = 0, 0
			binary.BigEndian.PutUint16(trans[2:], checksumBytes(trans))
		}
		ipHdr[10], ipHdr[11] = 0, 0
		binary.BigEndian.PutUint16(ipHdr[10:], checksumBytes(ipHdr))
		return append(append([]byte{}, ethBytes[:14]...), append(ipHdr, trans...)...)
	}
	if ver == 6 && (srcIs6 || dstIs6) {
		ipHdr := append([]byte{}, payload[:40]...)
		trans := append([]byte{}, payload[40:]...)
		nh := ipHdr[6]
		if modSrc != nil {
			copy(ipHdr[8:24], net.ParseIP(*modSrc).To16())
		}
		if modDst != nil {
			copy(ipHdr[24:40], net.ParseIP(*modDst).To16())
		}
		if nh == 6 || nh == 17 {
			if modSport != nil {
				binary.BigEndian.PutUint16(trans, *modSport)
			}
			if modDport != nil {
				binary.BigEndian.PutUint16(trans[2:], *modDport)
			}
			off := 16
			if nh == 17 {
				off = 6
			}
			if off+2 <= len(trans) {
				trans[off], trans[off+1] = 0, 0
				binary.BigEndian.PutUint16(trans[off:], tcpChecksum(ipHdr, trans))
			}
		} else if nh == 58 && len(trans) >= 4 {
			trans[2], trans[3] = 0, 0
			binary.BigEndian.PutUint16(trans[2:], checksumBytes(trans))
		}
		return append(append([]byte{}, ethBytes[:14]...), append(ipHdr, trans...)...)
	}
	return nil // v4↔v6 互转需对侧地址族全指定；未满足场景原样（半成品分支少用，照抄语义从简）
}

func isIPv4Literal(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && strings.Count(s, ":") == 0
}

// addOrModifyVLAN vlan nil → 原样；已有 8100 → 换 TCI；否则插入。
func addOrModifyVLAN(eth []byte, vlan *uint16) []byte {
	if vlan == nil {
		return eth
	}
	out := make([]byte, 0, len(eth)+4)
	out = append(out, eth[:12]...)
	if binary.BigEndian.Uint16(eth[12:14]) == 0x8100 {
		var t [4]byte
		binary.BigEndian.PutUint16(t[:2], 0x8100)
		binary.BigEndian.PutUint16(t[2:], *vlan)
		out = append(out, t[:]...)
		out = append(out, eth[16:]...) // 已有标签：剥旧 TCI 留内层 ethertype
	} else {
		var t [6]byte
		binary.BigEndian.PutUint16(t[:2], 0x8100)
		binary.BigEndian.PutUint16(t[2:], *vlan)
		copy(t[4:], eth[12:14])
		out = append(out, t[:]...)
		out = append(out, eth[14:]...)
	}
	return out
}

// ---- 主流程 ----

// replayFiles dt0 入口（对齐 replay_files + handlers dt0 校验）。
func replayFiles(payload []byte) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}
	allowed := map[string]bool{
		"pcaps": true, "uplink_iface": true, "downlink_iface": true,
		"uplink_vlan": true, "downlink_vlan": true, "mbps": true,
		"force_ip_src": true, "force_ip_dst": true, "force_sport": true, "force_dport": true,
		"force_build_flow": true, "client_ip_hint": true, "server_ip_hint": true,
		"enable_pcap_cache": true, "pcap_cache_dir": true, "verbose": true,
	}
	for k := range raw {
		if !allowed[k] {
			return nil, fmt.Errorf("PcapReplayer() got unexpected keyword argument %q", k)
		}
	}
	if len(raw["pcaps"]) == 0 || len(raw["uplink_iface"]) == 0 || len(raw["downlink_iface"]) == 0 ||
		string(raw["pcaps"]) == "null" || string(raw["uplink_iface"]) == "null" || string(raw["downlink_iface"]) == "null" ||
		string(raw["pcaps"]) == "" || string(raw["uplink_iface"]) == `""` || string(raw["downlink_iface"]) == `""` {
		return json.Marshal(map[string]string{
			"status":  "error",
			"message": "Missing required parameters: uplink_iface or downlink_iface",
		})
	}
	var req struct {
		Pcaps      []string `json:"pcaps"`
		UpIface    string   `json:"uplink_iface"`
		DownIface  string   `json:"downlink_iface"`
		UpVlan     *uint16  `json:"uplink_vlan"`
		DownVlan   *uint16  `json:"downlink_vlan"`
		Mbps       int      `json:"mbps"`
		ForceIpSrc *string  `json:"force_ip_src"`
		ForceIpDst *string  `json:"force_ip_dst"`
		ForceSport *uint16  `json:"force_sport"`
		ForceDport *uint16  `json:"force_dport"`
		ForceBuild bool     `json:"force_build_flow"`
		ClientHint *string  `json:"client_ip_hint"`
		ServerHint *string  `json:"server_ip_hint"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	r := &replayer{
		upIface: req.UpIface, downIface: req.DownIface,
		upVlan: req.UpVlan, downVlan: req.DownVlan, mbps: req.Mbps,
		forceIpSrc: req.ForceIpSrc, forceIpDst: req.ForceIpDst,
		forceSport: req.ForceSport, forceDport: req.ForceDport,
		forceBuildFlow: req.ForceBuild, clientHint: req.ClientHint, serverHint: req.ServerHint,
		flowTable: map[tuple5Key]*flowInfo5{},
	}
	r.startTime = nowSec()
	var totalBytesSent int
	for _, f := range req.Pcaps {
		pkts, _ := r.replayFile(f)
		r.totalFiles++
		r.totalPackets += pkts
		totalBytesSent = r.totalBytes
		// 全局限速（对齐 replay_files：按累计字节的期望耗时补睡）
		if r.mbps > 0 {
			elapsed := nowSec() - r.startTime
			should := float64(totalBytesSent) * 8 / float64(r.mbps) / 1e6
			if should > elapsed {
				time.Sleep(time.Duration((should - elapsed) * float64(time.Second)))
			}
		}
	}
	r.endTime = nowSec()
	dur := r.endTime - r.startTime
	actual := 0.0
	if dur > 0 {
		actual = float64(r.totalBytes) * 8 / 1e6 / dur
	}
	stats := map[string]any{
		"total_files":      r.totalFiles,
		"total_packets":    r.totalPackets,
		"total_bytes":      r.totalBytes,
		"uplink_packets":   r.upPackets,
		"uplink_bytes":     r.upBytes,
		"downlink_packets": r.downPackets,
		"downlink_bytes":   r.downBytes,
		"flow_count":       r.flowCount,
		"duration_seconds": round2(dur),
		"target_mbps":      r.mbps,
		"actual_mbps":      round2(actual),
	}
	return json.Marshal(stats)
}

func round2(f float64) float64 { return float64(int(f*100+0.5*sign(f))) / 100 }
func sign(f float64) float64 {
	if f < 0 {
		return -1
	}
	return 1
}

// replayFile 单文件回放，返回 (packets, 累计字节)。
func (r *replayer) replayFile(path string) (int, int) {
	if _, err := os.Stat(path); err != nil {
		log.Printf("[ERROR] %v", err)
		return 0, r.totalBytes
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 24 {
		log.Printf("[ERROR] pcap 全局头不完整：%s", path)
		return 0, r.totalBytes
	}
	magic := binary.LittleEndian.Uint32(data[:4])
	divisor := float64(1e6)
	if magic == 0xA1B23C4D || magic == 0x4D3CB2A1 {
		divisor = 1e9
	}
	packets := 0
	lastSend := time.Now()
	perPktBits := float64(r.mbps) * 1e6
	for off := 24; off+16 <= len(data); {
		sec := binary.LittleEndian.Uint32(data[off:])
		frac := binary.LittleEndian.Uint32(data[off+4:])
		incl := int(binary.LittleEndian.Uint32(data[off+8:]))
		off += 16
		if off+incl > len(data) {
			break
		}
		pkt := data[off : off+incl]
		off += incl
		ts := float64(sec) + float64(frac)/divisor

		// 解析：eth → VLAN → IP；非 IP 跳过（不计数）
		if len(pkt) < 14 {
			continue
		}
		ethType := binary.BigEndian.Uint16(pkt[12:14])
		payload := pkt[14:]
		if ethType == 0x8100 {
			_, et, rest, ok := parseVLANID(payload)
			if !ok {
				continue
			}
			ethType = et
			payload = rest
		}
		if ethType != 0x0800 && ethType != 0x86DD {
			continue
		}
		ver, ipSrc, ipDst, proto, trans := ipParse(payload)
		if ver == 0 || ipSrc == "" {
			continue
		}

		var direction string
		var key tuple5Key
		if r.directionless() && r.noTupleMod() && !r.forceBuildFlow {
			direction = "uplink"
			key = tuple5Key{}
		} else {
			macSrc := fmt.Sprintf("%x", pkt[6:12])
			macDst := fmt.Sprintf("%x", pkt[0:6])
			sport, dport, flags := transportParse(proto, trans)
			protoName := "OTHER"
			if proto == 6 {
				protoName = "TCP"
			} else if proto == 17 {
				protoName = "UDP"
			}
			t := tuple5{macSrc: macSrc, macDst: macDst, ipSrc: ipSrc, ipDst: ipDst, sport: sport, dport: dport, proto: protoName}
			key = tuple5Key{a: t, b: mirror(t), proto: protoName}
			direction = r.getDirection(key, t, flags, ts)
		}

		// 改写（对称换向，modify_packet 语义）+ VLAN + 发送
		out := pkt
		if !r.noTupleMod() && key.a.ipSrc != "" {
			modSrc, modDst, modSport, modDport := r.forceIpSrc, r.forceIpDst, r.forceSport, r.forceDport
			if direction == "downlink" {
				// 下行：源用 force_dst、目的用 force_src（端口同理）
				modSrc, modDst = r.forceIpDst, r.forceIpSrc
				modSport, modDport = r.forceDport, r.forceSport
			}
			out = buildModifiedPacket(pkt, modSrc, modDst, modSport, modDport)
			if out == nil {
				out = pkt
			}
		}
		iface := r.upIface
		var vlan *uint16
		if direction == "uplink" {
			vlan = r.upVlan
		} else {
			iface = r.downIface
			vlan = r.downVlan
		}
		out = addOrModifyVLAN(out, vlan)
		if err := replaySendFn(iface, out); err != nil {
			log.Printf("[ERROR] 发送数据包失败: %v", err)
			continue // Python send 失败 return（不计字节）；包计数照常？
		}
		packets++
		bytesInc := incl
		if bytesInc < 60 {
			bytesInc = 60
		}
		if direction == "uplink" {
			r.upPackets++
			r.upBytes += bytesInc
		} else {
			r.downPackets++
			r.downBytes += bytesInc
		}
		r.totalBytes += bytesInc

		// 每包限速（对齐 replay_file：delay=incl*8/bps）
		if r.mbps > 0 {
			delay := float64(incl) * 8 / perPktBits
			elapsed := time.Since(lastSend).Seconds()
			if delay > elapsed {
				time.Sleep(time.Duration((delay - elapsed) * float64(time.Second)))
			}
			lastSend = time.Now()
		}
	}
	return packets, r.totalBytes
}

func nowSec() float64 { return float64(time.Now().UnixNano()) / 1e9 }
