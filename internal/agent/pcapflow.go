package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// pcapFlowExtract dt200 响应契约：payload 畸形 JSON → error（断连）；
// 正常 → [4B i][JSON 流列表]（Python struct.pack("i", len(res)) + res）。
func pcapFlowExtract(payload []byte) ([]byte, error) {
	var req struct {
		PcapDir string `json:"pcap_dir"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	flows := extractPcapFlowFiveTuples(req.PcapDir)
	body, err := json.Marshal(flows)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out, nil
}

// httpMethodKeys dt200 方向识别用 HTTP 方法关键字（pcap_flow.py 同序）。
var httpMethodKeys = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "), []byte("TRACE "),
}

type tuple2 struct{ ip, port string }

type pcapFlow struct {
	firstSrc, firstDst, client tuple2
	finalized                  bool
	protoType                  string // "1"TCP "2"UDP "3"SCTP "4"ICMP
}

// extractPcapFlowFiveTuples 移植 pcap_flow.py：目录递归 *.pcap，纯 struct 解析，
// 双向流分组 + 方向一次锁定（首包默认 → SYN/SYN+ACK → HTTP 方法/响应行）。
// 输出字段全为字符串；流键 = (ip, port字符串) 元组字典序（"10"<"9" 照抄）；
// 单层 VLAN；IPv4 不验总长/分片；IPv6 固定 offset 6 不走扩展头；坏文件跳过。
func extractPcapFlowFiveTuples(pcapDir string) []map[string]string {
	results := []map[string]string{}
	var pcaps []string
	if fi, err := os.Stat(pcapDir); err != nil || !fi.IsDir() {
		return results
	}
	filepath.Walk(pcapDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(p, ".pcap") {
			pcaps = append(pcaps, p)
		}
		return nil
	})

	for _, pcapPath := range pcaps {
		pcapName := filepath.Base(pcapPath)
		flows := map[string]*pcapFlow{}
		func() {
			f, err := os.Open(pcapPath)
			if err != nil {
				log.Printf("extract_pcap_flow_five_tuples 解析 %s 失败: %v", pcapPath, err)
				return
			}
			defer f.Close()
			g := make([]byte, 24)
			if _, err := io.ReadFull(f, g); err != nil {
				return // 全局头不完整
			}
			hdr := make([]byte, 16)
			for {
				if _, err := io.ReadFull(f, hdr); err != nil {
					break // 记录头不完整 → 停止该文件
				}
				inclLen := binary.LittleEndian.Uint32(hdr[8:])
				pkt := make([]byte, inclLen)
				if _, err := io.ReadFull(f, pkt); err != nil {
					break // 记录体截断 → 停止（保留已解析流）
				}
				parsePacket(pkt, flows)
			}
		}()
		for _, flow := range flows {
			src, dst := flow.firstSrc, flow.firstDst
			if flow.client != flow.firstSrc {
				src, dst = flow.firstDst, flow.firstSrc
			}
			results = append(results, map[string]string{
				"pcap":      pcapName,
				"srcIp":     src.ip,
				"srcPort":   src.port,
				"destIp":    dst.ip,
				"destPort":  dst.port,
				"protoType": flow.protoType,
			})
		}
	}
	return results
}

// parsePacket 单包解析（逐条对齐 pcap_flow.py 内循环）。
func parsePacket(pkt []byte, flows map[string]*pcapFlow) {
	if len(pkt) < 14 {
		return
	}
	ethType := binary.BigEndian.Uint16(pkt[12:14])
	payload := pkt[14:]
	if ethType == 0x8100 { // 单层 VLAN
		if len(payload) < 4 {
			return
		}
		ethType = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}
	var proto byte
	var srcIP, dstIP string
	var trans []byte
	switch {
	case ethType == 0x0800:
		if len(payload) < 20 {
			return
		}
		ihl := int(payload[0]&0x0F) * 4
		proto = payload[9]
		srcIP = ipv4String(payload[12:16])
		dstIP = ipv4String(payload[16:20])
		trans = payload[ihl:]
	case ethType == 0x86DD:
		if len(payload) < 40 {
			return
		}
		proto = payload[6] // 固定 offset 6，不走扩展头（quirk）
		srcIP = ipv6String(payload[8:24])
		dstIP = ipv6String(payload[24:40])
		trans = payload[40:]
	default:
		return
	}

	var protoType string
	switch proto {
	case 6:
		protoType = "1"
	case 17:
		protoType = "2"
	case 132:
		protoType = "3"
	case 1, 58:
		protoType = "4"
	default:
		return
	}

	var src, dst tuple2
	flags := byte(0)
	if protoType == "1" || protoType == "2" || protoType == "3" {
		if len(trans) < 4 {
			return
		}
		sport := binary.BigEndian.Uint16(trans[:2])
		dport := binary.BigEndian.Uint16(trans[2:4])
		src, dst = tuple2{srcIP, itoa(sport)}, tuple2{dstIP, itoa(dport)}
		if proto == 6 && len(trans) > 13 {
			flags = trans[13]
		}
	} else { // ICMP：端口 "0"
		src, dst = tuple2{srcIP, "0"}, tuple2{dstIP, "0"}
	}

	// 流键：元组字典序（string 比较，"10"<"9"）+ protoType
	a, b := src, dst
	if tupleLess(b, a) {
		a, b = b, a
	}
	key := a.ip + "\x00" + a.port + "\x00" + b.ip + "\x00" + b.port + "\x00" + protoType
	flow := flows[key]
	if flow == nil {
		flow = &pcapFlow{firstSrc: src, firstDst: dst, client: src, protoType: protoType}
		flows[key] = flow
	}
	if flow.finalized {
		return
	}
	// 方向信号：SYN → 发起方；SYN+ACK → 接收方；HTTP 方法 → 请求方；HTTP/1. → 响应接收方
	var signaled tuple2
	has := false
	if proto == 6 {
		syn, ack := flags&0x02 != 0, flags&0x10 != 0
		if syn && !ack {
			signaled, has = src, true
		} else if syn && ack {
			signaled, has = dst, true
		}
		if !has && len(trans) >= 14 {
			dataOffset := int(trans[12]>>4) * 4
			var hp []byte
			if dataOffset <= len(trans) {
				hp = trans[dataOffset:]
			}
			if hasHTTPMethodPrefix(hp) {
				signaled, has = src, true
			} else if bytes.HasPrefix(hp, []byte("HTTP/1.")) {
				signaled, has = dst, true
			}
		}
	}
	if has {
		flow.client = signaled
		flow.finalized = true
	}
}

func tupleLess(a, b tuple2) bool {
	if a.ip != b.ip {
		return a.ip < b.ip
	}
	return a.port < b.port
}

func hasHTTPMethodPrefix(p []byte) bool {
	for _, m := range httpMethodKeys {
		if bytes.HasPrefix(p, m) {
			return true
		}
	}
	return false
}

func ipv4String(b []byte) string { // inet_ntoa
	return net.IP(b).String()
}

func ipv6String(b []byte) string { // inet_ntop AF_INET6
	ip := net.IP(make([]byte, 16))
	copy(ip, b)
	return ip.String()
}

func itoa(u uint16) string { return strconv.FormatUint(uint64(u), 10) }

// writeFileSync 写盘（dt24）；`^$` 已在上层转空。O_TRUNC 对齐 Python open("wb")。
func writeFileSync(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

// downloadFile dt3：nil filepath = Python open(None) → 断连；读失败 → 断连。
// gzip=true 时内容压缩后发（长度前缀为压缩后长度，§2）。
func downloadFile(cs *ConnState, payload []byte) ([]byte, error) {
	var req struct {
		Gzip bool `json:"gzip"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	fp := cs.Filepath()
	if fp == nil {
		return nil, errNilFilepath
	}
	content, err := os.ReadFile(*fp)
	if err != nil {
		return nil, err
	}
	if req.Gzip {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(content); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		content = buf.Bytes()
	}
	out := make([]byte, 8+len(content))
	binary.LittleEndian.PutUint64(out, uint64(len(content)))
	copy(out[8:], content)
	return out, nil
}
