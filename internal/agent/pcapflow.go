package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"os"
)

// pcapFlowExtract dt200 完整实现在 pcapflow 模块；本文件先落响应契约：
// payload 畸形 JSON → error（断连）；合法 → [4B i][JSON] 流列表（见设计 §3 dt200）。
func pcapFlowExtract(payload []byte) ([]byte, error) {
	var req struct {
		PcapDir string `json:"pcap_dir"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	flows := extractPcapFlowFiveTuples(req.PcapDir)
	return json.Marshal(flows)
}

// extractPcapFlowFiveTuples 完整实现（VLAN/IPv6/方向锁定/字符串字段/字典序流键）
// 由 dt200 专项测试驱动补齐（设计 §3 dt200）；当前占位返回空流列表。
func extractPcapFlowFiveTuples(dir string) []map[string]string {
	return []map[string]string{}
}

// writeFileSync 写盘（dt24）；`^$` 已在上层转空。O_TRUNC 对齐 Python open("wb")。
func writeFileSync(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

// downloadFile dt3：nil filepath = Python open(None) → 断连；读失败 → 断连。
// gzip=true 时内容压缩后发（长度为压缩后长度，§2）。
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
