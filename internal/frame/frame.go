// Package frame 实现 :9000 TCP 帧协议的字节层（设计文档 §2）。
//
// 帧格式：[4B len LE int32][4B datatype LE int32][payload]，len = 4 + len(payload)。
// step23 裸帧例外：[4B len][content]，无 datatype。
// 仅字节层；连接级状态机（21-24）归 internal/agent。
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// errInvalidLen 覆盖负长度与 <4 的长度前缀（无法容纳 datatype）。
var errInvalidLen = errors.New("frame: invalid length prefix")

// Encode 编组完整帧 [4B len][4B datatype][payload]。
func Encode(datatype int32, payload []byte) []byte {
	body := make([]byte, 4, 4+len(payload))
	binary.LittleEndian.PutUint32(body, uint32(datatype))
	body = append(body, payload...)
	return EncodeRaw(body)
}

// EncodeRaw 编组裸帧 [4B len][content]（step23 文件内容、含 datatype 的完整 body 均走此格式）。
func EncodeRaw(content []byte) []byte {
	out := make([]byte, 4+len(content))
	binary.LittleEndian.PutUint32(out, uint32(len(content)))
	copy(out[4:], content)
	return out
}

// Read 读取完整帧并拆出 datatype 与 payload。长度前缀 <4 视为协议违规返回错误。
func Read(r io.Reader) (datatype int32, payload []byte, err error) {
	body, err := ReadRaw(r)
	if err != nil {
		return 0, nil, err
	}
	if len(body) < 4 {
		return 0, nil, fmt.Errorf("frame: body %d bytes too small for datatype: %w", len(body), errInvalidLen)
	}
	dt := int32(binary.LittleEndian.Uint32(body[:4]))
	return dt, body[4:], nil
}

// ReadRaw 读取裸帧 [4B len][content]，精确读满 len 字节。
func ReadRaw(r io.Reader) (content []byte, err error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := int32(binary.LittleEndian.Uint32(head[:]))
	if n < 0 {
		return nil, fmt.Errorf("frame: negative length %d: %w", n, errInvalidLen)
	}
	content = make([]byte, n)
	if _, err := io.ReadFull(r, content); err != nil {
		return nil, err
	}
	return content, nil
}
