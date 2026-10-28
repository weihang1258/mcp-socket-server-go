package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net"
	"time"
)

// Serve 在已监听的 listener 上接受连接（双栈由调用方建 listener），阻塞。
// 每连接一个 goroutine（对齐 Python daemon_threads）。
func Serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleConn(conn, Do)
	}
}

// handleConn 单连接收发循环，逐条实现设计 §2 的 8 条接收规则。
// 返回即断连（Python: break/异常 → finally: request.close()）。
func handleConn(conn net.Conn, do DoFunc) {
	clientConnected()
	defer clientDisconnected()
	defer conn.Close()

	cs := newConnState()
	readBuf := make([]byte, 64*1024)
	var acc []byte         // Python 的 datatotal
	var dataLen int32 = -1 // -1 = 等待帧头（Python 的 data_len==0 态）

	for {
		n, err := conn.Read(readBuf)
		if err != nil {
			return // EOF / ConnectionReset / 超时 → 断连
		}
		chunk := readBuf[:n]
		if dataLen == -1 {
			// 规则 2：帧头态收到 <4B → 断连（首包过短）
			if len(chunk) < 4 {
				log.Printf("首包过短: %d bytes", len(chunk))
				return
			}
			dataLen = int32(binary.LittleEndian.Uint32(chunk[:4]))
			acc = append(acc[:0], chunk[4:]...)
		} else {
			acc = append(acc, chunk...)
		}

		// Python 每收一段做一次三态判定（不做帧内 salvage，超收全弃——quirk 保真）
		if int32(len(acc)) < dataLen {
			continue // 规则 3a：未收满，继续
		}
		if int32(len(acc)) > dataLen {
			// 规则 3b：超收 → 丢弃全部累计（含嵌入的下一帧头），等新帧头
			log.Printf("收到了字节数大于发送字节数，收到%d,发送%d", len(acc), dataLen)
			acc = acc[:0]
			dataLen = -1
			continue
		}
		// 恰好收满一帧
		data := acc
		acc = make([]byte, 0, len(acc))
		dataLen = -1
		if !processFrame(conn, cs, data, do) {
			return
		}
	}
}

// processFrame 处理一个已收满的帧。返回 false = 断连。
func processFrame(conn net.Conn, cs *ConnState, data []byte, do DoFunc) bool {
	if !cs.bin {
		// 规则 4：帧体 <4B → 跳过该帧继续
		if len(data) < 4 {
			log.Printf("指令数据过短: %d bytes", len(data))
			return true
		}
		dt := int32(binary.LittleEndian.Uint32(data[:4]))
		payload := data[4:]

		// 21-24 文件传输状态机（协议层直答，不走 do 的响应重试——§2 规则 5）
		switch dt {
		case 21:
			return handleDT21(conn, cs, payload)
		case 22:
			return handleDT22(conn, cs, payload)
		case 24:
			return handleDT24(conn, cs)
		}
		// dt3/其余业务类型走 do；bin 模式专用的 dt23 不会到这（见下方 bin 分支）
		resp, err := do(cs, dt, payload)
		if err != nil {
			log.Printf("错误：%v", err)
			return false // 规则 7：do() 异常 → 断连无响应
		}
		if resp != nil {
			sendWithRetry(conn, resp) // 规则 5：业务响应 sleep 3s 重发一次
		}
		return true // 规则 6：nil 响应静默继续
	}

	// bin 模式（dt22 之后）：帧体即文件内容，datatype 恒视作 23
	cs.content = append(cs.content, data...)
	if uint64(len(cs.content)) == cs.length {
		cs.bin = false
		return sendDirect(conn, []byte("23 ok"))
	}
	if uint64(len(cs.content)) > cs.length {
		// Python: RuntimeError（bufsize/bin 复位后断连）——复位对断连无观察差异，直接断
		log.Printf("接收字节数大于原始文件字节数：接收%d，原始%d", len(cs.content), cs.length)
		return false
	}
	return true // 未收满，继续
}

// handleDT21 文件名上传。两失败分支（§2）：
// 畸形 JSON → 立即断连；缺 filepath → 存 None，回 21 ok，dt24/dt3 时断连。
func handleDT21(conn net.Conn, cs *ConnState, payload []byte) bool {
	var fileinfo struct {
		Filepath *string `json:"filepath"`
		Gzip     bool    `json:"gzip"`
	}
	if err := json.Unmarshal(payload, &fileinfo); err != nil {
		log.Printf("文件名上传 JSON 解析失败: %v", err)
		return false
	}
	cs.filepath = fileinfo.Filepath
	cs.gzip = fileinfo.Gzip
	cs.gzipSet = true
	return sendDirect(conn, []byte("21 ok"))
}

// handleDT22 文件长度。三态：<8B 跳过 / >8B struct.error 断连 / 恰 8B 进 bin 模式。
func handleDT22(conn net.Conn, cs *ConnState, payload []byte) bool {
	if len(payload) < 8 {
		log.Printf("文件长度数据过短: %d bytes", len(payload))
		return true
	}
	if len(payload) > 8 {
		log.Printf("dt22 payload %d bytes, struct.error 需恰 8B", len(payload))
		return false
	}
	cs.length = binary.LittleEndian.Uint64(payload[:8])
	cs.content = cs.content[:0]
	cs.bin = true
	return sendDirect(conn, []byte("22 ok"))
}

// handleDT24 写文件。quirk 链：无前置 dt21（gzipSet=false）→ AttributeError 断连；
// filepath=None → open(None) 断连；解压失败/写盘失败 → 断连。`^$` 特例写空文件。
func handleDT24(conn net.Conn, cs *ConnState) bool {
	if !cs.gzipSet {
		log.Printf("dt24 无前置 dt21（self.gzip 未初始化）")
		return false
	}
	if cs.filepath == nil {
		log.Printf("dt24 filepath 为 None（dt21 未提供 filepath）")
		return false
	}
	content := cs.content
	if cs.gzip {
		zr, err := gzip.NewReader(bytes.NewReader(content))
		if err != nil {
			log.Printf("gzip 解压失败: %v", err)
			return false
		}
		content, err = io.ReadAll(zr)
		if err != nil {
			log.Printf("gzip 解压失败: %v", err)
			return false
		}
	}
	if bytes.Equal(content, []byte("^$")) {
		content = nil
	}
	if err := writeFileSync(*cs.filepath, content); err != nil {
		log.Printf("写文件失败 %s: %v", *cs.filepath, err)
		return false
	}
	cs.content = cs.content[:0]
	return sendDirect(conn, []byte("24 ok"))
}

// sendDirect 直发（21-24 握手应答，无重试）。写失败 = 连接已坏，断连。
func sendDirect(conn net.Conn, resp []byte) bool {
	if _, err := conn.Write(resp); err != nil {
		return false
	}
	return true
}

// sendWithRetry 业务响应发送：失败 sleep 3s 重发一次（§2 规则 5）。
func sendWithRetry(conn net.Conn, resp []byte) {
	if _, err := conn.Write(resp); err != nil {
		log.Printf("发送错误：%v", err)
		log.Printf("等待3秒，重新发送")
		time.Sleep(3 * time.Second)
		if _, err := conn.Write(resp); err != nil {
			log.Printf("重试发送也失败：%v", err)
		}
	}
}
