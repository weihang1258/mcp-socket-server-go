package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/weihang1258/mcp-socket-server-go/internal/frame"
)

// dt16 python_cmd：验收客户端 device/socket_linux.py:python_cmd 用它跑
// os.popen('cd <dir>;find ...').read() 列目录（download_pcap 下载目录时走这条路）。
// Go 版曾按设计文档「dt16 不复刻」直接返回 nil —— 不回任何字节，客户端永久阻塞，
// 现场表现为 pcapdump 下载卡住、服务端日志空白（2026-11-02 客户端实测 8s+ 无响应）。
// 契约（netutils.py:253 + handlers.py:370）：*args 依次 eval，结果 json.dumps
// → gzip → [4B i][gzip]，且必须单次 sendall 完整帧（客户端 recv 循环有缺陷）。

// pyFrame 解开 [4B i][gzip JSON]。
func pyFrame(t *testing.T, resp []byte) any {
	t.Helper()
	if len(resp) < 4 {
		t.Fatalf("响应过短: %d 字节", len(resp))
	}
	n := int(int32(binary.LittleEndian.Uint32(resp[:4])))
	if n <= 0 || len(resp) < 4+n {
		t.Fatalf("长度前缀 %d 与实际 %d 不符", n, len(resp)-4)
	}
	zr, err := gzip.NewReader(bytes.NewReader(resp[4 : 4+n]))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	var v any
	if err := json.Unmarshal(plain, &v); err != nil {
		t.Fatalf("JSON %q: %v", plain, err)
	}
	return v
}

// 客户端 listdir 的真实形态：os.popen('cd DIR;find ./ ...').read()
func TestDT16ListdirLikeClient(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/a.pcap", "A")
	writeFile(t, dir+"/b.pcap", "B")
	writeFile(t, dir+"/skip.txt", "X")

	addr := startTestAgent(t)
	payload, _ := json.Marshal([]string{
		"os.popen('cd " + dir + ";find ./ -maxdepth 1 -name \"*.pcap\"|sort -V')", "read()",
	})
	got := pyFrame(t, roundTrip(t, addr, 16, payload))
	s, _ := got.(string)
	lines := strings.Fields(s)
	if len(lines) != 2 || lines[0] != "./a.pcap" || lines[1] != "./b.pcap" {
		t.Fatalf("列目录结果不对: %q", s)
	}
}

// 非 os.popen 的任意 Python 表达式（原版 eval 能算）必须变成 error JSON，
// 但绝不能像旧版那样不回字节——客户端会永久阻塞。
func TestDT16EvalExpressionRejected(t *testing.T) {
	addr := startTestAgent(t)
	got := pyFrame(t, roundTrip(t, addr, 16, []byte(`["1+1"]`)))
	m, ok := got.(map[string]any)
	if !ok || m["error"] == nil {
		t.Fatalf("任意表达式应回 error JSON（不执行 eval），实际 %v", got)
	}
}

// 支持 os.popen(...).read() 前导的 strip()/readlines() 等链式取用
func TestDT16ChainCall(t *testing.T) {
	addr := startTestAgent(t)
	payload, _ := json.Marshal([]string{`os.popen('printf "x\ny\n"')`, `read().strip()`})
	got := pyFrame(t, roundTrip(t, addr, 16, payload))
	if got != "x\ny" {
		t.Fatalf("链式调用结果: %v", got)
	}
}

// 非白名单表达式必须变成错误 JSON（不阻塞、不执行任意代码）
func TestDT16RejectsUnknownExpression(t *testing.T) {
	addr := startTestAgent(t)
	got := pyFrame(t, roundTrip(t, addr, 16, []byte(`["__import__('os').system('true')"]`)))
	m, ok := got.(map[string]any)
	if !ok || m["error"] == nil {
		t.Fatalf("未知表达式应回 error JSON，实际 %v", got)
	}
}

// 响应必须是一次完整帧：客户端先 recv 一次拿 4B 长度再续收，
// 若分两次写会被判「接收字节数大于原始文件字节数」。
func TestDT16SingleWrite(t *testing.T) {
	dir := t.TempDir()
	var listing strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&listing, "./file-%03d.pcap\n", i)
	}
	writeFile(t, dir+"/listing.txt", listing.String())
	addr := startTestAgent(t)
	payload, _ := json.Marshal([]string{"os.popen('cat " + dir + "/listing.txt')", "read()"})
	c := dial(t, addr)
	if _, err := c.Write(frame.Encode(16, payload)); err != nil {
		t.Fatal(err)
	}
	first := recvDeadline(t, c, 3*time.Second)
	if len(first) < 4 {
		t.Fatalf("首发应含长度前缀，实际 %d 字节", len(first))
	}
	total := 4 + int(int32(binary.LittleEndian.Uint32(first[:4])))
	if total <= len(first) {
		return // 内核一次交付完整帧，最理想
	}
	// 首包被 TCP 分段时，续收的字节必须是同一帧的剩余部分（而不是错误帧）
	rest := make([]byte, total-len(first))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatalf("续收失败（客户端会卡住）: %v", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
