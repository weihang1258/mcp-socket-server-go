package agent

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/weihang1258/mcp-socket-server-go/internal/frame"
)

// Python 原版 protocol.py/handlers.py 在每个 datatype 入口都打一行日志，
// pcapdump 下载卡住时现场靠它判断客户端最后发了哪一帧。Go 版此前成功路径
// 全程静默，脚本卡住时服务端日志完全看不出请求到没到——2026-11-02 客户端
// 验收 #22 指出。本测试锁定 Python 原文案（JSON 用 Python repr 单引号风格）。

// captureLog 把标准日志改写到 buffer，测试结束还原。
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	oldOut := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
	})
	return &buf
}

// roundTrip 发一帧并读走响应（读超时视为无响应，交给断言）。
func roundTrip(t *testing.T, addr string, dt int, payload []byte) []byte {
	t.Helper()
	c := dial(t, addr)
	if _, err := c.Write(frame.Encode(int32(dt), payload)); err != nil {
		t.Fatalf("write dt%d: %v", dt, err)
	}
	return recvDeadline(t, c, 2*time.Second)
}

// payload 日志用 Python repr（单引号、True/False、空格分隔），便于现场与
// Python 版日志逐字对照。
func TestPyReprPayload(t *testing.T) {
	got := pyReprPayload([]byte(`{"filepath":"/dev/shm/a.pcap","gzip":true}`))
	want := `{'filepath': '/dev/shm/a.pcap', 'gzip': True}`
	if got != want {
		t.Fatalf("payload repr\n got=%s\nwant=%s", got, want)
	}
}

// 帧接收日志：Python protocol.py:43/45/51/54。
func TestFrameRecvLogsMatchPython(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(file, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := startTestAgent(t)
	buf := captureLog(t)
	roundTrip(t, addr, 21, []byte(`{"filepath":"`+file+`","gzip":false}`))
	out := buf.String()

	for _, want := range []string{
		"指定接收有效字节数：",
		"本条接收长度",
		"接收总长度",
		"文件名上传:21 ",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺少日志 %q；实际日志:\n%s", want, out)
		}
	}
}

// dt3 下载日志：Python handlers.py:135。
func TestDT3DownloadLogsMatchPython(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "m.pcap")
	if err := os.WriteFile(file, []byte("PCAPDATA"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := startTestAgent(t)
	buf := captureLog(t)
	c := dial(t, addr)
	if _, err := c.Write(frame.Encode(21, []byte(`{"filepath":"`+file+`","gzip":false}`))); err != nil {
		t.Fatal(err)
	}
	recvDeadline(t, c, time.Second) // 21 ok
	if _, err := c.Write(frame.Encode(3, []byte(`{"gzip":false}`))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // 等 handler 打完日志
	out := buf.String()
	if !strings.Contains(out, "文件传输：下载文件，类型：3，文件路径："+file) {
		t.Fatalf("缺少 dt3 下载日志；实际:\n%s", out)
	}
	// Python protocol.py:122 response(N)：<前100字节hex>
	if !regexp.MustCompile(`response\(\d+\)：`).MatchString(out) {
		t.Fatalf("缺少 response(N) 日志；实际:\n%s", out)
	}
}

// dt200 五元组提取日志：handlers.py:440/442。
func TestDT200LogsMatchPython(t *testing.T) {
	dir := t.TempDir()
	addr := startTestAgent(t)
	buf := captureLog(t)
	roundTrip(t, addr, 200, []byte(`{"pcap_dir":"`+dir+`"}`))
	out := buf.String()
	for _, want := range []string{"提取pcap五元组流，类型：200，参数：", "提取完成，共 0 条流"} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺少日志 %q；实际:\n%s", want, out)
		}
	}
}

// 只读探针（isfile/isdir）也要有日志——验收脚本下载前常用它们判断。
func TestProbeLogsMatchPython(t *testing.T) {
	addr := startTestAgent(t)
	buf := captureLog(t)
	roundTrip(t, addr, 7, []byte(`{"file":"/nope"}`))
	roundTrip(t, addr, 8, []byte(`{"dir":"/nope"}`))
	out := buf.String()
	for _, want := range []string{"是否文件，类型：7，参数：", "是否目录，类型：8，参数："} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺少日志 %q；实际:\n%s", want, out)
		}
	}
}
