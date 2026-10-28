package agent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 每个用例独占全局 ss 状态：跑完强制复位
func resetListen(t *testing.T) {
	t.Helper()
	stopListenForTest()
	socketbinDirForTest(t.TempDir())
	t.Cleanup(func() { stopListenForTest() })
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func dtListen(t *testing.T, action string, port int, file string) []byte {
	t.Helper()
	if port == 0 {
		port = 30001
	}
	var resp []byte
	var err error
	if action == "save" {
		resp, err = runDT(t, 173, mustJSON(t, map[string]string{"file": file}))
	} else {
		resp, err = runDT(t, 171, mustJSON(t, map[string]any{"host": nil, "port": port}))
		if action != "start" {
			t.Fatal("use specific helpers for other actions")
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func listenStartT(t *testing.T, port int) map[string]any {
	t.Helper()
	resp, err := runDT(t, 171, mustJSON(t, map[string]any{"host": "127.0.0.1", "port": port}))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("dt171 resp: %v (%q)", err, resp)
	}
	return m
}

func listenSend(t *testing.T, port int, data []byte) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		c.Write(data)
		c.Close()
		return
	}
	t.Fatal("cannot connect to listen port")
}

func listenFetchT(t *testing.T) ([]byte, error) {
	t.Helper()
	resp, err := runDT(t, 174, nil)
	if err != nil {
		return nil, err
	}
	if len(resp) < 8 {
		return nil, fmt.Errorf("unexpected: %q", resp)
	}
	n := binary.LittleEndian.Uint64(resp[:8])
	zr, _ := gzip.NewReader(bytes.NewReader(resp[8 : 8+n]))
	return io.ReadAll(zr)
}

// dt171+dt174：启动监听收流 → fetch 全量（gzip 解包）
func TestListenStartFetch(t *testing.T) {
	resetListen(t)
	port := freePort(t)
	m := listenStartT(t, port)
	if _, ok := m["pid"]; !ok {
		t.Fatalf("dt171 must return pid list: %v", m)
	}
	listenSend(t, port, []byte("stream-data-1"))
	time.Sleep(300 * time.Millisecond)
	data, err := listenFetchT(t)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "stream-data-1" {
		t.Fatalf("fetched: %q", data)
	}
	// 幂等：再 start 不报错仍回 pid 列表
	m2 := listenStartT(t, port)
	if _, ok := m2["pid"]; !ok {
		t.Fatalf("idempotent start: %v", m2)
	}
}

// dt172 清数据：fetch 变空 + socketbin 目录被清
func TestListenClean(t *testing.T) {
	resetListen(t)
	port := freePort(t)
	listenStartT(t, port)
	listenSend(t, port, []byte("to-be-cleaned"))
	time.Sleep(300 * time.Millisecond)
	if resp, err := runDT(t, 172, nil); err != nil || string(resp) != "ok" {
		t.Fatalf("dt172 want ok: %q %v", resp, err)
	}
	data, err := listenFetchT(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("after clean want empty, got %q", data)
	}
}

// dt172 未启动监听 → 裸 b"error"
func TestListenCleanNotStarted(t *testing.T) {
	resetListen(t)
	resp, err := runDT(t, 172, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != "error" {
		t.Fatalf("want bare error, got %q", resp)
	}
}

// dt173 保存：已收数据写盘；未启动 → b"error"；缺 file 键 → 断连
func TestListenSave(t *testing.T) {
	resetListen(t)
	port := freePort(t)
	listenStartT(t, port)
	listenSend(t, port, []byte("save-me"))
	time.Sleep(300 * time.Millisecond)

	dst := filepath.Join(t.TempDir(), "saved.bin")
	resp, err := runDT(t, 173, mustJSON(t, map[string]string{"file": dst}))
	if err != nil || string(resp) != "ok" {
		t.Fatalf("dt173: %q %v", resp, err)
	}
	data, _ := os.ReadFile(dst)
	if string(data) != "save-me" {
		t.Fatalf("saved: %q", data)
	}
	// 停止后 save → error
	stopListenForTest()
	resp, err = runDT(t, 173, mustJSON(t, map[string]string{"file": dst}))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != "error" {
		t.Fatalf("save after stop want error, got %q", resp)
	}
	// 缺 file 键 → 断连
	resetListen(t)
	listenStartT(t, freePort(t))
	if _, err := runDT(t, 173, []byte(`{"nofield":1}`)); err == nil {
		t.Fatal("missing file key must disconnect")
	}
}

// dt174 未启动 → {"error":"未启动监听"} JSON（裸文本无前缀）
func TestListenFetchNotStarted(t *testing.T) {
	resetListen(t)
	resp, err := runDT(t, 174, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp), "未启动监听") {
		t.Fatalf("want error JSON, got %q", resp)
	}
}

// dt175 停止：ok；后再 fetch → 未启动错误；再 start 可重建
func TestListenStop(t *testing.T) {
	resetListen(t)
	port := freePort(t)
	listenStartT(t, port)
	listenSend(t, port, []byte("x"))
	time.Sleep(200 * time.Millisecond)

	resp, err := runDT(t, 175, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != "ok" {
		t.Fatalf("dt175 want ok, got %q", resp)
	}
	// 端口应已释放
	if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
		c.Close()
		t.Fatal("port still accepting after stop")
	}
	// dt175 未启动 → error JSON
	resp, err = runDT(t, 175, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp), "未启动监听") {
		t.Fatalf("second stop want error JSON, got %q", resp)
	}
	// 重建
	m := listenStartT(t, port)
	if _, ok := m["pid"]; !ok {
		t.Fatalf("restart failed: %v", m)
	}
}

// dt175 端口残留清扫：stop 后 fake pid 仍报占用 → 3 轮轮询后回失败 JSON
func TestListenStopPortOccupiedFails(t *testing.T) {
	resetListen(t)
	port := freePort(t)
	listenStartT(t, port)
	setFakePids("12345") // 停止后仍"占用"
	defer setFakePids("")
	resp, err := runDT(t, 175, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp), "停止监听失败") {
		t.Fatalf("want occupied-failure JSON, got %q", resp)
	}
	// quirk：失败也清 ss → 再 fetch 是"未启动"
	resp, err = runDT(t, 174, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp), "未启动监听") {
		t.Fatalf("ss must be cleared even on failed stop, got %q", resp)
	}
}

// pid 列表解析：fake ss 输出多个 pid
func TestListenPidParsing(t *testing.T) {
	resetListen(t)
	setFakePids("111 222")
	defer setFakePids("")
	port := freePort(t)
	m := listenStartT(t, port)
	pids, ok := m["pid"].([]any)
	if !ok || len(pids) != 2 || pids[0] != "111" || pids[1] != "222" {
		t.Fatalf("pid parse wrong: %v", m)
	}
}

// socketbin 落盘：空闲 1s 后整块落 <epoch_us>.bin
func TestListenSocketbinFlush(t *testing.T) {
	resetListen(t)
	port := freePort(t)
	listenStartT(t, port)
	listenSend(t, port, []byte("flush-me"))
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		entries, _ := os.ReadDir(socketbinDir())
		if len(entries) > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("socketbin flush never happened")
}
