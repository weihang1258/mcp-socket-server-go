package agent

// 端到端：桥（Client）真的把 timeout_s 发到 agent，agent 到点杀进程组并回
// 结构化超时；壳进程（真正干活的 sh/sleep）必须消失。方案 §10 步骤 2 的
// 单机版验收（真机版见 e2e_live_test.go）。

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/weihang1258/mcp-socket-server-go/internal/frame"
)

func TestWireTimeoutStopsProcess(t *testing.T) {
	addr := startTestAgent(t)
	c := dial(t, addr)
	defer c.Close()

	payload := mustJSON(t, map[string]any{"args": "sleep 999", "timeout_s": 1})
	if _, err := c.Write(frame.Encode(1, payload)); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatalf("读回执: %v", err)
	}
	n := int(binary.LittleEndian.Uint32(head))
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatalf("读回执体: %v", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	plain, _ := io.ReadAll(zr)
	var m map[string]any
	if err := json.Unmarshal(plain, &m); err != nil {
		t.Fatalf("json: %v (body=%s)", err, plain)
	}
	if m["timeout"] != true || m["killed"] != true {
		t.Fatalf("回执缺少 timeout/killed: %v", m)
	}
	if m["verified"] != true {
		t.Fatalf("verified=false：进程组还有活口: %v", m)
	}
	// 独立复核：回执里那个进程组必须真的没了。只查该 pgid——
	// 扫全机的 "sleep 999" 会被别的进程/上一次中断的测试影响，误报过。
	pgidF, _ := m["pgid"].(float64)
	if pgidF <= 0 {
		t.Fatalf("回执缺少 pgid: %v", m)
	}
	pgid := int(pgidF)
	for i := 0; i < 20; i++ {
		if pids := pidsInGroup(pgid); len(pids) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("超时后进程组 %d 仍有活口: %v", pgid, pidsInGroup(pgid))
}

// pidsInGroup 列出进程组内的存活进程（忽略僵尸）。
func pidsInGroup(pgid int) []string {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	want := strconv.Itoa(pgid)
	var hit []string
	for _, e := range ents {
		if !e.IsDir() || e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		r := strings.LastIndex(s, ")")
		if r < 0 {
			continue
		}
		f := strings.Fields(s[r+1:])
		if len(f) < 3 || f[0] == "Z" || f[0] == "X" {
			continue
		}
		if f[2] == want {
			hit = append(hit, e.Name())
		}
	}
	return hit
}
