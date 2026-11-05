package agent

// §6.2 超时真停验收：timeout_s 到点必须留下"进程组已消失"的证据，
// 而不是只断连接。真机也用它跑 sleep 999（方案 §10 步骤 2）。

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func decodeGzipFrame(t *testing.T, resp []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(unwrapGzipResp(t, resp), &m); err != nil {
		t.Fatalf("json: %v", err)
	}
	return m
}

func TestCmdExecTimeoutKillsGroup(t *testing.T) {
	oldS, oldMs := secondNs.Load(), timeMillisecondNs.Load()
	secondNs.Store(int64(50 * time.Millisecond)) // 优雅期 0.1 秒
	timeMillisecondNs.Store(int64(10 * time.Millisecond))
	defer func() { secondNs.Store(oldS); timeMillisecondNs.Store(oldMs) }()

	out, err := cmdExec(mustJSON(t, map[string]any{
		"args":      "sleep 999 & echo $!; wait",
		"timeout_s": 1,
	}))
	if err != nil {
		t.Fatalf("cmdExec: %v", err)
	}
	m := decodeGzipFrame(t, out)
	if m["timeout"] != true {
		t.Fatalf("缺 timeout 标记: %v", m)
	}
	if m["killed"] != true {
		t.Fatalf("killed=false: %v", m)
	}
	if m["verified"] != true {
		t.Fatalf("verified=false（进程组还有活口）: %v", m)
	}
	// 回执里报的 pgid 必须真的不存在了（不是只看自己的判断）
	if pgid, _ := m["pgid"].(float64); pgid > 0 {
		if _, err := os.Stat("/proc/" + strconv.Itoa(int(pgid))); err == nil {
			t.Fatalf("pgid %v 仍在 /proc 中", pgid)
		}
	}
	if !strings.Contains(m["stderr"].(string), "超时") {
		t.Fatalf("stderr 未写明超时: %v", m["stderr"])
	}
}

func TestCmdExecNoTimeoutCompatible(t *testing.T) {
	// 不传 timeout_s = 旧行为：跑完就返回，不打 timeout 标记
	out, err := cmdExec(mustJSON(t, map[string]any{"args": "echo hi"}))
	if err != nil {
		t.Fatal(err)
	}
	m := decodeGzipFrame(t, out)
	if _, has := m["timeout"]; has {
		t.Fatalf("未传 timeout_s 却出现 timeout 字段: %v", m)
	}
	if m["stdout"] != "hi\n" {
		t.Fatalf("stdout=%q", m["stdout"])
	}
}
