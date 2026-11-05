package mcpbridge

// waitDPIAlive 的关键防误判：命令被 agent 到点杀掉时 stdout 是空串。
// 若把这当成一次"采样值"，它必然与基线不等 → 误判"DPI 活了"。
// 调用方（dpi_switch_mode / dpi_service / dpi_apply_config）会据此报成功，
// 而 DPI 实际没起来。

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func timeoutReply(w *mockConnIO) {
	body, _ := json.Marshal(map[string]any{
		"code": -1, "stdout": "", "stderr": "命令超时，已杀进程组",
		"timeout": true, "killed": true, "verified": true, "pgid": 1,
	})
	gz := gzipBytes(body)
	n := make([]byte, 4)
	binary.LittleEndian.PutUint32(n, uint32(len(gz)))
	w.raw(append(n, gz...))
}

// 关键场景：**基线采到了**（第一个 md5sum 正常返回非空 hash），之后的采样全被杀。
// 此时空 stdout 与基线不等——若把被杀采样当有效观测就会误判"DPI 活了"。
// 评审 P2-9：只让全部采样都失败是假绿（那样基线永远建不起来，删掉修复也照样过）。
func TestWaitDPIAliveIgnoresKilledSamples(t *testing.T) {
	var n int
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if strings.Contains(p["args"], "md5sum") {
				n++
				if n == 1 {
					cmdReply(w, 0, "aaaa\n", "")
					return
				}
				timeoutReply(w)
				return
			}
			cmdReply(w, 0, "", "")
		}
	})
	c, _ := dialClient(t, m)

	start := time.Now()
	if waitDPIAlive(c, 5) {
		t.Fatalf("有基线、后续采样全被杀却判定 DPI 存活（耗时 %v）", time.Since(start))
	}
	if n < 2 {
		t.Fatalf("mock 只被采了 %d 次，没覆盖到'基线后被杀'", n)
	}
}

// 连基线都采不到：同样必须判 false（不能因为"没有基线"就跳过判定）。
func TestWaitDPIAliveNoBaselineIsFalse(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 1:
			timeoutReply(w)
		}
	})
	c, _ := dialClient(t, m)
	if waitDPIAlive(c, 3) {
		t.Fatal("连基线都采不到却判定 DPI 存活")
	}
}

func TestWaitDPIAliveDetectsChange(t *testing.T) {
	// 正常路径：第一次采样是基线，之后值变了 → alive=true
	var n int
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if !strings.Contains(p["args"], "md5sum") {
				cmdReply(w, 0, "", "")
				return
			}
			n++
			if n <= 1 {
				cmdReply(w, 0, "aaa\n", "")
				return
			}
			cmdReply(w, 0, "bbb\n", "")
		}
	})
	c, _ := dialClient(t, m)
	if !waitDPIAlive(c, 10) {
		t.Fatal("md5 变了却没判存活")
	}
}
