package mcpbridge

// switchMode 的核对语义对齐 Python dpi.py:1291-1325：切完之后开关/版本/模式
// 只要有一项对不上，整次切换就是失败（Python 置 result=False），不能只往
// marks 里记一笔然后报成功。

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// cmdReply 回一个 gzip dt1 回执（{code,stdout,stderr}）。
func cmdReply(w *mockConnIO, code int, stdout, stderr string) {
	body, _ := json.Marshal(map[string]any{"code": code, "stdout": stdout, "stderr": stderr})
	gz := gzipBytes(body)
	n := make([]byte, 4)
	binary.LittleEndian.PutUint32(n, uint32(len(gz)))
	w.raw(append(n, gz...))
}

func TestSwitchModeFailsOnModeMismatch(t *testing.T) {
	out := switchAgainstMock(t, `[{"code":0,"stdout":"dpi_ver 1.0.0\n"}]`)
	if _, ok := out["_error"]; !ok {
		t.Fatalf("切完模式对不上却报成功: %+v", out)
	}
}

// switchAgainstMock 起一个只会说"没切过去"的 agent：
// dpi 版本/模式查询始终返回同一组值，切换脚本"执行成功"但它们不变。
func switchAgainstMock(t *testing.T, _ string) map[string]any {
	t.Helper()
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		if dt != 1 {
			return
		}
		var p map[string]string
		json.Unmarshal(payload, &p)
		cmd := p["args"]
		switch {
		case strings.Contains(cmd, "dpiversion"):
			cmdReply(w, 0, "1.0.0\n", "")
		case strings.Contains(cmd, "dpimode"):
			cmdReply(w, 0, "com_a_b\n", "")
		case strings.Contains(cmd, "mod_switch.sh"):
			cmdReply(w, 0, "switched\n", "")
		default:
			cmdReply(w, 0, "", "")
		}
	})
	c, _ := dialClient(t, m)
	got, err := switchMode(c, dpiSwitchModeIn{
		BaseIn: BaseIn{Targets: []string{m.Addr}},
		Mode:   "com_x_y", // 与 mock 回的 com_a_b 不一致
		Force:  true,
	}, 1)
	if err != nil {
		t.Fatalf("switchMode: %v", err)
	}
	m2, ok := got.(map[string]any)
	if !ok {
		// 成功分支会回 dpiSwitchData；把它转成 map 方便统一断言
		b, _ := json.Marshal(got)
		m2 = map[string]any{}
		json.Unmarshal(b, &m2)
		if _, hasErr := m2["_error"]; !hasErr {
			t.Fatalf("期望失败回执，实际成功: %+v", got)
		}
	}
	return m2
}
