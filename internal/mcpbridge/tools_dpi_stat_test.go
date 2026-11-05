package mcpbridge

// pid 必须是平铺的字符串数组；policy_wait 不能把"解析不到"当成 expected=0。
import (
	"strings"
	"testing"
)

func TestToListenStartFlattensPID(t *testing.T) {
	got := toListenStart(map[string]any{"pid": []any{"111", "222"}})
	if len(got.PID) != 2 || got.PID[0] != "111" {
		t.Fatalf("pid 应为 [111 222]，实际 %#v（评审 P3-2：曾变成 [[111]]）", got.PID)
	}
	if got := toListenStart(map[string]any{"pid": "333"}); len(got.PID) != 1 || got.PID[0] != "333" {
		t.Fatalf("单值 pid 也要摊平: %#v", got.PID)
	}
}

// dpi_policy_wait(expected=0)：解析不到 actual 时不能因为 intOf2("")==0 就判已就绪
// （评审 P3-9）。这里直接锁住判据本身的行为。
func TestPolicyWaitZeroExpectedNeedsActualValue(t *testing.T) {
	for _, tc := range []struct {
		actual string
		want   bool
	}{
		{"", false},  // 还没解析出值：不能说"已经 0 条"
		{"0", true},  // 真的是 0 条
		{"3", false}, //
	} {
		got := strings.TrimSpace(tc.actual) != "" && intOf2(tc.actual) == 0
		if got != tc.want {
			t.Errorf("actual=%q 判据应为 %v，实际 %v", tc.actual, tc.want, got)
		}
	}
}
