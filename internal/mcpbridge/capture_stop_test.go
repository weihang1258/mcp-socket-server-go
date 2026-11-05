package mcpbridge

// capture_stop 对真实 agent 的回执兼容：dt6 只回 {"res":bool}（agent/handlers.go、
// Python handlers.py:162-168），没有 pcap_complete 四态。工具层若坚持要这个键，
// 真机上每次停抓包都会报 business 失败、reason 为 "<nil>"。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCaptureStopAcceptsLegacyResReply(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		if dt == 6 { // dt6 停抓包：老语义只回 {"res":true}
			w.text(`{"res":true}`)
		}
	})
	b := newTestBridge(t)
	srv := NewServer(b)
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true}))
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "capture_stop", Arguments: map[string]any{
		"targets": []string{m.Addr}, "port": portOf(m.Addr), "path": "/tmp/x.pcap"}})
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope[captureStopData]
	if err := json.Unmarshal([]byte(textOf(t, res)), &env); err != nil {
		t.Fatal(err)
	}
	if env.Ok != 1 {
		t.Fatalf("legacy 回执被误判失败: %+v", env.Failed)
	}
	d := env.Results[0].Data
	if !d.Stopped || !d.Legacy {
		t.Fatalf("应标记 stopped=true / legacy=true: %+v", d)
	}
	if d.Cleanup == nil || !d.Cleanup.Verified {
		t.Fatalf("确认停止后 cleanup.verified 应为 true: %+v", d.Cleanup)
	}
}

// 四态回执（方案 §4.5）：pcap_complete 是"完整"语义，false 必须判失败。
// 评审 P1-2：改造时把它取反了，正常收尾反而报失败、写盘失败反而报成功。
func TestCaptureStopFourStatePcapComplete(t *testing.T) {
	for _, tc := range []struct {
		name     string
		complete bool
		wantOK   bool
	}{
		{"pcap 完整", true, true},
		{"pcap 不完整", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
				if dt == 6 {
					w.text(fmt.Sprintf(`{"stopped":true,"exitcode":0,"pcap_complete":%v}`, tc.complete))
				}
			})
			env := callCaptureStop(t, m)
			if tc.wantOK && env.Ok != 1 {
				t.Fatalf("pcap_complete=true 应成功: %+v", env.Failed)
			}
			if !tc.wantOK {
				if env.Ok != 0 || len(env.Failed) != 1 {
					t.Fatalf("pcap_complete=false 必须判失败: %+v", env)
				}
				cu := env.Failed[0].Cleanup
				if cu == nil || cu.Verified {
					t.Fatalf("pcap 不完整时 cleanup.verified 必须为 false: %+v", cu)
				}
			}
		})
	}
}

func callCaptureStop(t *testing.T, m *mockServer) Envelope[captureStopData] {
	t.Helper()
	b := newTestBridge(t)
	srv := NewServer(b)
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true}))
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "capture_stop", Arguments: map[string]any{
		"targets": []string{m.Addr}, "port": portOf(m.Addr), "path": "/tmp/x.pcap"}})
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope[captureStopData]
	if err := json.Unmarshal([]byte(textOf(t, res)), &env); err != nil {
		t.Fatal(err)
	}
	return env
}
