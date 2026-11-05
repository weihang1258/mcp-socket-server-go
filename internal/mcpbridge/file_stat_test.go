package mcpbridge

// file_stat 必须一次分清「不存在 / 是目录 / 是文件」：只问 dt7 的话目录与
// 不存在都回 exists=false，调用方还得再补一次查询。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestFileStatDistinguishesDirAndMissing(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 7: // isfile：只有 /f 是文件
			w.text(boolRes(string(payload) == `{"file":"/f"}`))
		case 8: // isdir：只有 /d 是目录
			w.text(boolRes(string(payload) == `{"dir":"/d"}`))
		case 11: // dt11 回裸数字
			w.text(`42`)
		}
	})
	b := newTestBridge(t)
	call := func(path string) fileStatData {
		raw := b.runBatchResults(context.Background(), []string{m.Addr}, portOf(m.Addr),
			LkNone, "", true, 5, func(c *Client) (any, error) {
				isFile, err := c.Isfile(path)
				if err != nil {
					return nil, err
				}
				if !isFile {
					isDir, derr := c.Isdir(path)
					if derr != nil {
						return nil, derr
					}
					return fileStatData{Exists: isDir, IsDir: isDir}, nil
				}
				size, err := c.getsize(path)
				if err != nil {
					return nil, err
				}
				return fileStatData{Exists: true, SizeBytes: size}, nil
			})
		env := envelopeFrom[fileStatData](raw)
		if env.Ok != 1 {
			t.Fatalf("%s: %+v", path, env.Failed)
		}
		return env.Results[0].Data
	}

	if got := call("/f"); !got.Exists || got.IsDir || got.SizeBytes != 42 {
		t.Fatalf("文件: %+v", got)
	}
	if got := call("/d"); !got.Exists || !got.IsDir {
		t.Fatalf("目录: %+v", got)
	}
	if got := call("/nope"); got.Exists || got.IsDir {
		t.Fatalf("不存在: %+v", got)
	}
}

// 走真实注册路径（SDK CallTool → file_stat handler）：上面那个测的是复制品逻辑，
// handler 里改了而测不到就会假绿。
func TestFileStatThroughRealTool(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 7:
			w.text(boolRes(string(payload) == `{"file":"/f"}`))
		case 8:
			w.text(boolRes(string(payload) == `{"dir":"/d"}`))
		case 11:
			w.text(`42`)
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

	for _, tc := range []struct {
		path      string
		exists    bool
		isDir     bool
		sizeBytes float64
	}{
		{"/f", true, false, 42},
		{"/d", true, true, 0},
		{"/nope", false, false, 0},
	} {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "file_stat", Arguments: map[string]any{
			"targets": []string{m.Addr}, "path": tc.path, "port": portOf(m.Addr)}})
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		var env Envelope[fileStatData]
		if err := json.Unmarshal([]byte(textOf(t, res)), &env); err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if env.Ok != 1 {
			t.Fatalf("%s: %+v", tc.path, env.Failed)
		}
		got := env.Results[0].Data
		if got.Exists != tc.exists || got.IsDir != tc.isDir || float64(got.SizeBytes) != tc.sizeBytes {
			t.Fatalf("%s: got %+v want exists=%v dir=%v size=%v", tc.path, got, tc.exists, tc.isDir, tc.sizeBytes)
		}
	}
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatal("回执无文本内容")
	return ""
}

// boolRes 用 payload 里的路径名决定 res，让 mock 能按路径区分。
func boolRes(cond bool) string {
	if cond {
		return `{"res":true}`
	}
	return `{"res":false}`
}
