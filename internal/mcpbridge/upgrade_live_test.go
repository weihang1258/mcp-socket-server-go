package mcpbridge

// 三链真机升级闭环（设计 §9.5）。真实 systemd + /opt/socket 布局 + 真实 MCP 工具调用：
//   链A: Python 1.8.3（systemd 在跑）→ upgrade_run v1.9.1（本地 Go 构建）→ Go agent
//   链B: Go 1.9.1 → upgrade_run v1.9.2 → Go agent（自升级）
//   链C: Go 1.9.2 → upgrade_run v1.8.3（真机 PyInstaller 字节）→ 还原现场
// serve 别名双向 = systemd unit（ExecStart=.../current/socket_server serve）逐链重启即验。
// 前置（缺一 skip）：root + SOCKETSTACK_LIVE_UPGRADE=1 + socket_server.service active
// + /opt/socket/config autoupgrade=on + go 工具链。会真实重启本机服务约 3 次。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func liveUpgradeGuards(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("需要 root（真机升级闭环，sudo 运行）")
	}
	if os.Getenv("SOCKETSTACK_LIVE_UPGRADE") != "1" {
		t.Skip("需显式 SOCKETSTACK_LIVE_UPGRADE=1（会重启本机 socket_server 服务）")
	}
	if out, err := exec.Command("systemctl", "is-active", "--quiet", "socket_server.service").CombinedOutput(); err != nil {
		t.Skipf("socket_server.service 未运行: %s", out)
	}
	if cfg, err := os.ReadFile("/opt/socket/config"); err != nil || !strings.Contains(string(cfg), "autoupgrade=on") {
		t.Skip("/opt/socket/config autoupgrade != on")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go 工具链不可用")
	}
}

// buildGoAgent 按版本号构建真实 socketstack（-X 注入 Version），返回字节。
func buildGoAgent(t *testing.T, version string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "socketstack_"+version)
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", // root 下 git 目录属主不同 → VCS stamping 128
		"-ldflags", "-X github.com/weihang1258/mcp-socket-server-go/internal/agent.Version="+version,
		"-o", out, "../../cmd/socketstack")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if bytes, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build v%s: %v\n%s", version, err, bytes)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pyAgentBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("/opt/socket/versions/1.8.3/socket_server")
	if err != nil {
		t.Skipf("读 1.8.3 PyInstaller 失败: %v", err)
	}
	return b
}

// releaseServer 本地"中央"：version.py + /v<ver>/socket_server(.sha256)。
func releaseServer(t *testing.T, releases map[string][]byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/socket_server/version.py", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "VERSION = \"1.9.2\"\n")
	})
	for ver, bin := range releases {
		v, content := ver, bin
		mux.HandleFunc("/v"+v+"/socket_server", func(w http.ResponseWriter, r *http.Request) {
			w.Write(content)
		})
		sum := sha256.Sum256(content)
		mux.HandleFunc("/v"+v+"/socket_server.sha256", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, hex.EncodeToString(sum[:]))
		})
	}
	return httptest.NewServer(mux)
}

// mcpCall 经真实 MCP 客户端调工具并解 JSON 结果。
func mcpCall(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("%s: 空内容", name)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s: 非 TextContent: %T", name, res.Content[0])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("%s: 结果非 JSON: %s", name, text.Text)
	}
	return out
}

// waitVersion 直连 dt14 轮询到期望版本（重启窗口容错）。
func waitVersion(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		c := NewClient("127.0.0.1", 9000, 5)
		if err := c.Connect(); err == nil {
			v, err := c.Version()
			c.Close()
			if err == nil && v == want {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("60s 内未确认 dt14=%s", want)
}

func assertAgentLive(t *testing.T, wantVersion string) {
	t.Helper()
	if out, err := exec.Command("systemctl", "is-active", "--quiet", "socket_server.service").CombinedOutput(); err != nil {
		t.Fatalf("升级后服务未 active: %s", out)
	}
	cur, err := os.Readlink("/opt/socket/versions/current")
	if err != nil || filepath.Base(cur) != wantVersion {
		t.Fatalf("current → %s (err=%v), want …/%s", cur, err, wantVersion)
	}
	waitVersion(t, wantVersion)
}

func TestLiveThreeChainUpgradeInterop(t *testing.T) {
	liveUpgradeGuards(t)

	bin191 := buildGoAgent(t, "1.9.1")
	bin192 := buildGoAgent(t, "1.9.2")
	py183 := pyAgentBytes(t)
	releases := map[string][]byte{"1.9.1": bin191, "1.9.2": bin192, "1.8.3": py183}

	srv := releaseServer(t, releases)
	defer srv.Close()
	rawVersionBase, releaseBase = srv.URL+"/socket_server/version.py", srv.URL

	b := newTestBridge(t)
	if r := b.Registry.AddTarget("127.0.0.1", 9000, nil, ""); r["ok"] != true {
		t.Fatalf("AddTarget: %v", r)
	}
	msrv := mcp.NewServer(&mcp.Implementation{Name: "live", Version: "0"}, nil)
	b.RegisterTools(msrv)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := msrv.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// §9.5 quirk：升级重启后池内旧连接已死且 acquire 不检活（Python pool.py 同语义）
	// → 升级后首个调用失败一次；真实客户端即重试，重试必须成功
	runUpgrade := func(chain, ver string) map[string]any {
		args := map[string]any{"targets": []string{"127.0.0.1"}, "version": ver, "timeout": 60}
		out := mcpCall(t, cs, "upgrade_run", args)
		if out["ok"] != float64(1) {
			t.Logf("%s 首调失败（升级后死连接 quirk，预期可发生）: %v", chain, out["failed"])
			out = mcpCall(t, cs, "upgrade_run", args)
			if out["ok"] != float64(1) {
				t.Fatalf("%s 重试仍失败: %v", chain, out)
			}
		}
		return out
	}

	// 链A: Python 1.8.3 → Go 1.9.1（跨实现升级，unit 不动 → serve 别名拉起 Go）
	t.Log("链A: Python 1.8.3 → Go 1.9.1")
	runUpgrade("链A", "1.9.1")
	assertAgentLive(t, "1.9.1")

	// 链B: Go 1.9.1 → Go 1.9.2（自升级）
	t.Log("链B: Go 1.9.1 → Go 1.9.2")
	runUpgrade("链B", "1.9.2")
	assertAgentLive(t, "1.9.2")

	// 链C: Go 1.9.2 → Python 1.8.3（回滚方向，还原现场）
	t.Log("链C: Go 1.9.2 → Python 1.8.3")
	runUpgrade("链C", "1.8.3")
	assertAgentLive(t, "1.8.3")
}
