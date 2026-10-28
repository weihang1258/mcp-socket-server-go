package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func setUpgradeRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "versions"), 0o755)
	prev := upgradeRoot
	upgradeRoot = dir
	t.Cleanup(func() { upgradeRoot = prev })
	return dir
}

func setUpgradeRestart(t *testing.T, called *atomic.Bool) {
	t.Helper()
	prev := restartServiceFn
	restartServiceFn = func() error { called.Store(true); return nil }
	t.Cleanup(func() { restartServiceFn = prev })
}

func setUpgradeClients(n int64) { overrideClients.Store(n) }

// finalize：staging sha 校验 → chmod 755 → 原子 replace → 清 staging
func TestUpgradeFinalizeHappy(t *testing.T) {
	root := setUpgradeRoot(t)
	vdir := filepath.Join(root, "versions", "1.9.1", ".staging")
	os.MkdirAll(vdir, 0o755)
	bin := filepath.Join(vdir, "socket_server")
	os.WriteFile(bin, []byte("NEW-BINARY"), 0o644)
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte("NEW-BINARY")))

	ok, err := finalizePushedVersion("1.9.1", sha)
	if !ok || err != nil {
		t.Fatalf("finalize: %v %v", ok, err)
	}
	final := filepath.Join(root, "versions", "1.9.1", "socket_server")
	data, err := os.ReadFile(final)
	if err != nil || string(data) != "NEW-BINARY" {
		t.Fatalf("final binary: %v", err)
	}
	if fi, _ := os.Stat(final); fi.Mode()&0o111 == 0 {
		t.Fatal("final binary must be 0755")
	}
	if _, err := os.Stat(vdir); !os.IsNotExist(err) {
		t.Fatal("staging dir must be removed")
	}
}

// sha 不符：清理残包 + 拒绝
func TestUpgradeFinalizeShaMismatch(t *testing.T) {
	root := setUpgradeRoot(t)
	vdir := filepath.Join(root, "versions", "1.9.1", ".staging")
	os.MkdirAll(vdir, 0o755)
	os.WriteFile(filepath.Join(vdir, "socket_server"), []byte("DATA"), 0o644)

	ok, err := finalizePushedVersion("1.9.1", strings.Repeat("a", 64))
	if ok || err == nil {
		t.Fatal("want reject")
	}
	if !strings.Contains(err.Error(), "sha256 校验失败") {
		t.Fatalf("message: %v", err)
	}
	if _, serr := os.Stat(vdir); !os.IsNotExist(serr) {
		t.Fatal("staging must be cleaned on sha mismatch")
	}
}

// 缺 staging 包 / 版本非法
func TestUpgradeFinalizeRejects(t *testing.T) {
	root := setUpgradeRoot(t)
	if ok, err := finalizePushedVersion("1.9.1", strings.Repeat("a", 64)); ok || err == nil {
		t.Fatal("missing staging must reject")
	}
	if ok, err := finalizePushedVersion("../evil", strings.Repeat("a", 64)); ok || err == nil {
		t.Fatal("bad version must reject")
	}
	_ = root
}

// dt20 全链路：v 前缀归一化 + force + 无其他客户端 → ok；后台触发 restart
func TestDT20Happy(t *testing.T) {
	root := setUpgradeRoot(t)
	vdir := filepath.Join(root, "versions", "1.9.1", ".staging")
	os.MkdirAll(vdir, 0o755)
	os.WriteFile(filepath.Join(vdir, "socket_server"), []byte("NB"), 0o644)
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte("NB")))
	var restarted atomic.Bool
	setUpgradeRestart(t, &restarted)
	setUpgradeClients(1) // 仅 dt20 自身连接

	payload, _ := json.Marshal(map[string]any{"version": "v1.9.1", "sha256": sha, "force": true})
	resp, err := runDT(t, 20, payload)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(resp, &m)
	if m["ok"] != true || m["version"] != "1.9.1" {
		t.Fatalf("dt20 resp: %q", resp)
	}
	// 后台 switch_to：等软链切换 + restart 调用
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if restarted.Load() {
			link, err := os.Readlink(filepath.Join(root, "versions", "current"))
			if err == nil && strings.HasSuffix(link, "1.9.1") {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("restart/link not done: link=%v restarted=%v", func() any {
		l, e := os.Readlink(filepath.Join(root, "versions", "current"))
		if e != nil {
			return e.Error()
		}
		return l
	}(), restarted.Load())
}

// dt20 拒绝矩阵：autoupgrade off / 其他客户端 / sha 非法 / 版本非法
func TestDT20Rejections(t *testing.T) {
	root := setUpgradeRoot(t)
	vdir := filepath.Join(root, "versions", "1.9.1", ".staging")
	os.MkdirAll(vdir, 0o755)
	os.WriteFile(filepath.Join(vdir, "socket_server"), []byte("NB"), 0o644)
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte("NB")))

	// 其他客户端 >1 且非 force
	setUpgradeClients(3)
	resp, _ := runDT(t, 20, mustJSON(t, map[string]any{"version": "1.9.1", "sha256": sha}))
	var m map[string]string
	json.Unmarshal(resp, &m)
	if !strings.Contains(m["error"], "拒绝升级") {
		t.Fatalf("busy reject: %q", resp)
	}
	// force 可过客户端检查（到 autoupgrade 分支）
	setUpgradeClients(1)
	// sha 非法
	resp, _ = runDT(t, 20, mustJSON(t, map[string]any{"version": "1.9.1", "sha256": "xyz"}))
	json.Unmarshal(resp, &m)
	if !strings.Contains(m["error"], "sha256") {
		t.Fatalf("sha reject: %q", resp)
	}
	// 版本非法
	resp, _ = runDT(t, 20, mustJSON(t, map[string]any{"version": "evil", "sha256": sha}))
	json.Unmarshal(resp, &m)
	if !strings.Contains(m["error"], "version") {
		t.Fatalf("version reject: %q", resp)
	}
	// autoupgrade=off
	os.WriteFile(filepath.Join(root, "config"), []byte("autoupgrade=off\n"), 0o644)
	resp, _ = runDT(t, 20, mustJSON(t, map[string]any{"version": "1.9.1", "sha256": sha}))
	json.Unmarshal(resp, &m)
	if !strings.Contains(m["error"], "autoupgrade=off") {
		t.Fatalf("autoupgrade reject: %q", resp)
	}
}

// switch_to：未下载版本 → false；已下载 → 原子软链切换
func TestUpgradeSwitchTo(t *testing.T) {
	root := setUpgradeRoot(t)
	var restarted atomic.Bool
	setUpgradeRestart(t, &restarted)
	if switchTo("9.9.9") {
		t.Fatal("undownloaded version must fail")
	}
	vdir := filepath.Join(root, "versions", "1.9.5")
	os.MkdirAll(vdir, 0o755)
	os.WriteFile(filepath.Join(vdir, "socket_server"), []byte("x"), 0o755)
	if !switchTo("1.9.5") {
		t.Fatal("switch want true")
	}
	link, err := os.Readlink(filepath.Join(root, "versions", "current"))
	if err != nil || !strings.HasSuffix(link, "1.9.5") {
		t.Fatalf("current link: %q %v", link, err)
	}
}

// autoupgrade 配置读写：缺省 on；set 写回保留其他键
func TestAutoupgradeConfig(t *testing.T) {
	root := setUpgradeRoot(t)
	if !readAutoupgrade() {
		t.Fatal("missing config default on")
	}
	os.WriteFile(filepath.Join(root, "config"), []byte("http_port=9001\nautoupgrade=on\nproxy=\n"), 0o644)
	if !readAutoupgrade() {
		t.Fatal("on expected")
	}
	setAutoupgrade("off")
	data, _ := os.ReadFile(filepath.Join(root, "config"))
	if !strings.Contains(string(data), "http_port=9001") || !strings.Contains(string(data), "autoupgrade=off") {
		t.Fatalf("other keys must survive: %q", data)
	}
}
