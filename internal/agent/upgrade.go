package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/weihang1258/mcp-socket-server-go/internal/svc"
)

// 升级落地（upgrader.py/supervisor.py/autoupgrade.py 移植，设计 §3 服务化段 + dt20 行）。
// 路径逐字对齐 Python：/opt/socket/versions/<v>/{.staging/,}socket_server、current 软链、
// /opt/socket/config 的 autoupgrade=（缺省 on，dt20 落地前实时读）。
// switch_to 走 svc 的 systemctl restart（生产会杀死本进程——与 Python 同）。

var upgradeRoot = "/opt/socket"

// restartServiceFn 服务重启注入点（生产 = svc.AgentRestart → systemctl restart）。
var restartServiceFn = defaultRestartService

func defaultRestartService() error { return svcAgentRestart() }

// overrideClients 测试注入活跃客户端数；默认 -1 = 用真实 Clients()。
var overrideClients atomic.Int64

func activeClientsNow() int64 {
	if n := overrideClients.Load(); n >= 0 {
		return n
	}
	return Clients()
}

var upgradeLock = make(chan struct{}, 1) // 非阻塞互斥（对齐 _upgrade_lock）

var versionRe = regexp.MustCompile(`^\d+(\.\d+){1,3}$`)

// normalizeVersion strip + lstrip("v")（dt20 归一化，复审 P2 已核）。
func normalizeVersion(s string) string { return strings.TrimLeft(strings.TrimSpace(s), "v") }

func versionsDir() string { return filepath.Join(upgradeRoot, "versions") }

// readAutoupgrade /opt/socket/config 的 autoupgrade=（缺省 on；实时读）。
func readAutoupgrade() bool {
	data, err := os.ReadFile(filepath.Join(upgradeRoot, "config"))
	if err != nil {
		return true // 默认 on
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "autoupgrade=") {
			return strings.ToLower(strings.TrimSpace(line[len("autoupgrade="):])) == "on"
		}
	}
	return true
}

// setAutoupgrade 写回（保留其他键，对齐 autoupgrade.set_autoupgrade）。
// SetAutoupgrade 导出（CLI 用）。
func SetAutoupgrade(state string) error { return setAutoupgrade(state) }

func setAutoupgrade(state string) error {
	type kv struct{ k, v string }
	var order []kv
	cfg := map[string]string{}
	if data, err := os.ReadFile(filepath.Join(upgradeRoot, "config")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if _, seen := cfg[k]; !seen {
				order = append(order, kv{k, v})
			}
			cfg[k] = v
		}
	}
	cfg["autoupgrade"] = state
	var sb strings.Builder
	for _, pair := range order {
		if pair.k == "autoupgrade" {
			pair.v = state
		}
		sb.WriteString(pair.k + "=" + pair.v + "\n")
	}
	if _, seen := cfg["autoupgrade"]; !seen {
		sb.WriteString("autoupgrade=" + state + "\n")
	}
	return os.WriteFile(filepath.Join(upgradeRoot, "config"), []byte(sb.String()), 0o644)
}

// isVersionDownloaded versions/<v>/socket_server 存在且可执行。
func isVersionDownloaded(version string) bool {
	fi, err := os.Stat(filepath.Join(versionsDir(), version, "socket_server"))
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}

// finalizePushedVersion 校验并落盘（纯本地；staging sha 校验→chmod→replace→清 staging）。
func finalizePushedVersion(version, expectedSHA string) (bool, error) {
	version = normalizeVersion(version)
	if !versionRe.MatchString(version) {
		return false, fmt.Errorf("version 非法: '%s'", version)
	}
	expectedSHA = strings.ToLower(strings.TrimSpace(expectedSHA))
	if len(expectedSHA) != 64 || !isHex64(expectedSHA) {
		return false, errors.New("缺少或非法 sha256（需 64 位十六进制）")
	}
	if !readAutoupgrade() {
		return false, errors.New("本机 autoupgrade=off，已拒绝升级（/opt/socket/config 改为 on 后重试）")
	}
	stagingDir := filepath.Join(versionsDir(), version, ".staging")
	stagingBin := filepath.Join(stagingDir, "socket_server")
	fi, err := os.Stat(stagingBin)
	if err != nil || fi.IsDir() {
		return false, fmt.Errorf("未找到推送的升级包: %s（需先经 :9001 上传）", stagingBin)
	}
	data, err := os.ReadFile(stagingBin)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != expectedSHA {
		os.RemoveAll(stagingDir)
		return false, fmt.Errorf("sha256 校验失败: 期望 %s, 实际 %s（已清理残包）", expectedSHA, actual)
	}
	finalBin := filepath.Join(versionsDir(), version, "socket_server")
	if err := os.Chmod(stagingBin, 0o755); err != nil {
		return false, err
	}
	if err := os.Rename(stagingBin, finalBin); err != nil {
		return false, err
	}
	os.RemoveAll(stagingDir)
	log.Printf("升级包落盘: %s (sha256=%s...)", finalBin, actual[:16])
	return true, nil
}

func isHex64(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// switchTo 原子改 current 软链 + 重启（Python switch_to 语义：不返回 = 正常）。
func switchTo(version string) bool {
	version = normalizeVersion(version)
	if !isVersionDownloaded(version) {
		log.Printf("版本 %s 未下载到本地 %s，无法切换", version, versionsDir())
		return false
	}
	current := filepath.Join(versionsDir(), "current")
	target := filepath.Join(versionsDir(), version)
	tmp := current + ".tmp"
	if fi, err := os.Lstat(tmp); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		os.Remove(tmp) // 仅清理残留软链（Python islink 语义；普通文件残留 → symlink 失败不重启）
	}
	if err := os.Symlink(target, tmp); err != nil {
		return false
	}
	if err := os.Rename(tmp, current); err != nil { // 原子 replace
		os.Remove(tmp)
		return false
	}
	// 版本目录只增不减（真机 25 个版本 389MB）。切换成功后再清理，当前版本
	// 一定保得住；清理失败只记日志，绝不能影响升级。
	if err := pruneOldVersions(version, keepVersions); err != nil {
		log.Printf("清理旧版本失败（不影响升级）: %v", err)
	}
	// 同机部署时 mcp 也走 current/socket_server。**必须在 agent restart 之前**
	// 重启它：restartServiceFn 是 `systemctl restart <自己>`，会把本进程杀掉，
	// 排在它后面的代码永远执行不到（v1.9.5 就栽在这——回函说会重启 mcp，
	// 真机验收 mcp PID 纹丝不动）。
	if mcpActiveFn() {
		if err := mcpRestartFn(); err != nil {
			log.Printf("mcp 单元重启失败（同机部署时它仍在跑旧二进制）: %v", err)
		}
	}
	// 日志打在 restart 前：restart 会杀死本进程（Python 注释同源）
	log.Printf("升级完成：v%s → v%s，重启服务生效...", Version, version)
	if err := restartServiceFn(); err != nil {
		log.Printf("service restart 失败: %v", err)
	}
	return true
}

// 同机部署时 mcp 单元也走 current/socket_server（软链布局）。切换后只重启
// agent 会让 mcp 继续跑旧版本——与 install 路径同一个坑，这里一并处理。
// mcp 未运行（分机部署）时不动它。
var (
	mcpActiveFn  = svc.MCPActive
	mcpRestartFn = svc.MCPRestart
)

// applyPushedUpgrade dt20 同步段（_apply_pushed_upgrade 语义顺序）。
// 返回响应字节；restartVersion 非空 → 后台 0.3s 后 switch_to。
func applyPushedUpgrade(payload []byte) ([]byte, string) {
	var p struct {
		Version string `json:"version"`
		SHA     string `json:"sha256"`
		Force   bool   `json:"force"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, "" // Python json.loads 异常 → do() 冒泡 → 断连无响应
	}
	version := normalizeVersion(p.Version)
	if !versionRe.MatchString(version) {
		return jsonMarshal(map[string]string{"error": "version 参数非法（期望如 1.8.0）"}), ""
	}
	sha := strings.ToLower(strings.TrimSpace(p.SHA))
	if len(sha) != 64 || !isHex64(sha) {
		return jsonMarshal(map[string]string{"error": "缺少或非法 sha256（需 64 位十六进制）"}), ""
	}
	if !readAutoupgrade() {
		return jsonMarshal(map[string]string{"error": "本机 autoupgrade=off，已拒绝升级（/opt/socket/config 改为 on 后重试）"}), ""
	}
	select {
	case upgradeLock <- struct{}{}:
		defer func() { <-upgradeLock }()
	default:
		return jsonMarshal(map[string]string{"error": "升级进行中，请勿重复下发"}), ""
	}
	// active_clients>1（含 dt20 自身这条连接）且非 force → 拒
	if n := activeClientsNow(); n > 1 && !p.Force {
		return jsonMarshal(map[string]string{
			"error": fmt.Sprintf("还有 %d 个其它客户端连接，拒绝升级（force=true 可强制）", n-1),
		}), ""
	}
	ok, err := finalizePushedVersion(version, sha)
	if !ok {
		log.Printf("升级落盘失败: %v", err)
		return jsonMarshal(map[string]string{"error": err.Error()}), ""
	}
	return jsonMarshal(map[string]any{"ok": true, "version": version}), version
}

// dt20 后台段：0.3s 让响应先送达（字节已入内核缓冲），再切链+重启。
func restartAfterUpgrade(version string) {
	time.Sleep(300 * time.Millisecond)
	if !switchTo(version) {
		log.Printf("升级切换失败：版本 %s 落盘后仍不可切换（见上方日志）", version)
	}
}

// svcAgentRestart 生产重启（svc 不依赖 agent，无环）。
var svcAgentRestart = svc.AgentRestart

// upgradeMu 仅防 dt20 并发重入 applyPushedUpgrade 的测试态。
var upgradeMu sync.Mutex

// jsonMarshal 生产侧 JSON 序列化（测试文件另有 mustJSON）。
func jsonMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
