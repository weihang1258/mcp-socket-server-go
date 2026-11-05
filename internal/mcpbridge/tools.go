package mcpbridge

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// 15 个 MCP 工具（server.py 逐行契约，设计 §4）+ _run_batch 语义。

// Bridge mcp 桥聚合状态（init 一次）。
type Bridge struct {
	mu          sync.Mutex
	Registry    *Registry
	Locks       *LockManager
	Audit       *Audit
	Sched       *Scheduler
	Whitelist   []string
	DownloadDir string
	Proxy       string
	// proxyResolved 生效代理（ResolveProxy 结果，Init 时算一次）。
	// 显式 mcp.proxy 优先，空则回退 /opt/socket/config 的 proxy=。
	proxyResolved string
	Cfg           BridgeConfig
}

type BridgeConfig struct {
	DBPath         string
	DownloadDir    string
	Proxy          string
	UpgradeRepo    string
	UpgradeMirror  string
	LogLevel       string
	AuditDays      int
	Whitelist      []string
	DefaultTimeout int
	// FTPUser/FTPPassword 用于 dpi_prepare_package 的桥侧直连 FTP 下载。
	// 凭据留在桥配置里：不进工具参数、不进审计、不出现在靶机进程表。
	FTPUser     string
	FTPPassword string
}

// Init 初始化（对齐 init_server：registry/locks/audit 共用 db_path）。
func Init(cfg BridgeConfig) *Bridge {
	ConfigureUpgradeSource(cfg.UpgradeRepo, cfg.UpgradeMirror)
	proxy := ResolveProxy(cfg.Proxy)
	// 生效值一行可见：真机曾因配置层级错误 mirror 未生效，启动时毫无迹象，
	// 直到下载失败才发现（五轮验收）。repo/mirror/proxy 必须在这里就能对上。
	log.Printf("升级源配置: repo=%q mirror=%q proxy=%q", cfg.UpgradeRepo, cfg.UpgradeMirror, proxy)
	b := &Bridge{
		Registry:      mustRegistry(cfg.DBPath),
		Locks:         NewLockManager(),
		Audit:         mustAudit(cfg.DBPath, cfg.AuditDays),
		Sched:         NewScheduler(),
		Whitelist:     cfg.Whitelist,
		DownloadDir:   cfg.DownloadDir,
		Proxy:         cfg.Proxy,
		proxyResolved: proxy,
		Cfg:           cfg,
	}
	StartDailyCheck(proxy, func() string { return BridgeVersion })
	return b
}

// mustRegistry 每个 Bridge 各开一个 registry。
//
// 原来用包级 sync.Once 做单例，导致 newTestBridge 传的 t.TempDir() 只有第一个
// 生效：之后所有用例共享同一个库，且首个用例结束目录被删，测试之间互相污染
// （评审 P2-E）。生产里 Init 只调一次，去掉单例没有行为变化。
func mustRegistry(path string) *Registry {
	r, err := OpenRegistry(path)
	if err != nil {
		log.Fatalf("registry 打开失败: %v", err)
	}
	return r
}

func mustAudit(path string, days int) *Audit {
	a, err := OpenAudit(path, days)
	if err != nil {
		log.Fatalf("audit 打开失败: %v", err)
	}
	return a
}

// BridgeVersion initialize serverInfo 桥版本序列（与 dt14 靶机版本分离，§0）。
var BridgeVersion = "0.4.0"

// resolve @tag 展开（registry nil 兜底直通）。
func (b *Bridge) resolve(targets []string) []string {
	if b.Registry == nil {
		return targets
	}
	return b.Registry.Resolve(targets)
}

// runBatch _run_batch 移植：锁 → 池 → fn → 释放；CAPTURE 成功保留锁；
// {"_error":...} → failed；nil → note；false → failed。
// retrySafe 标记本工具重发是否无副作用，只影响断连文案分档（见 connErrText）。
func (b *Bridge) runBatch(ctx context.Context, targets []string, port int, class Lk, lockKey string,
	auditTool string, auditParams map[string]any, retrySafe bool, timeout int,
	fn func(c *Client) (any, error)) map[string]any {
	t0 := time.Now()
	results := b.runBatchResults(ctx, targets, port, class, lockKey, retrySafe, timeout, fn)

	// audit
	if auditTool != "" {
		b.writeAudit(ctx, auditTool, auditParams, results, t0)
	}
	return assemble(results)
}

// runBatchResults 同上但不做审计与组装，返回原始逐靶机结果（typed 信封用）。
func (b *Bridge) runBatchResults(ctx context.Context, targets []string, port int, class Lk, lockKey string,
	retrySafe bool, timeout int, fn func(c *Client) (any, error)) []TargetResult {
	resolved := b.resolve(targets)
	// 未知 @tag / 拼错的 host 会被 resolve 静默丢掉，剩下 0 台 → 信封变成
	// total=0/ok=0，读起来像"全都成功了"。调用方（含大模型）据此会以为动作
	// 已下发。这里补一条失败行，让"没匹配到任何目标"明确可见。
	if len(resolved) == 0 {
		return []TargetResult{{Target: joinTargets(targets), Ok: false,
			Err: noResolveReason(targets), ErrType: ErrBusiness}}
	}
	results := make([]TargetResult, len(resolved))

	// Python ThreadPoolExecutor(min(50, len))：多靶机并行各自计时。
	// sem 复用 Scheduler 的全局闸门——每次调用各建一个会把实际上限放大成
	// 「并发调用数 × 50」（评审 P2-4）。
	sem := b.Sched.Sem()
	var wg sync.WaitGroup
	for i, hp := range resolved {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, hp string) {
			defer wg.Done()
			defer func() { <-sem }()
			b.runOne(&results[i], hp, port, class, lockKey, retrySafe, timeout, fn)
		}(i, hp)
	}
	wg.Wait()
	return results
}

// runOne 单靶机执行（锁 → 池 → fn → 释放；CAPTURE 成功保留锁）。
func (b *Bridge) runOne(r *TargetResult, hp string, port int, class Lk, lockKey string, retrySafe bool, timeout int,
	fn func(c *Client) (any, error)) {
	host, portN := splitHostPort(hp, port)
	// 1. 锁（fail-fast）
	if class != LkNone {
		if err := b.Locks.TryAcquire(hp, class, lockKey); err != nil {
			*r = TargetResult{Target: hp, Ok: false, Err: err.Error()}
			return
		}
	}
	// 2. 池借出
	pool := b.Sched.GetPool(host, portN)
	c, err := pool.Acquire(10, timeout)
	if err != nil {
		if class != LkNone {
			b.Locks.Release(hp, class, lockKey)
		}
		// 出口 A：请求未发出（建连失败/池满），按工具幂等性分档（dialErrText）。
		// 不加前缀——"pool: " 曾只出现在本处（十轮验收 P2：两通道/两出口前缀不一），
		// 档位信息已由 dialErrText 尾注承载
		*r = TargetResult{Target: hp, Ok: false, Err: dialErrText(err, retrySafe), ErrType: ErrNetwork}
		return
	}
	// 2b. 超时真停（方案 §6.2）：agent 侧 timeout_s 让它在到点时先杀进程组，
	// socket deadline 比它宽 10 秒，保证「先杀后回包」有机会送达，而不是
	// 桥这边先断连、设备上的命令继续跑。
	c.CmdTimeout = timeout
	c.BudgetEnd = time.Now().Add(time.Duration(timeout) * time.Second)
	c.SetTimeout(timeout + 10)

	// 3. 执行
	healthy := true
	ok := true
	var data any
	data, err = fn(c)
	if err != nil {
		healthy = false
		ok = false
		*r = TargetResult{Target: hp, Ok: false, Err: connErrText(err, retrySafe), ErrType: connErrType(err)}
		// 子命令超时（多步编排内部）：把 killed/verified 带到最终 Failure
		var ce *CmdError
		if errors.As(err, &ce) && ce.Cleanup != nil {
			r.Cleanup = ce.Cleanup
			r.ErrType = ErrTimeout
		}
	} else {
		switch v := data.(type) {
		case map[string]any:
			if v == nil { // typed nil map（fn 直返客户端结果的 wait=false 路径）与裸 nil 同义
				data = map[string]any{"note": "wait=false 为异步执行不返回回显;需要 stdout 请 wait=true"} // B18
			} else if cu, timedOut := timeoutCleanup(v); timedOut {
				// agent 已到点杀进程组（方案 §6.2）：归 timeout，带 cleanup 回执；
				// verified=false 时调用方不得认为环境已释放。
				ok = false
				reason := fmt.Sprintf("执行超时（%d 秒），靶机已终止命令", timeout)
				if e, ok2 := v["_error"].(string); ok2 && e != "" {
					reason = e
				}
				*r = TargetResult{Target: hp, Ok: false, Err: reason, ErrType: ErrTimeout, Cleanup: cu}
				data = nil
			} else if e, has := v["_error"]; has { // 通用失败通道
				ok = false
				*r = TargetResult{Target: hp, Ok: false, Err: fmt.Sprint(e)}
				data = nil
			}
		case nil:
			data = map[string]any{"note": "wait=false 为异步执行不返回回显;需要 stdout 请 wait=true"} // B18
		case bool:
			if !v { // B23/B04
				ok = false
				*r = TargetResult{Target: hp, Ok: false, Err: "agent 返回 False（业务失败）"}
				data = nil
			}
		}
	}
	pool.Release(c, healthy)
	// B04: CAPTURE 长锁仅失败时立即释放；成功保留给 stop
	if class != LkNone {
		if class != LkCapture || !ok {
			b.Locks.Release(hp, class, lockKey)
		}
	}
	if ok && data != nil {
		*r = TargetResult{Target: hp, Ok: true, Data: data}
	}
}

// writeAudit 审计（outcomes 逐 target {target,ok,error}）。
func (b *Bridge) writeAudit(ctx context.Context, tool string, params map[string]any, results []TargetResult, t0 time.Time) {
	outcomes := []map[string]any{}
	okN, failN := 0, 0
	for _, r := range results {
		outcomes = append(outcomes, map[string]any{"target": r.Target, "ok": r.Ok, "error": r.Err})
		if r.Ok {
			okN++
		} else {
			failN++
		}
	}
	b.Audit.Write(tool, params, outcomes, okN, failN, int(time.Since(t0).Milliseconds()), sourceIPFromCtx(ctx))
}

// assemble {ok, failed:[{target,reason}], results:[{target,...data}]}。
func assemble(results []TargetResult) map[string]any {
	okN := 0
	failed := []map[string]any{}
	out := []map[string]any{}
	for _, r := range results {
		if r.Ok {
			okN++
			row := map[string]any{"target": r.Target}
			if m, is := r.Data.(map[string]any); is { // B13: dict 展开
				for k, v := range m {
					row[k] = v
				}
			} else if r.Data != nil {
				row["result"] = r.Data
			}
			out = append(out, row)
		} else {
			failed = append(failed, map[string]any{"target": r.Target, "reason": r.Err})
		}
	}
	return map[string]any{"ok": okN, "failed": failed, "results": out}
}

// splitHostPort 拆 host:port。resolve 已经把 "host:port" 拆成裸 host（registry.py:107
// 首冒号且其后全数字），所以进到这里还带冒号的只有两种：resolve 留下的裸 IPv6
// （fd00::5 / ::1），或 @tag 展开出来的裸 host。裸 IPv6 的末段常是纯数字，
// LastIndex 会把它误当端口（fd00::5 → host "fd00:" port 5）。
// 因此：多冒号且无方括号 → 整体当 host，端口用默认值。
func splitHostPort(hp string, defaultPort int) (string, int) {
	if strings.HasPrefix(hp, "[") { // [fd00::5]:9000
		if h, p, err := net.SplitHostPort(hp); err == nil {
			n := 0
			fmt.Sscanf(p, "%d", &n)
			return h, n
		}
		return strings.Trim(hp, "[]"), defaultPort
	}
	if strings.Count(hp, ":") > 1 { // 裸 IPv6，无端口
		return hp, defaultPort
	}
	idx := strings.LastIndex(hp, ":")
	if idx > 0 && isAllDigits(hp[idx+1:]) {
		host := strings.Trim(hp[:idx], "[]")
		n := 0
		fmt.Sscanf(hp[idx+1:], "%d", &n)
		return host, n
	}
	return strings.Trim(hp, "[]"), defaultPort
}

// ---- 工具注册（15 工具；入参 typed schema：jsonschema tag = Python Field description，
// omitempty = 非必填（可选参数默认值写入描述），对齐 server.py:37-75 的 Annotated 契约）----

// RegisterTools 注册全部工具（11 类，方案 §2/§4）。
// 每个工具的 name/description/inputSchema/outputSchema/_meta 一次注册齐全。
func (b *Bridge) RegisterTools(s *mcp.Server) {
	b.registerTargetTools(s)
	b.registerFileTools(s)
	b.registerShellTools(s)
	b.registerNetTools(s)
	b.registerCaptureTools(s)
	b.registerTrafficTools(s)
	b.registerListenTools(s)
	b.registerPcapTools(s)
	b.registerDpiStatTools(s)
	b.registerDpiDeviceTools(s)
	b.registerDpiPolicyTools(s)
	b.registerDpiInstallTools(s)
	b.registerBridgeTools(s)
}
func orDefaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// ---- helpers ----

func probe(host string, port, timeoutSec int) error {
	conn, err := netDialTimeout(host, port, timeoutSec)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func allFailed(targets []string, reason string) map[string]any {
	failed := []map[string]any{}
	for _, t := range targets {
		failed = append(failed, map[string]any{"target": t, "reason": reason})
	}
	return map[string]any{"ok": 0, "failed": failed, "results": []any{}}
}

func mergeMap(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// stripPortForURL host 三形态解析（[v6]:port / host:port / 裸 v6）。
func stripPortForURL(t string) string {
	if strings.HasPrefix(t, "[") && strings.Contains(t, "]:") {
		return strings.TrimPrefix(strings.SplitN(t, "]:", 2)[0], "[")
	}
	if strings.Count(t, ":") == 1 {
		parts := strings.Split(t, ":")
		if isAllDigits(parts[1]) {
			return parts[0]
		}
	}
	return t
}

func renameField(v any, from, to string) any {
	rows, ok := v.([]map[string]any)
	if !ok {
		return v
	}
	for _, row := range rows {
		if val, has := row[from]; has {
			row[to] = val
			delete(row, from)
		}
	}
	return rows
}

func parseVer3(v string) []int {
	m := regexp.MustCompile(`^\d+(\.\d+){1,3}$`).FindString(v)
	if m == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := []int{}
	for _, p := range parts {
		n := 0
		fmt.Sscanf(p, "%d", &n)
		out = append(out, n)
	}
	return out // 不补零：Python 元组前缀比较 (1,8)<(1,8,0)=true（复审 P2-10）
}

// verLess Python 元组前缀比较语义：短元组逐位比，前缀相等时短元组更小。
func verLess(parts []int, a, b, c int) bool {
	tuple := []int{a, b, c}
	for i := 0; i < len(parts) && i < 3; i++ {
		if parts[i] != tuple[i] {
			return parts[i] < tuple[i]
		}
	}
	return len(parts) < 3 // 前缀相等：短 < 长
}

func atLeast(v string, a, b, c int) bool {
	p := parseVer3(v)
	return p != nil && !verLess(p, a, b, c)
}

var _ = os.Getenv
