package mcpbridge

import (
	"context"
	"fmt"
	"log"
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

var (
	registryOnce sync.Once
	registryInst *Registry
	registryErr  error
)

func mustRegistry(path string) *Registry {
	registryOnce.Do(func() {
		registryInst, registryErr = OpenRegistry(path)
	})
	if registryErr != nil {
		log.Fatalf("registry 打开失败: %v", registryErr)
	}
	return registryInst
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
	resolved := b.resolve(targets)
	results := make([]TargetResult, len(resolved))

	// Python ThreadPoolExecutor(min(50, len))：多靶机并行各自计时
	sem := make(chan struct{}, 50)
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

	// audit
	if auditTool != "" {
		b.writeAudit(ctx, auditTool, auditParams, results, t0)
	}
	return assemble(results)
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
		// 出口 A：请求未发出（建连失败/池不可用），按工具幂等性分档（dialErrText）
		*r = TargetResult{Target: hp, Ok: false, Err: "pool: " + dialErrText(err, retrySafe)}
		return
	}
	// 3. 执行
	healthy := true
	ok := true
	var data any
	data, err = fn(c)
	if err != nil {
		healthy = false
		ok = false
		*r = TargetResult{Target: hp, Ok: false, Err: connErrText(err, retrySafe)}
	} else {
		switch v := data.(type) {
		case map[string]any:
			if e, has := v["_error"]; has { // 通用失败通道
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

func splitHostPort(hp string, defaultPort int) (string, int) {
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

func boolPtr(b bool) *bool { return &b }

func ro(name, desc string) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: desc, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}
}

// add 包装：handler 返回 any（map/list/标量），SDK 自动 structured content。
func add[In any](s *mcp.Server, t *mcp.Tool, h func(ctx context.Context, args In) any) {
	mcp.AddTool(s, t, func(ctx context.Context, req *mcp.CallToolRequest, args In) (*mcp.CallToolResult, any, error) {
		return nil, h(ctx, args), nil
	})
}

// 各工具入参（字段名 = MCP 参数名；omitempty = 可选）。
type callDescArgs struct {
	Description string `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的（将展示给用户），不超过 50 字"`
}
type listTargetsArgs struct {
	Description string `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type addTargetArgs struct {
	Host        string   `json:"host" jsonschema:"靶机 IP 或主机名(IPv6 裸地址,自动剥方括号)"`
	Port        int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Tags        []string `json:"tags,omitempty" jsonschema:"标签列表,用于 @tag 选机"`
	Note        string   `json:"note,omitempty" jsonschema:"备注(如机器用途)"`
	Force       bool     `json:"force,omitempty" jsonschema:"true = 跳过探活强制注册离线靶机"`
	Description string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type removeTargetArgs struct {
	Host        string `json:"host" jsonschema:"靶机 IP 或主机名"`
	Port        int    `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Description string `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type targetsArgs struct {
	Targets     []string `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	Port        int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Timeout     int      `json:"timeout,omitempty" jsonschema:"单靶机操作超时秒数(connect+执行+返回),多靶机并行各自计时"`
	Description string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type fileTransferArgs struct {
	Targets     []string `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	HTTPPort    int      `json:"http_port,omitempty" jsonschema:"靶机 HTTP 文件服务端口(默认 9001)"`
	Description string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type isfilePathArgs struct {
	Targets     []string `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	Path        string   `json:"path" jsonschema:"靶机上的绝对路径"`
	Port        int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Timeout     int      `json:"timeout,omitempty" jsonschema:"单靶机操作超时秒数(默认 15)"`
	Description string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type pcapFlowArgs struct {
	Targets     []string `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	PcapDir     string   `json:"pcap_dir" jsonschema:"靶机上的 pcap 目录绝对路径"`
	Port        int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Timeout     int      `json:"timeout,omitempty" jsonschema:"单靶机操作超时秒数(默认 30)"`
	Description string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type cmdExecArgs struct {
	Targets     []string          `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	Args        string            `json:"args" jsonschema:"要执行的命令及参数(白名单非空时须命中前缀)"`
	Cwd         string            `json:"cwd,omitempty" jsonschema:"命令工作目录(留空 = 默认)"`
	Env         map[string]string `json:"env,omitempty" jsonschema:"命令环境变量键值对(可选,整替换子进程环境)"`
	Wait        *bool             `json:"wait,omitempty" jsonschema:"true = 等命令结束返回结果(默认);false=立即返回无结果"`
	Port        int               `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Timeout     int               `json:"timeout,omitempty" jsonschema:"单靶机操作超时秒数(默认 60;wait=false 时取 min(60,15))"`
	Description string            `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type captureStartArgs struct {
	Targets     []string `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	Iface       string   `json:"iface,omitempty" jsonschema:"网卡名,如 eth0;留空自动取默认路由网卡"`
	Path        string   `json:"path,omitempty" jsonschema:"靶机上的 pcap 保存绝对路径(默认 /home/tmp/tmp.pcap;多任务请显式传不同 path)"`
	Extended    string   `json:"extended,omitempty" jsonschema:"tcpdump 扩展过滤表达式(留空=不过滤)"`
	SingleQueue *bool    `json:"single_queue,omitempty" jsonschema:"true = 单队列收包(收包序=线序,默认)"`
	Port        int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Timeout     int      `json:"timeout,omitempty" jsonschema:"单靶机操作超时秒数(默认 30)"`
	Description string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type captureStopArgs struct {
	Targets []string `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	Path    string   `json:"path,omitempty" jsonschema:"停止的 pcap 绝对路径(默认 /home/tmp/tmp.pcap)"`
	Port    int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Timeout int      `json:"timeout,omitempty" jsonschema:"单靶机操作超时秒数(默认 30)"`
}

type boceRunArgs struct {
	Targets      []string `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	Url          string   `json:"url" jsonschema:"拨测目标 URL"`
	Count        int      `json:"count,omitempty" jsonschema:"拨测次数(默认 1)"`
	Interval     int      `json:"interval,omitempty" jsonschema:"拨测间隔秒(默认 0)"`
	ThreadCount  int      `json:"thread_count,omitempty" jsonschema:"拨测并发线程数(默认 1)"`
	Mode         string   `json:"mode,omitempty" jsonschema:"拨测模式: 封堵/重定向 有效;弹窗未实现(恒失败);其他值按未知模式恒失败"`
	ChromiumPath string   `json:"chromium_path,omitempty" jsonschema:"chromium 可执行文件路径(留空=默认 /opt/socket/chrome-linux/chrome)"`
	Port         int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Timeout      int      `json:"timeout" jsonschema:"单靶机操作超时秒数(connect+执行+返回),多靶机并行各自计时;至少 10 秒(拨测内部 HTTP/goto 预算自动扣 10s 余量)"`
	Description  string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type replayRunArgs struct {
	Targets       []string `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	Pcaps         []string `json:"pcaps" jsonschema:"靶机上 pcap 文件的绝对路径列表(需先用 HTTP 上传)"`
	UplinkIface   string   `json:"uplink_iface" jsonschema:"上行物理网卡名,如 eth0"`
	DownlinkIface string   `json:"downlink_iface" jsonschema:"下行物理网卡名,单臂回放可与上行相同"`
	UplinkVlan    *int     `json:"uplink_vlan,omitempty" jsonschema:"VLAN ID(可选,不给则不打 VLAN 标)"`
	DownlinkVlan  *int     `json:"downlink_vlan,omitempty" jsonschema:"VLAN ID(可选)"`
	Mbps          int      `json:"mbps,omitempty" jsonschema:"回放限速 Mbps,0=不限速(默认)"`
	ForceIpSrc    string   `json:"force_ip_src,omitempty" jsonschema:"强制替换源 IP(可选)"`
	ForceIpDst    string   `json:"force_ip_dst,omitempty" jsonschema:"强制替换目的 IP(可选)"`
	ForceSport    int      `json:"force_sport,omitempty" jsonschema:"强制替换源端口(0 = 不改写,默认)"`
	ForceDport    int      `json:"force_dport,omitempty" jsonschema:"强制替换目的端口(0 = 不改写,默认)"`
	Port          int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Timeout       int      `json:"timeout,omitempty" jsonschema:"单靶机操作超时秒数(默认 120)"`
	Description   string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type socketListenArgs struct {
	Targets     []string `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	Action      string   `json:"action" jsonschema:"start = 启动返回pid / stop=停止当前监听 / clean=清空已收数据 / save=已收数据保存到靶机文件 / fetch=取回已收数据(超过 max_bytes 落盘靶机并截断返回)"`
	ListenPort  int      `json:"listen_port,omitempty" jsonschema:"仅 start 用:监听端口(默认 30001)"`
	File        string   `json:"file,omitempty" jsonschema:"仅 save 用:数据保存到靶机的绝对路径"`
	MaxBytes    int      `json:"max_bytes,omitempty" jsonschema:"仅 fetch 用:返回内容上限(解压后明文字节),超限截断并落盘靶机(默认 1048576)"`
	Port        int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Timeout     int      `json:"timeout,omitempty" jsonschema:"单靶机操作超时秒数(默认 30)"`
	Description string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

type upgradeRunArgs struct {
	Targets     []string `json:"targets" jsonschema:"靶机列表(裸IP/host:port/@tag 标签)"`
	Version     string   `json:"version,omitempty" jsonschema:"目标版本号如 1.8.0;留空=自动查 GitHub 最新版(失败可显式指定重试)"`
	Force       bool     `json:"force,omitempty" jsonschema:"true = 靶机有其它客户端连接时强制升级(会带着连接重启);默认 false=拒绝"`
	Port        int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口(默认 9000)"`
	Timeout     int      `json:"timeout,omitempty" jsonschema:"单靶机操作超时秒数(默认 60)"`
	Description string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的"`
}

// RegisterTools 注册全部 15 工具。
func (b *Bridge) RegisterTools(s *mcp.Server) {
	tg := func(args targetsArgs) []string { return args.Targets }

	// 1. list_targets
	add(s, ro("list_targets", "列出已注册的靶机。"), func(ctx context.Context, a listTargetsArgs) any {
		return map[string]any{"targets": b.Registry.ListTargets()}
	})

	// 2. add_target
	add(s, &mcp.Tool{Name: "add_target", Description: "注册新靶机。tags 用于 @tag 选机。注册前 TCP 探活（不通拒绝，force=True 跳过）。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, a addTargetArgs) any {
			host := strings.Trim(a.Host, "[]")
			if !a.Force {
				if err := probe(host, orDefault(a.Port, 9000), 3); err != nil {
					return map[string]any{"ok": false, "error": fmt.Sprintf("%s:%d 不可达(TCP connect 失败: %v)，未注册；force=True 可强制注册", host, orDefault(a.Port, 9000), err)}
				}
			}
			return b.Registry.AddTarget(host, orDefault(a.Port, 9000), a.Tags, a.Note)
		})

	// 3. remove_target
	add(s, &mcp.Tool{Name: "remove_target", Description: "移除靶机(有活跃锁或活跃监听时拒绝)。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), IdempotentHint: true}},
		func(ctx context.Context, a removeTargetArgs) any {
			port := orDefault(a.Port, 9000)
			// quirk：锁/liveness/删除键全用原始 host（不剥方括号）
			if b.Locks.HasActive(a.Host) {
				return map[string]any{"ok": false, "error": fmt.Sprintf("靶机 %s 有活跃锁，无法移除", a.Host)}
			}
			if b.Registry.GetListenLiveness(a.Host, port) {
				return map[string]any{"ok": false, "error": fmt.Sprintf("靶机 %s 有活跃监听，请先 socket_listen action=stop", a.Host)}
			}
			return b.Registry.RemoveTarget(a.Host, port)
		})

	// 4. version
	add(s, ro("version", "查询靶机 socket_server 版本号(datatype 14,只读)。升级前先调本工具确认各靶机现版本，再决定调 upgrade_run 升到哪个版本。"),
		func(ctx context.Context, a targetsArgs) any {
			out := b.runBatch(ctx, tg(a), orDefault(a.Port, 9000), LkNone, "", "", nil, true, orDefault(a.Timeout, 15), func(c *Client) (any, error) {
				return c.Version()
			})
			out["results"] = renameField(out["results"], "result", "version")
			return out
		})

	// 5. file_transfer
	add(s, ro("file_transfer", "获取客户端与靶机之间点对点传文件的命令(零网络调用,纯指引)。上传后需执行权限接 cmd_exec chmod +x。9001 拒绝连接=靶机 http_port=0(配置关闭)或版本 <1.7.0,先 upgrade_run 升级。靶机侧路径限白名单: /home/tmp/ 与 /opt/socket/versions/*/.staging/(升级自动走 staging,无需关心);传其他目录会 403,v1.9.11 起生效(Python 靶机不受限)。"),
		func(ctx context.Context, a fileTransferArgs) any {
			httpPort := orDefault(a.HTTPPort, 9001)
			var cmds []map[string]string
			for _, t := range b.resolve(a.Targets) {
				host := stripPortForURL(t)
				h6 := host
				if strings.Contains(host, ":") {
					h6 = "[" + host + "]"
				}
				cmds = append(cmds, map[string]string{
					"target":   t,
					"download": fmt.Sprintf("curl -o 本地文件 \"http://%s:%d/files?path=<远端绝对路径>\"", h6, httpPort),
					"upload":   fmt.Sprintf("curl -F \"path=<远端绝对路径>\" -F \"file=@本地文件\" http://%s:%d/files", h6, httpPort),
				})
			}
			if len(cmds) == 0 {
				return map[string]any{"ok": 0, "note": "无已注册靶机,先 add_target 注册再用",
					"usage": []string{
						"下载: curl -o 本地文件 \"http://<靶机IP>:9001/files?path=<远端绝对路径>\"",
						"上传: curl -F \"path=<远端绝对路径>\" -F \"file=@本地文件\" http://<靶机IP>:9001/files",
						"路径白名单(Go 靶机 v1.9.11+): /home/tmp/ 与 /opt/socket/versions/*/.staging/,白名单外 403"}}
			}
			return map[string]any{"ok": len(cmds), "commands": cmds}
		})

	// 6. isfile
	add(s, ro("isfile", "检查靶机文件是否存在(datatype 7,只读)。文件内容的上传下载用 file_transfer 工具(返回点对点直传命令)。"),
		func(ctx context.Context, a isfilePathArgs) any {
			out := b.runBatch(ctx, a.Targets, orDefault(a.Port, 9000), LkNone, "", "", nil, true, orDefault(a.Timeout, 15), func(c *Client) (any, error) {
				return c.Isfile(a.Path)
			})
			out["results"] = renameField(out["results"], "result", "exists")
			return out
		})

	// 7. isdir
	add(s, ro("isdir", "检查目录是否存在(datatype 8,只读)。"),
		func(ctx context.Context, a isfilePathArgs) any {
			out := b.runBatch(ctx, a.Targets, orDefault(a.Port, 9000), LkNone, "", "", nil, true, orDefault(a.Timeout, 15), func(c *Client) (any, error) {
				return c.Isdir(a.Path)
			})
			out["results"] = renameField(out["results"], "result", "exists")
			return out
		})

	// 8. pcap_flow_extract
	add(s, ro("pcap_flow_extract", "提取 pcap 五元组流(datatype 200,只读)。>1000 条截断。protoType: 1=TCP 2=UDP 4=ICMP。"),
		func(ctx context.Context, a pcapFlowArgs) any {
			resolved := b.resolve(a.Targets)
			results := b.Sched.Batch(resolved, orDefault(a.Port, 9000), orDefault(a.Timeout, 30), true, func(c *Client) (any, error) {
				return c.PcapFlowExtractRaw(a.PcapDir)
			})
			okN := 0
			failed := []map[string]any{}
			out := []map[string]any{}
			for _, r := range results {
				if !r.Ok {
					failed = append(failed, map[string]any{"target": r.Target, "reason": r.Err})
					continue
				}
				okN++
				flows, _ := r.Data.([]any)
				total := len(flows)
				truncated := false
				if total > 1000 {
					flows = flows[:1000]
					truncated = true
				}
				out = append(out, map[string]any{"target": r.Target, "flows": flows,
					"total": total, "truncated": truncated})
			}
			return map[string]any{"ok": okN, "failed": failed, "results": out}
		})

	// 9. cmd_exec
	add(s, &mcp.Tool{Name: "cmd_exec", Description: "执行命令(datatype 1,SHELL/DANGER,白名单校验后转发)。返回 {code,stdout,stderr};wait=false 为异步执行不返回回显(需要回显必须 wait=true);stdout 超 64KB 截断(带 stdout_truncated 标记)。把脚本/大段内容放到靶机勿经命令内嵌,调 file_transfer 获取上传命令。白名单为空=不限制（默认）。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)}},
		func(ctx context.Context, a cmdExecArgs) any {
			wait := true
			if a.Wait != nil {
				wait = *a.Wait
			}
			port := orDefault(a.Port, 9000)
			timeout := orDefault(a.Timeout, 60)
			effTimeout := timeout
			if !wait && timeout > 15 {
				effTimeout = 15
			}
			log.Printf("cmd_exec CALLED: targets=%v port=%d wait=%v args=%.120q", a.Targets, port, wait, a.Args)
			if len(b.Whitelist) > 0 {
				hit := false
				for _, w := range b.Whitelist {
					if strings.HasPrefix(strings.TrimSpace(a.Args), w) {
						hit = true
						break
					}
				}
				if !hit {
					log.Printf("cmd_exec REJECTED by whitelist (allowed=%v)", b.Whitelist)
					failed := []map[string]any{}
					for _, t := range a.Targets {
						failed = append(failed, map[string]any{"target": t, "reason": "命令不在白名单: " + a.Args})
					}
					return map[string]any{"ok": 0, "failed": failed, "results": []any{}}
				}
			}
			return b.runBatch(ctx, a.Targets, port, LkShell, "", "cmd_exec",
				map[string]any{"args": a.Args, "cwd": a.Cwd, "wait": wait}, false, effTimeout,
				func(c *Client) (any, error) {
					return c.CmdExec(a.Args, a.Cwd, a.Env, wait)
				})
		})

	// 10. capture_start
	add(s, &mcp.Tool{Name: "capture_start", Description: "AF_PACKET 嗅探抓包（datatype 5，CAPTURE 持锁；独立子进程，ps 中无 tcpdump 子进程属正常）。iface 空则取 routeinfo 默认网卡；默认 path 全局共用，多任务请显式传不同 path。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, a captureStartArgs) any {
			sq := true
			if a.SingleQueue != nil {
				sq = *a.SingleQueue
			}
			return b.runBatch(ctx, a.Targets, orDefault(a.Port, 9000), LkCapture,
				orDefaultStr(a.Path, "/home/tmp/tmp.pcap"), "capture_start",
				map[string]any{"iface": a.Iface, "path": orDefaultStr(a.Path, "/home/tmp/tmp.pcap"), "extended": a.Extended, "single_queue": sq},
				false, orDefault(a.Timeout, 30), func(c *Client) (any, error) {
					d, err := c.CaptureStart(a.Iface, orDefaultStr(a.Path, "/home/tmp/tmp.pcap"), a.Extended, sq)
					if err != nil {
						return nil, err
					}
					if res, _ := d["res"].(bool); !res {
						if e, has := d["error"]; has { // 1.7.2+ 兼容分支（v1.8.3 死代码）
							return map[string]any{"_error": e}, nil
						}
						return false, nil // B23 泛化
					}
					return d, nil
				})
		})

	// 11. capture_stop
	add(s, &mcp.Tool{Name: "capture_stop", Description: "停止抓包(datatype 6)。返回四态：stopped/exitcode/pcap_complete；pcap_complete=false 表示 pcap 可能不完整（该 target 记为 failed）；未在抓的路径返回 stopped=false + note（幂等，非错误）。释放 capture_start 持有的 CAPTURE(path) 锁。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), IdempotentHint: true}},
		func(ctx context.Context, a captureStopArgs) any {
			path := orDefaultStr(a.Path, "/home/tmp/tmp.pcap")
			t0 := time.Now()
			results := b.Sched.Batch(b.resolve(a.Targets), orDefault(a.Port, 9000), orDefault(a.Timeout, 30), true, func(c *Client) (any, error) {
				return c.CaptureStop(path)
			})
			okN := 0
			failed := []map[string]any{}
			failedDetails := []map[string]any{}
			out := []map[string]any{}
			outcomes := []map[string]any{}
			for _, r := range results {
				b.Locks.Release(r.Target, LkCapture, path) // 无论成败释放
				outcomes = append(outcomes, map[string]any{"target": r.Target, "ok": r.Ok, "error": r.Err})
				if !r.Ok {
					failed = append(failed, map[string]any{"target": r.Target, "reason": r.Err})
					continue
				}
				d, _ := r.Data.(map[string]any)
				stopped, _ := d["stopped"].(bool)
				errMsg, hasErr := d["error"].(string)
				if stopped && d["pcap_complete"] == false {
					d["warning"] = "pcap 可能不完整/未排序"
					failed = append(failed, map[string]any{"target": r.Target,
						"reason": fmt.Sprintf("pcap 可能不完整/未排序(exitcode=%v)", d["exitcode"])})
					failedDetails = append(failedDetails, mergeMap(map[string]any{"target": r.Target}, d))
					continue
				}
				if !stopped && hasErr && errMsg != "" { // 空串 error = falsy → ok（P2-9）
					failed = append(failed, map[string]any{"target": r.Target, "reason": errMsg})
					failedDetails = append(failedDetails, mergeMap(map[string]any{"target": r.Target}, d))
					continue
				}
				okN++
				out = append(out, mergeMap(map[string]any{"target": r.Target}, d))
			}
			b.Audit.Write("capture_stop", map[string]any{"path": path}, outcomes, okN, len(failed),
				int(time.Since(t0).Milliseconds()), sourceIPFromCtx(ctx))
			resp := map[string]any{"ok": okN, "failed": failed, "results": out}
			if len(failedDetails) > 0 {
				resp["failed_details"] = failedDetails // B03
			}
			return resp
		})

	// 12. boce_run
	add(s, &mcp.Tool{Name: "boce_run", Description: "拨测(datatype 131,BROWSER)。mode 仅\"封堵/重定向\"有判定实现；\"弹窗\"未实现（恒失败）。timeout 一个参数表示两层超时：既约束单靶机整体操作(connect+执行+返回)，拨测内部的 HTTP/goto 预算也取该值扣 10s 余量。下限 10 秒（低于会被拒绝）。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, a boceRunArgs) any {
			port := orDefault(a.Port, 9000)
			if a.Timeout < 10 {
				return allFailed(a.Targets, "timeout 至少 10 秒（Input should be greater than or equal to 10）")
			}
			socketTimeout := a.Timeout + 10
			inner := a.Timeout - 10
			if inner < 3 {
				inner = 3
			}
			return b.runBatch(ctx, a.Targets, port, LkBrowser, "", "boce_run",
				map[string]any{"url": a.Url, "count": orDefault(a.Count, 1), "mode": orDefaultStr(a.Mode, "封堵")}, false, socketTimeout,
				func(c *Client) (any, error) {
					return c.BoceRun(a.Url, orDefault(a.Count, 1), a.Interval, orDefault(a.ThreadCount, 1), inner, orDefaultStr(a.Mode, "封堵"), a.ChromiumPath)
				})
		})

	// 13. replay_run
	add(s, &mcp.Tool{Name: "replay_run", Description: "在靶机回放 pcap 流量文件。需先用 HTTP 上传把 pcap 传到靶机: curl -F \"path=/home/tmp/x.pcap\" -F \"file=@x.pcap\" http://<host>:9001/files。回放与抓包/拨测同靶机互斥;回放+抓包请分属两台靶机(跨机拓扑)。单臂回放（uplink_iface == downlink_iface 且无 VLAN 差异）时所有包计为 uplink，downlink/flow_count 恒 0 属正常，需方向统计用双接口。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, a replayRunArgs) any {
			log.Printf("replay_run CALLED: targets=%v pcaps=%v uplink=%s mbps=%d", a.Targets, a.Pcaps, a.UplinkIface, a.Mbps)
			var fis, fid *string
			if a.ForceIpSrc != "" {
				fis = &a.ForceIpSrc
			}
			if a.ForceIpDst != "" {
				fid = &a.ForceIpDst
			}
			var fs, fd *uint16
			if a.ForceSport != 0 {
				x := uint16(a.ForceSport)
				fs = &x
			}
			if a.ForceDport != 0 {
				x := uint16(a.ForceDport)
				fd = &x
			}
			var upV, downV *uint16
			if a.UplinkVlan != nil {
				x := uint16(*a.UplinkVlan)
				upV = &x
			}
			if a.DownlinkVlan != nil {
				x := uint16(*a.DownlinkVlan)
				downV = &x
			}
			return b.runBatch(ctx, a.Targets, orDefault(a.Port, 9000), LkReplay, "", "replay_run",
				map[string]any{"pcaps": a.Pcaps, "uplink_iface": a.UplinkIface, "downlink_iface": a.DownlinkIface, "mbps": a.Mbps},
				false, orDefault(a.Timeout, 120), func(c *Client) (any, error) {
					return c.ReplayRun(a.Pcaps, a.UplinkIface, a.DownlinkIface, upV, downV, a.Mbps, fis, fid, fs, fd)
				})
		})

	// 14. socket_listen
	add(s, &mcp.Tool{Name: "socket_listen", Description: "在靶机启动 TCP 端口监听接收流量(TCP 监听不接收无握手的裸回放流,回放对比需回放侧重建会话或用 UDP)。action: start=启动返回pid / stop=停止当前监听 / clean=清空已收数据 / save=已收数据保存到靶机文件 / fetch=取回已收数据(超过 max_bytes 落盘靶机并截断返回)。注意: 已在监听时再 start 为幂等操作,返回现有 pid;更换 listen_port 先 stop 再 start;fetch/save 须在 stop 之前。同一监听实例须按 start→...→save/fetch 顺序调用",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, a socketListenArgs) any {
			file := a.File
			if action := a.Action; action == "save" && file == "" {
				return allFailed(a.Targets, "save 动作需要 file 参数")
			} else {
				switch action {
				case "start", "stop", "clean", "save", "fetch":
				default:
					return allFailed(a.Targets, fmt.Sprintf("未知 action: %s", action))
				}
			}
			log.Printf("socket_listen CALLED: targets=%v action=%s listen_port=%d file=%s", a.Targets, a.Action, orDefault(a.ListenPort, 30001), file)
			listenPort := orDefault(a.ListenPort, 30001)
			maxBytes := orDefault(a.MaxBytes, 1048576)
			return b.runBatch(ctx, a.Targets, orDefault(a.Port, 9000), LkSystem, "", "socket_listen",
				map[string]any{"action": a.Action, "listen_port": listenPort, "file": file, "max_bytes": maxBytes},
				false, orDefault(a.Timeout, 30), func(c *Client) (any, error) {
					switch a.Action {
					case "start":
						res, err := c.SocketListen("start", listenPort, "", 0)
						if err != nil {
							return nil, err
						}
						if v, verr := c.Version(); verr == nil && atLeast(v, 1, 7, 1) {
							b.Registry.SetListenLiveness(c.Host, c.Port, true) // B16
						}
						return res, nil
					case "stop":
						res, err := c.SocketListen("stop", 0, "", 0)
						b.Registry.SetListenLiveness(c.Host, c.Port, false)
						return res, err
					case "clean":
						return c.SocketListen("clean", 0, "", 0)
					case "save":
						return c.SocketListen("save", 0, file, 0)
					default: // fetch
						data, err := c.SocketListen("fetch", 0, "", maxBytes)
						if err != nil {
							return nil, err
						}
						raw := data.([]byte)
						result := map[string]any{"size": len(raw)}
						if len(raw) <= maxBytes {
							result["data_b64"] = b64Encode(raw)
							result["truncated"] = false
							return result, nil
						}
						fp := fmt.Sprintf("/home/tmp/listen_%s.log", time.Now().Format("20060102_150405"))
						if _, err := c.SocketListen("save", 0, fp, 0); err != nil {
							return nil, err
						}
						result["data_b64"] = b64Encode(raw[:maxBytes])
						result["truncated"] = true
						result["file_path"] = fp
						return result, nil
					}
				})
		})

	// 15. upgrade_run
	add(s, &mcp.Tool{Name: "upgrade_run", Description: "升级靶机 socket_server（需靶机 1.8.0+，旧靶机请先用 install.sh 安装）。流程:确定版本(指定则零查询/留空查最新)→中央下载→经 :9001 推包→dt20 校验落盘→后台重启→轮询 dt14 确认。升级期间靶机服务重启约 5-15 秒不可用;非 force 且靶机有其它客户端连接时靶机拒绝。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)}},
		func(ctx context.Context, a upgradeRunArgs) any {
			port := orDefault(a.Port, 9000)
			t0 := time.Now()
			targets := b.resolve(a.Targets)
			if len(targets) == 0 {
				return map[string]any{"ok": 0, "version": a.Version, "failed": allFailed(a.Targets, "无有效靶机")["failed"], "results": []any{}}
			}
			ver := strings.TrimLeft(strings.TrimSpace(a.Version), "v")
			if ver != "" {
				if !VersionOK(ver) {
					return map[string]any{"ok": 0, "version": ver,
						"failed":  []map[string]any{{"target": "*", "reason": fmt.Sprintf("版本号非法: %q", ver)}},
						"results": []any{}}
				}
			} else {
				ver = FetchLatestVersion(b.proxyResolved)
				if ver == "" {
					return map[string]any{"ok": 0, "version": "",
						"failed":  []map[string]any{{"target": "*", "reason": "查询最新版失败（GitHub 不可达），可显式指定 version 重试"}},
						"results": []any{}}
				}
			}
			binaryPath, sha, err := EnsureReleaseBinary(ver, b.DownloadDir, b.proxyResolved)
			if err != nil {
				// 下载失败也写审计（六轮验收 P3-1）：此前直接 return，audit_log
				// 空白——失败原因只在 MCP 回执里活一次，事后无从查起，与终态
				// 审计口径（§八.2）不一致。target="*" = 未进入单靶执行阶段。
				b.Audit.Write("upgrade_run", map[string]any{"version": ver, "force": a.Force},
					[]map[string]any{{"target": "*", "ok": false, "error": err.Error()}},
					0, 1, int(time.Since(t0).Milliseconds()), sourceIPFromCtx(ctx))
				return map[string]any{"ok": 0, "version": ver, "failed": []map[string]any{{"target": "*", "reason": err.Error()}}, "results": []any{}}
			}
			log.Printf("upgrade_run: v%s sha=%s... binary=%s targets=%v", ver, sha[:16], binaryPath, targets)

			// 中间段不写审计（Python 未传 audit_tool；仅终态一条，复审 P1-3）
			batch := b.runBatch(ctx, targets, port, LkSystem, "", "",
				map[string]any{"version": ver, "force": a.Force}, false, orDefault(a.Timeout, 60), func(c *Client) (any, error) {
					cur, err := c.Version()
					if err != nil {
						return nil, err
					}
					if !atLeast(cur, 1, 8, 0) {
						return map[string]any{"_error": fmt.Sprintf("靶机 v%s 过旧，请先用 install.sh 安装 1.8.0+", cur)}, nil
					}
					if _, _, perr := PushBinary(c.Host, binaryPath, ver, pushHTTPPort, 300); perr != nil {
						return map[string]any{"_error": perr.Error()}, nil
					}
					resp, err := c.UpgradeApply(ver, sha, a.Force)
					if err != nil {
						// dt20 由靶机切链后自杀式重启收尾：响应与重启存在竞态，
						// EOF/reset 时升级可能已实际完成（2026-11-01 真机两次
						// upgrade_run 均撞到，一次实成一次实败）。标记后照常进入
						// 确认轮询、由 dt14 版本终审判定，不直接记推送失败。
						if isConnLost(err) {
							return map[string]any{"_applyLost": true, "from_version": cur}, nil
						}
						return nil, err
					}
					if e, has := resp["error"].(string); has {
						return map[string]any{"_error": e}, nil
					}
					if resp["ok"] != true {
						return map[string]any{"_error": fmt.Sprintf("无法解析的 dt20 响应: %v", resp)}, nil
					}
					c.Close() // 服务即将重启：close 后归还（死连接 quirk 复刻）
					return map[string]any{"pushed": true, "from_version": cur}, nil
				})

			// 轮询 dt14（180s/3s；rpartition 拆分 quirk：fd00::5 → host="fd00:" port=5）
			var pushed []map[string]any
			if rows, ok := batch["results"].([]map[string]any); ok {
				for _, r := range rows {
					if r["pushed"] == true || r["_applyLost"] == true {
						pushed = append(pushed, r)
					}
				}
			}
			confirmed := map[string]bool{}
			type pendingItem struct {
				target, host string
				port         int
			}
			var pending []pendingItem
			for _, r := range pushed {
				t, _ := r["target"].(string)
				idx := strings.LastIndex(t, ":")
				host, pn := t, port
				if idx > 0 && isAllDigits(t[idx+1:]) {
					host = t[:idx] // rpartition 语义：不剥方括号（quirk 照抄）
					fmt.Sscanf(t[idx+1:], "%d", &pn)
				}
				pending = append(pending, pendingItem{t, host, pn})
			}
			deadline := time.Now().Add(180 * time.Second)
			for len(pending) > 0 && time.Now().Before(deadline) {
				time.Sleep(3 * time.Second)
				var rest []pendingItem
				for _, it := range pending {
					c := NewClient(it.host, it.port, 5)
					// 轮询用一次性 dial：connect 自带重试会把 3s 一轮拖成 18s，
					// 180s 预算只够 10 轮。靶机没起来就下一轮再来。
					if err := c.dialOnce(); err != nil {
						rest = append(rest, it)
						continue
					}
					v, err := c.Version()
					c.Close()
					if err != nil {
						rest = append(rest, it)
						continue
					}
					if v == ver {
						confirmed[it.target] = true
					} else {
						rest = append(rest, it)
					}
				}
				pending = rest
			}
			results := []map[string]any{}
			failed := batch["failed"].([]map[string]any)
			for _, it := range pushed {
				t, _ := it["target"].(string)
				if confirmed[t] {
					results = append(results, map[string]any{"target": t, "upgraded": true,
						"version": ver, "from_version": it["from_version"]})
				} else if it["_applyLost"] == true {
					failed = append(failed, map[string]any{"target": t,
						"reason": "dt20 响应丢失（与靶机重启竞态）且 180 秒内未确认到新版本，升级可能未完成，请查靶机日志 /var/log/socket_server.log"})
				} else {
					failed = append(failed, map[string]any{"target": t,
						"reason": "推送已受理但 180 秒内未确认到新版本（端口未释放/重启异常），请查靶机日志 /var/log/socket_server.log"})
				}
			}
			// 必须带 error：只记 ok:false 的话，失败原因（推包失败 / 建连失败 /
			// 180s 未确认……）在审计里彻底消失，事后只能靠猜。
			outcomes := []map[string]any{}
			for _, r := range results {
				outcomes = append(outcomes, map[string]any{"target": r["target"], "ok": true, "error": ""})
			}
			for _, f := range failed {
				if f["target"] != "*" {
					outcomes = append(outcomes, map[string]any{"target": f["target"], "ok": false, "error": fmt.Sprint(f["reason"])})
				}
			}
			b.Audit.Write("upgrade_run", map[string]any{"version": ver, "force": a.Force},
				outcomes, len(results), len(outcomes)-len(results), int(time.Since(t0).Milliseconds()), sourceIPFromCtx(ctx))
			return map[string]any{"ok": len(results), "version": ver, "failed": failed,
				"results": results, "duration_ms": int(time.Since(t0).Milliseconds())}
		})
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
