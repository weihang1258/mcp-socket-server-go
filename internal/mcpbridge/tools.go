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
	Cfg         BridgeConfig
}

type BridgeConfig struct {
	DBPath         string
	DownloadDir    string
	Proxy          string
	LogLevel       string
	AuditDays      int
	Whitelist      []string
	BindHost       string
	BindPort       int
	DefaultTimeout int
}

// Init 初始化（对齐 init_server：registry/locks/audit 共用 db_path）。
func Init(cfg BridgeConfig) *Bridge {
	b := &Bridge{
		Registry:    mustRegistry(cfg.DBPath),
		Locks:       NewLockManager(),
		Audit:       mustAudit(cfg.DBPath, cfg.AuditDays),
		Sched:       NewScheduler(),
		Whitelist:   cfg.Whitelist,
		DownloadDir: cfg.DownloadDir,
		Proxy:       cfg.Proxy,
		Cfg:         cfg,
	}
	StartDailyCheck(cfg.Proxy, func() string { return BridgeVersion })
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
func (b *Bridge) runBatch(targets []string, port int, class Lk, lockKey string,
	auditTool string, auditParams map[string]any, timeout int,
	fn func(c *Client) (any, error)) map[string]any {
	t0 := time.Now()
	resolved := b.resolve(targets)
	results := make([]TargetResult, len(resolved))

	for i, hp := range resolved {
		host, portN := splitHostPort(hp, port)
		// 1. 锁（fail-fast）
		if class != LkNone {
			if err := b.Locks.TryAcquire(hp, class, lockKey); err != nil {
				results[i] = TargetResult{Target: hp, Ok: false, Err: err.Error()}
				continue
			}
		}
		// 2. 池借出
		pool := b.Sched.GetPool(host, portN)
		c, err := pool.Acquire(10, timeout)
		if err != nil {
			if class != LkNone {
				b.Locks.Release(hp, class, lockKey)
			}
			results[i] = TargetResult{Target: hp, Ok: false, Err: "pool: " + err.Error()}
			continue
		}
		// 3. 执行
		healthy := true
		ok := true
		var data any
		data, err = fn(c)
		if err != nil {
			healthy = false
			ok = false
			results[i] = TargetResult{Target: hp, Ok: false, Err: err.Error()}
		} else {
			switch v := data.(type) {
			case map[string]any:
				if e, has := v["_error"]; has { // 通用失败通道
					ok = false
					results[i] = TargetResult{Target: hp, Ok: false, Err: fmt.Sprint(e)}
					data = nil
				}
			case nil:
				data = map[string]any{"note": "wait=false 为异步执行不返回回显;需要 stdout 请 wait=true"} // B18
			case bool:
				if !v { // B23/B04
					ok = false
					results[i] = TargetResult{Target: hp, Ok: false, Err: "agent 返回 False（业务失败）"}
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
			results[i] = TargetResult{Target: hp, Ok: true, Data: data}
		}
	}

	// audit
	if auditTool != "" {
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
		b.Audit.Write(auditTool, auditParams, outcomes, okN, failN, int(time.Since(t0).Milliseconds()), "internal")
	}

	return assemble(results)
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

// ---- 工具注册（顺序/annotations/描述对齐 server.py:262-786）----

// RegisterTools 注册全部 15 工具。
func (b *Bridge) RegisterTools(s *mcp.Server) {
	type emptyArgs struct{}

	add := func(t *mcp.Tool, h func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any) {
		mcp.AddTool(s, t, func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			return nil, h(ctx, req, args), nil
		})
	}
	ro := func(name, desc string) *mcp.Tool {
		return &mcp.Tool{Name: name, Description: desc, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}
	}
	tg := func(args map[string]any) []string {
		raw, _ := args["targets"].([]any)
		out := make([]string, 0, len(raw))
		for _, x := range raw {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	argInt := func(args map[string]any, key string, def int) int {
		if v, ok := args[key].(float64); ok {
			return int(v)
		}
		return def
	}
	argStr := func(args map[string]any, key, def string) string {
		if v, ok := args[key].(string); ok && v != "" {
			return v
		}
		return def
	}
	_ = emptyArgs{}

	// 1. list_targets
	add(ro("list_targets", "列出已注册的靶机。"), func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
		return map[string]any{"targets": b.Registry.ListTargets()}
	})

	// 2. add_target
	add(&mcp.Tool{Name: "add_target", Description: "注册新靶机。tags 用于 @tag 选机。注册前 TCP 探活（不通拒绝，force=True 跳过）。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			host := argStr(args, "host", "")
			port := argInt(args, "port", 9000)
			force := args["force"] == true
			var tags []string
			if raw, ok := args["tags"].([]any); ok {
				for _, x := range raw {
					if s, ok := x.(string); ok {
						tags = append(tags, s)
					}
				}
			}
			note := argStr(args, "note", "")
			host = strings.Trim(host, "[]")
			if !force {
				if err := probe(host, port, 3); err != nil {
					return map[string]any{"ok": false, "error": fmt.Sprintf("%s:%d 不可达(TCP connect 失败: %v)，未注册；force=True 可强制注册", host, port, err)}
				}
			}
			return b.Registry.AddTarget(host, port, tags, note)
		})

	// 3. remove_target
	add(&mcp.Tool{Name: "remove_target", Description: "移除靶机(有活跃锁或活跃监听时拒绝)。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), IdempotentHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			host := argStr(args, "host", "")
			port := argInt(args, "port", 9000)
			// quirk：锁/liveness/删除键全用原始 host（不剥方括号）
			if b.Locks.HasActive(host) {
				return map[string]any{"ok": false, "error": fmt.Sprintf("靶机 %s 有活跃锁，无法移除", host)}
			}
			if b.Registry.GetListenLiveness(host, port) {
				return map[string]any{"ok": false, "error": fmt.Sprintf("靶机 %s 有活跃监听，请先 socket_listen action=stop", host)}
			}
			return b.Registry.RemoveTarget(host, port)
		})

	// 4. version
	add(ro("version", "查询靶机 socket_server 版本号(datatype 14,只读)。升级前先调本工具确认各靶机现版本，再决定调 upgrade_run 升到哪个版本。"),
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			timeout := argInt(args, "timeout", 15)
			port := argInt(args, "port", 9000)
			out := b.runBatch(tg(args), port, LkNone, "", "", nil, timeout, func(c *Client) (any, error) {
				return c.Version()
			})
			out["results"] = renameField(out["results"], "result", "version")
			return out
		})

	// 5. file_transfer
	add(ro("file_transfer", "获取客户端与靶机之间点对点传文件的命令(零网络调用,纯指引)。上传后需执行权限接 cmd_exec chmod +x。9001 拒绝连接=靶机 http_port=0(配置关闭)或版本 <1.7.0。"),
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			httpPort := argInt(args, "http_port", 9001)
			var cmds []map[string]string
			for _, t := range b.resolve(tg(args)) {
				host := stripPortForURL(t)
				h6 := host
				if strings.Contains(host, ":") {
					h6 = "[" + host + "]"
				}
				cmds = append(cmds, map[string]string{
					"target":   t,
					"download": fmt.Sprintf(`curl -o 本地文件 "http://%s:%d/files?path=<远端绝对路径>"`, h6, httpPort),
					"upload":   fmt.Sprintf(`curl -F "path=<远端绝对路径>" -F "file=@本地文件" http://%s:%d/files`, h6, httpPort),
				})
			}
			if len(cmds) == 0 {
				return map[string]any{"ok": 0, "note": "无已注册靶机,先 add_target 注册再用",
					"usage": []string{
						`下载: curl -o 本地文件 "http://<靶机IP>:9001/files?path=<远端绝对路径>"`,
						`上传: curl -F "path=<远端绝对路径>" -F "file=@本地文件" http://<靶机IP>:9001/files`}}
			}
			return map[string]any{"ok": len(cmds), "commands": cmds}
		})

	// 6. isfile
	add(ro("isfile", "检查靶机文件是否存在(datatype 7,只读)。文件内容的上传下载用 file_transfer 工具(返回点对点直传命令)。"),
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			timeout := argInt(args, "timeout", 15)
			port := argInt(args, "port", 9000)
			path := argStr(args, "path", "")
			out := b.runBatch(tg(args), port, LkNone, "", "", nil, timeout, func(c *Client) (any, error) {
				return c.Isfile(path)
			})
			out["results"] = renameField(out["results"], "result", "exists")
			return out
		})

	// 7. isdir
	add(ro("isdir", "检查目录是否存在(datatype 8,只读)。"),
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			timeout := argInt(args, "timeout", 15)
			port := argInt(args, "port", 9000)
			path := argStr(args, "path", "")
			out := b.runBatch(tg(args), port, LkNone, "", "", nil, timeout, func(c *Client) (any, error) {
				return c.Isdir(path)
			})
			out["results"] = renameField(out["results"], "result", "exists")
			return out
		})

	// 8. pcap_flow_extract
	add(ro("pcap_flow_extract", "提取 pcap 五元组流(datatype 200,只读)。>1000 条截断。protoType: 1=TCP 2=UDP 4=ICMP。"),
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			timeout := argInt(args, "timeout", 30)
			port := argInt(args, "port", 9000)
			pcapDir := argStr(args, "pcap_dir", "")
			resolved := b.resolve(tg(args))
			results := b.Sched.Batch(resolved, port, timeout, func(c *Client) (any, error) {
				return c.PcapFlowExtractRaw(pcapDir)
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
				truncated := false
				if len(flows) > 1000 {
					flows = flows[:1000]
					truncated = true
				}
				out = append(out, map[string]any{"target": r.Target, "flows": flows,
					"total": len(r.Data.([]any)), "truncated": truncated})
			}
			return map[string]any{"ok": okN, "failed": failed, "results": out}
		})

	// 9. cmd_exec
	add(&mcp.Tool{Name: "cmd_exec", Description: "执行命令(datatype 1,SHELL/DANGER,白名单校验后转发)。返回 {code,stdout,stderr};wait=false 为异步执行不返回回显;stdout 超 64KB 截断。白名单为空=不限制（默认）。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			cmdArgs := argStr(args, "args", "")
			cwd := argStr(args, "cwd", "")
			wait := args["wait"] != false
			port := argInt(args, "port", 9000)
			timeout := argInt(args, "timeout", 60)
			effTimeout := timeout
			if !wait {
				if timeout > 15 {
					effTimeout = 15
				}
			}
			log.Printf("cmd_exec CALLED: args=%.120q wait=%v", cmdArgs, wait)
			if len(b.Whitelist) > 0 {
				hit := false
				for _, w := range b.Whitelist {
					if strings.HasPrefix(strings.TrimSpace(cmdArgs), w) {
						hit = true
						break
					}
				}
				if !hit {
					failed := []map[string]any{}
					for _, t := range tg(args) {
						failed = append(failed, map[string]any{"target": t, "reason": "命令不在白名单: " + cmdArgs})
					}
					return map[string]any{"ok": 0, "failed": failed, "results": []any{}}
				}
			}
			return b.runBatch(tg(args), port, LkShell, "", "cmd_exec",
				map[string]any{"args": cmdArgs, "cwd": cwd, "wait": wait}, effTimeout,
				func(c *Client) (any, error) {
					return c.CmdExec(cmdArgs, cwd, nil, wait)
				})
		})

	// 10. capture_start
	add(&mcp.Tool{Name: "capture_start", Description: "AF_PACKET 嗅探抓包（datatype 5，CAPTURE 持锁；独立子进程，ps 中无 tcpdump 子进程属正常）。iface 空则取默认网卡；默认 path 全局共用，多任务请显式传不同 path。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			iface := argStr(args, "iface", "")
			path := argStr(args, "path", "/home/tmp/tmp.pcap")
			extended := argStr(args, "extended", "")
			singleQueue := args["single_queue"] != false
			port := argInt(args, "port", 9000)
			timeout := argInt(args, "timeout", 30)
			return b.runBatch(tg(args), port, LkCapture, path, "capture_start",
				map[string]any{"iface": iface, "path": path, "extended": extended, "single_queue": singleQueue},
				timeout, func(c *Client) (any, error) {
					d, err := c.CaptureStart(iface, path, extended, singleQueue)
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

	// 11. capture_stop（独立实现：四态 + failed_details + 锁无论成败释放）
	add(&mcp.Tool{Name: "capture_stop", Description: "停止抓包(datatype 6)。返回四态：stopped/exitcode/pcap_complete；pcap_complete=false 表示 pcap 可能不完整；未在抓的路径返回 stopped=false + note（幂等）。释放 capture_start 持有的 CAPTURE(path) 锁。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), IdempotentHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			path := argStr(args, "path", "/home/tmp/tmp.pcap")
			port := argInt(args, "port", 9000)
			timeout := argInt(args, "timeout", 30)
			t0 := time.Now()
			resolved := b.resolve(tg(args))
			results := b.Sched.Batch(resolved, port, timeout, func(c *Client) (any, error) {
				return c.CaptureStop(path)
			})
			okN := 0
			failed := []map[string]any{}
			failedDetails := []map[string]any{}
			out := []map[string]any{}
			for _, r := range results {
				b.Locks.Release(r.Target, LkCapture, path) // 无论成败释放
				if !r.Ok {
					failed = append(failed, map[string]any{"target": r.Target, "reason": r.Err})
					continue
				}
				d, _ := r.Data.(map[string]any)
				stopped, _ := d["stopped"].(bool)
				if stopped && d["pcap_complete"] == false {
					d["warning"] = "pcap 可能不完整/未排序"
					failed = append(failed, map[string]any{"target": r.Target,
						"reason": fmt.Sprintf("pcap 可能不完整/未排序(exitcode=%v)", d["exitcode"])})
					failedDetails = append(failedDetails, d)
					continue
				}
				if !stopped {
					if e, has := d["error"].(string); has {
						failed = append(failed, map[string]any{"target": r.Target, "reason": e})
						failedDetails = append(failedDetails, d)
						continue
					}
				}
				okN++
				out = append(out, mergeMap(map[string]any{"target": r.Target}, d))
			}
			outcomes := []map[string]any{}
			for _, f := range out {
				outcomes = append(outcomes, map[string]any{"target": f["target"], "ok": true})
			}
			for _, f := range failed {
				outcomes = append(outcomes, map[string]any{"target": f["target"], "ok": false})
			}
			b.Audit.Write("capture_stop", map[string]any{"path": path}, outcomes, okN, len(failed),
				int(time.Since(t0).Milliseconds()), "internal")
			resp := map[string]any{"ok": okN, "failed": failed, "results": out}
			if len(failedDetails) > 0 {
				resp["failed_details"] = failedDetails // B03：失败也保留结构化
			}
			return resp
		})

	// 12. boce_run
	add(&mcp.Tool{Name: "boce_run", Description: "拨测(datatype 131,BROWSER)。mode 仅\"封堵/重定向\"有判定实现；\"弹窗\"未实现（恒失败）。timeout 一个参数表示两层超时：既约束单靶机整体操作，拨测内部的 HTTP/goto 预算也取该值扣 10s 余量。下限 10 秒。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			url := argStr(args, "url", "")
			count := argInt(args, "count", 1)
			interval := argInt(args, "interval", 0)
			threadCount := argInt(args, "thread_count", 1)
			mode := argStr(args, "mode", "封堵")
			chromium := argStr(args, "chromium_path", "")
			port := argInt(args, "port", 9000)
			timeout := argInt(args, "timeout", 60)
			if timeout < 10 {
				return map[string]any{"ok": 0,
					"failed":  []map[string]any{{"target": "*", "reason": "timeout 至少 10 秒（Input should be greater than or equal to 10）"}},
					"results": []any{}}
			}
			socketTimeout := timeout + 10
			inner := timeout - 10
			if inner < 3 {
				inner = 3
			}
			return b.runBatch(tg(args), port, LkBrowser, "", "boce_run",
				map[string]any{"url": url, "count": count, "mode": mode}, socketTimeout,
				func(c *Client) (any, error) {
					return c.BoceRun(url, count, interval, threadCount, inner, mode, chromium)
				})
		})

	// 13. replay_run
	add(&mcp.Tool{Name: "replay_run", Description: "在靶机回放 pcap 流量文件。需先用 HTTP 上传把 pcap 传到靶机。回放与抓包/拨测同靶机互斥;回放+抓包请分属两台靶机(跨机拓扑)。单臂回放时所有包计为 uplink，downlink/flow_count 恒 0 属正常。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			var pcaps []string
			if raw, ok := args["pcaps"].([]any); ok {
				for _, x := range raw {
					if s, ok := x.(string); ok {
						pcaps = append(pcaps, s)
					}
				}
			}
			upIface := argStr(args, "uplink_iface", "")
			downIface := argStr(args, "downlink_iface", "")
			mbps := argInt(args, "mbps", 0)
			port := argInt(args, "port", 9000)
			timeout := argInt(args, "timeout", 120)
			var upVlan, downVlan *uint16
			if v, ok := args["uplink_vlan"].(float64); ok {
				uv := uint16(v)
				upVlan = &uv
			}
			if v, ok := args["downlink_vlan"].(float64); ok {
				dv := uint16(v)
				downVlan = &dv
			}
			var fis, fid *string
			if v, ok := args["force_ip_src"].(string); ok && v != "" {
				fis = &v
			}
			if v, ok := args["force_ip_dst"].(string); ok && v != "" {
				fid = &v
			}
			var fs, fd *uint16
			if v := argInt(args, "force_sport", 0); v != 0 {
				x := uint16(v)
				fs = &x
			}
			if v := argInt(args, "force_dport", 0); v != 0 {
				x := uint16(v)
				fd = &x
			}
			log.Printf("replay_run CALLED: pcaps=%v uplink=%s mbps=%d", pcaps, upIface, mbps)
			return b.runBatch(tg(args), port, LkReplay, "", "replay_run",
				map[string]any{"pcaps": pcaps, "uplink_iface": upIface, "downlink_iface": downIface, "mbps": mbps},
				timeout, func(c *Client) (any, error) {
					return c.ReplayRun(pcaps, upIface, downIface, upVlan, downVlan, mbps, fis, fid, fs, fd)
				})
		})

	// 14. socket_listen
	add(&mcp.Tool{Name: "socket_listen", Description: "在靶机启动 TCP 端口监听接收流量。action: start=启动返回pid / stop=停止 / clean=清空 / save=保存到靶机文件 / fetch=取回(超 max_bytes 落盘截断)。已在监听时再 start 为幂等;fetch/save 须在 stop 之前。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			action := argStr(args, "action", "")
			listenPort := argInt(args, "listen_port", 30001)
			file := argStr(args, "file", "")
			maxBytes := argInt(args, "max_bytes", 1048576)
			port := argInt(args, "port", 9000)
			timeout := argInt(args, "timeout", 30)
			if action == "save" && file == "" {
				return allFailed(tg(args), "save 动作需要 file 参数")
			}
			switch action {
			case "start", "stop", "clean", "save", "fetch":
			default:
				return allFailed(tg(args), fmt.Sprintf("未知 action: %s", action))
			}
			log.Printf("socket_listen CALLED: action=%s listen_port=%d file=%s", action, listenPort, file)
			return b.runBatch(tg(args), port, LkSystem, "", "socket_listen",
				map[string]any{"action": action, "listen_port": listenPort, "file": file, "max_bytes": maxBytes},
				timeout, func(c *Client) (any, error) {
					switch action {
					case "start":
						res, err := c.SocketListen("start", listenPort, "", 0)
						if err != nil {
							return nil, err
						}
						// B16: 1.7.1+ 登记监听 liveness
						if v, err := c.Version(); err == nil {
							if atLeast(v, 1, 7, 1) {
								b.Registry.SetListenLiveness(c.Host, c.Port, true)
							}
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
						ts := time.Now().Format("20060102_150405")
						fp := fmt.Sprintf("/home/tmp/listen_%s.log", ts)
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
	add(&mcp.Tool{Name: "upgrade_run", Description: "升级靶机 socket_server（需靶机 1.8.0+）。流程:确定版本(指定则零查询/留空查最新)→中央下载→经 :9001 推包→dt20 校验落盘→后台重启→轮询 dt14 确认。升级期间靶机服务重启约 5-15 秒不可用;非 force 且靶机有其它客户端连接时靶机拒绝。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) any {
			version := argStr(args, "version", "")
			force := args["force"] == true
			port := argInt(args, "port", 9000)
			timeout := argInt(args, "timeout", 60)
			t0 := time.Now()
			targets := b.resolve(tg(args))
			if len(targets) == 0 {
				return map[string]any{"ok": 0, "version": version, "failed": allFailed(tg(args), "无有效靶机")["failed"], "results": []any{}}
			}
			ver := strings.TrimLeft(strings.TrimSpace(version), "v")
			if ver != "" {
				if !VersionOK(ver) {
					return map[string]any{"ok": 0, "version": ver,
						"failed":  []map[string]any{{"target": "*", "reason": fmt.Sprintf("版本号非法: %q", ver)}},
						"results": []any{}}
				}
			} else {
				ver = FetchLatestVersion(b.Proxy)
				if ver == "" {
					return map[string]any{"ok": 0, "version": "",
						"failed":  []map[string]any{{"target": "*", "reason": "查询最新版失败（GitHub 不可达），可显式指定 version 重试"}},
						"results": []any{}}
				}
			}
			binaryPath, sha, err := EnsureReleaseBinary(ver, b.DownloadDir, b.Proxy)
			if err != nil {
				return map[string]any{"ok": 0, "version": ver, "failed": []map[string]any{{"target": "*", "reason": err.Error()}}, "results": []any{}}
			}
			log.Printf("upgrade_run: v%s sha=%s... binary=%s targets=%v", ver, sha[:16], binaryPath, targets)

			batch := b.runBatch(targets, port, LkSystem, "", "upgrade_run",
				map[string]any{"version": ver, "force": force}, timeout, func(c *Client) (any, error) {
					cur, err := c.Version()
					if err != nil {
						return nil, err
					}
					parts := parseVer3(cur)
					if parts == nil {
						return map[string]any{"_error": fmt.Sprintf("靶机版本号异常: %q", cur)}, nil
					}
					if verLess(parts, 1, 8, 0) {
						return map[string]any{"_error": fmt.Sprintf("靶机 v%s 过旧，请先用 install.sh 安装 1.8.0+", cur)}, nil
					}
					if _, _, perr := PushBinary(c.Host, binaryPath, ver, 9001, 300); perr != nil {
						return map[string]any{"_error": perr.Error()}, nil
					}
					resp, err := c.UpgradeApply(ver, sha, force)
					if err != nil {
						return nil, err
					}
					if e, has := resp["error"].(string); has {
						return map[string]any{"_error": e}, nil
					}
					if resp["ok"] != true {
						return map[string]any{"_error": fmt.Sprintf("无法解析的 dt20 响应: %v", resp)}, nil
					}
					c.Close() // 服务即将重启：close 后归还，不复用垂死连接
					return map[string]any{"pushed": true, "from_version": cur}, nil
				})

			// 轮询 dt14 确认（180s/3s；短连接新建）
			var pushed []map[string]any
			if rows, ok := batch["results"].([]map[string]any); ok {
				for _, r := range rows {
					if r["pushed"] == true {
						pushed = append(pushed, r)
					}
				}
			}
			confirmed := map[string]bool{}
			var pending []struct {
				target, host string
				port         int
				fromVersion  any
			}
			for _, r := range pushed {
				t, _ := r["target"].(string)
				host, p := splitHostPort(t, port)
				pending = append(pending, struct {
					target, host string
					port         int
					fromVersion  any
				}{t, host, p, r["from_version"]})
			}
			deadline := time.Now().Add(180 * time.Second)
			for len(pending) > 0 && time.Now().Before(deadline) {
				time.Sleep(3 * time.Second)
				var rest []struct {
					target, host string
					port         int
					fromVersion  any
				}
				for _, it := range pending {
					c := NewClient(it.host, it.port, 5)
					if err := c.Connect(); err != nil {
						rest = append(rest, it) // 重启中
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
				} else {
					failed = append(failed, map[string]any{"target": t,
						"reason": "推送已受理但 180 秒内未确认到新版本（端口未释放/重启异常），请查靶机日志 /var/log/socket_server.log"})
				}
			}
			outcomes := []map[string]any{}
			for _, r := range results {
				outcomes = append(outcomes, map[string]any{"target": r["target"], "ok": true})
			}
			for _, f := range failed {
				if f["target"] != "*" {
					outcomes = append(outcomes, map[string]any{"target": f["target"], "ok": false})
				}
			}
			b.Audit.Write("upgrade_run", map[string]any{"version": ver, "force": force},
				outcomes, len(results), len(outcomes)-len(results), int(time.Since(t0).Milliseconds()), "internal")
			return map[string]any{"ok": len(results), "version": ver, "failed": failed,
				"results": results, "duration_ms": int(time.Since(t0).Milliseconds())}
		})
}

// ---- helpers ----

func boolPtr(b bool) *bool { return &b }

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
	for len(out) < 3 {
		out = append(out, 0)
	}
	return out
}

func verLess(parts []int, a, b, c int) bool {
	if len(parts) < 3 {
		return true
	}
	if parts[0] != a {
		return parts[0] < a
	}
	if parts[1] != b {
		return parts[1] < b
	}
	return parts[2] < c
}

func atLeast(v string, a, b, c int) bool {
	p := parseVer3(v)
	return p != nil && !verLess(p, a, b, c)
}

var _ = os.Getenv
