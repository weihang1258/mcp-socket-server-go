package mcpbridge

// bridge_ 分类：桥自身（方案 §4.11）。
// 注意与 dpi_upgrade 区分：本组升级的是靶机上的 socket_server 自身，不是 DPI 固件。

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bridgeVersionIn struct {
	BaseIn
}

type bridgeUpgradeIn struct {
	BaseIn
	Version string `json:"version,omitempty" jsonschema:"目标版本号如 1.9.1；留空 = 自动查 GitHub 最新版（失败可显式指定重试）"`
	Force   bool   `json:"force,omitempty" jsonschema:"true = 靶机有其它客户端连接时强制升级（会带着连接重启），缺省 false = 拒绝"`
}

type bridgeVersionData struct {
	Version string `json:"version"`
}

type bridgeUpgradeData struct {
	Upgraded    bool   `json:"upgraded"`
	Version     string `json:"version"`
	FromVersion string `json:"from_version,omitempty"`
}

func (b *Bridge) registerBridgeTools(s *mcp.Server) {
	addTyped(s, ro("bridge_version",
		"查靶机上 socket_server（桥的服务端）的版本号（dt14，只读）。升级前先确认各靶机现版本。注意：这不是 DPI 固件版本，DPI 版本用 dpi_get_info。超时缺省 15 秒。"),
		func(ctx context.Context, a bridgeVersionIn) Envelope[bridgeVersionData] {
			return runEnvelope[bridgeVersionData](b, ctx, a.BaseIn, "bridge_version", map[string]any{},
				LkNone, "", true, func(c *Client) (any, error) {
					v, err := c.Version()
					if err != nil {
						return nil, err
					}
					return bridgeVersionData{Version: v}, nil
				})
		})

	addTyped(s, destructive("bridge_upgrade",
		"升级靶机上的 socket_server 自身（不是 DPI 固件，DPI 升级用 dpi_upgrade）。流程：确定版本（指定则零查询/留空查最新）→ 中央下载 → 经 :9001 推包 → dt20 校验落盘 → 后台重启 → 轮询 dt14 确认。升级期间靶机服务重启约 5-15 秒不可用；非 force 且靶机有其它客户端连接时靶机拒绝。需靶机 1.8.0+，更旧的先用 install.sh。超时缺省 60 秒。"),
		func(ctx context.Context, a bridgeUpgradeIn) Envelope[bridgeUpgradeData] {
			return b.runBridgeUpgrade(ctx, a)
		})
}

// runBridgeUpgrade upgrade_run 的完整编排（原样保留语义：下载失败也写审计、
// dt20 响应丢失仍轮询确认、rpartition 拆 host:port 的 quirk）。
func (b *Bridge) runBridgeUpgrade(ctx context.Context, a bridgeUpgradeIn) Envelope[bridgeUpgradeData] {
	port := orDefault(a.Port, 9000)
	t0 := time.Now()
	targets := b.resolve(a.Targets)
	failAll := func(reason string) Envelope[bridgeUpgradeData] {
		return allFailedEnvelope[bridgeUpgradeData](targets, reason, ErrBusiness)
	}
	if len(targets) == 0 {
		return failAll("无有效靶机")
	}
	ver := strings.TrimLeft(strings.TrimSpace(a.Version), "v")
	if ver != "" {
		if !VersionOK(ver) {
			return failAll(fmt.Sprintf("版本号非法: %q", ver))
		}
	} else {
		ver = FetchLatestVersion(b.proxyResolved)
		if ver == "" {
			return failAll("查询最新版失败（GitHub 不可达），可显式指定 version 重试")
		}
	}
	binaryPath, sha, err := EnsureReleaseBinary(ver, b.DownloadDir, b.proxyResolved)
	if err != nil {
		// 下载失败也写审计：否则失败原因只在 MCP 回执里活一次，事后无从查起。
		b.Audit.Write("bridge_upgrade", map[string]any{"version": ver, "force": a.Force},
			[]map[string]any{{"target": "*", "ok": false, "error": err.Error()}},
			0, 1, int(time.Since(t0).Milliseconds()), sourceIPFromCtx(ctx))
		return failAll(err.Error())
	}
	log.Printf("bridge_upgrade: v%s sha=%s... binary=%s targets=%v", ver, sha[:16], binaryPath, targets)

	// 中间段不写审计（仅终态一条）。
	batch := b.runBatchResults(ctx, targets, port, LkSystem, "", false, orDefault(a.Timeout, 60),
		func(c *Client) (any, error) {
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
				// EOF/reset 时升级可能已实际完成。标记后照常进入确认轮询。
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
	type pendingItem struct {
		target, host string
		port         int
	}
	var pending []pendingItem
	var failed []Failure
	for _, r := range batch {
		if !r.Ok {
			et := r.ErrType
			if et == "" {
				et = classifyErr(fmt.Errorf("%s", r.Err))
			}
			failed = append(failed, Failure{Target: r.Target, Reason: r.Err, ErrorType: et})
			continue
		}
		it, _ := r.Data.(map[string]any)
		t := r.Target
		idx := strings.LastIndex(t, ":")
		host, pn := t, port
		if idx > 0 && isAllDigits(t[idx+1:]) {
			host = t[:idx] // rpartition 语义：不剥方括号（quirk 照抄）
			fmt.Sscanf(t[idx+1:], "%d", &pn)
		}
		_ = it
		pending = append(pending, pendingItem{t, host, pn})
	}
	confirmed := map[string]bool{}
	deadline := time.Now().Add(180 * time.Second)
	for len(pending) > 0 && time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		var rest []pendingItem
		for _, it := range pending {
			c := NewClient(it.host, it.port, 5)
			// 轮询用一次性 dial：connect 自带重试会把 3s 一轮拖成 18s。
			if err := c.dialOnce(); err != nil {
				rest = append(rest, it)
				continue
			}
			v, err := c.Version()
			c.Close()
			if err == nil && v == ver {
				confirmed[it.target] = true
			} else {
				rest = append(rest, it)
			}
		}
		pending = rest
	}

	out := Envelope[bridgeUpgradeData]{Results: []Result[bridgeUpgradeData]{}, Failed: []Failure{}, Total: len(targets)}
	out.Failed = append(out.Failed, failed...)
	for _, r := range batch {
		if !r.Ok {
			continue
		}
		it, _ := r.Data.(map[string]any)
		if confirmed[r.Target] {
			from, _ := it["from_version"].(string)
			out.Ok++
			out.Results = append(out.Results, Result[bridgeUpgradeData]{Target: r.Target,
				Data: bridgeUpgradeData{Upgraded: true, Version: ver, FromVersion: from}})
			continue
		}
		reason := "推送已受理但 180 秒内未确认到新版本（端口未释放/重启异常），请查靶机日志 /var/log/socket_server.log"
		if it["_applyLost"] == true {
			reason = "dt20 响应丢失（与靶机重启竞态）且 180 秒内未确认到新版本，升级可能未完成，请查靶机日志 /var/log/socket_server.log"
		}
		out.Failed = append(out.Failed, Failure{Target: r.Target, Reason: reason, ErrorType: ErrBusiness})
	}

	// 审计必须带 error 字段，与 writeAudit 的格式一致。
	outcomes := []map[string]any{}
	for _, r := range out.Results {
		outcomes = append(outcomes, map[string]any{"target": r.Target, "ok": true, "error": ""})
	}
	for _, f := range out.Failed {
		outcomes = append(outcomes, map[string]any{"target": f.Target, "ok": false, "error": f.Reason})
	}
	b.Audit.Write("bridge_upgrade", map[string]any{"version": ver, "force": a.Force},
		outcomes, out.Ok, len(out.Failed), int(time.Since(t0).Milliseconds()), sourceIPFromCtx(ctx))
	return out
}
