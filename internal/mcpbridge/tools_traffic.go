package mcpbridge

// capture_ / replay_ / probe_ / listen_ / pcap_ 分类（方案 §4.5–§4.9）。

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---- 入参 ----

type captureStartIn struct {
	BaseIn
	Iface       string `json:"iface,omitempty" jsonschema:"网卡名，如 eth0；留空自动取默认路由网卡"`
	Path        string `json:"path,omitempty" jsonschema:"靶机上的 pcap 保存绝对路径，缺省 /home/tmp/tmp.pcap；多任务请显式传不同 path"`
	Extended    string `json:"extended,omitempty" jsonschema:"tcpdump 扩展过滤表达式（留空 为 不过滤）"`
	SingleQueue *bool  `json:"single_queue,omitempty" jsonschema:"true 表示 单队列收包（收包序=线序），缺省 true"`
}

type captureStopIn struct {
	BaseIn
	Path string `json:"path,omitempty" jsonschema:"停止的 pcap 绝对路径，缺省 /home/tmp/tmp.pcap"`
}

type replayIn struct {
	BaseIn
	Pcaps         []string `json:"pcaps" jsonschema:"靶机上 pcap 文件的绝对路径列表，如 [\"/home/tmp/a.pcap\"]（先用 file_put 上传）"`
	UplinkIface   string   `json:"uplink_iface" jsonschema:"上行物理网卡名，如 eth0"`
	DownlinkIface string   `json:"downlink_iface,omitempty" jsonschema:"下行物理网卡名；单臂回放可与上行相同"`
	UplinkVlan    *int     `json:"uplink_vlan,omitempty" jsonschema:"VLAN ID（可选，不给则不打 VLAN 标）"`
	DownlinkVlan  *int     `json:"downlink_vlan,omitempty" jsonschema:"VLAN ID（1-4094）；不给则不打 VLAN 标"`
	Mbps          *int     `json:"mbps,omitempty" jsonschema:"回放限速 Mbps；不传 为 缺省 50；显式传 0 为 不限速（会打满网口）"`
	ForceIPSrc    string   `json:"force_ip_src,omitempty" jsonschema:"强制替换源 IP（可选）"`
	ForceIPDst    string   `json:"force_ip_dst,omitempty" jsonschema:"强制替换目的 IP（可选）"`
	ForceSport    int      `json:"force_sport,omitempty" jsonschema:"强制替换源端口（0 为 不改写）"`
	ForceDport    int      `json:"force_dport,omitempty" jsonschema:"强制替换目的端口（0 为 不改写）"`
}

type probeIn struct {
	BaseIn
	URL          string `json:"url" jsonschema:"拨测目标 URL，如 http://example.com"`
	Count        int    `json:"count,omitempty" jsonschema:"拨测次数，缺省 1"`
	Interval     int    `json:"interval,omitempty" jsonschema:"拨测间隔秒，缺省 0"`
	ThreadCount  int    `json:"thread_count,omitempty" jsonschema:"并发线程数，缺省 1"`
	Mode         string `json:"mode,omitempty" jsonschema:"拨测模式：封堵 / 重定向 有判定实现；弹窗未实现（恒失败）"`
	ChromiumPath string `json:"chromium_path,omitempty" jsonschema:"chromium 可执行文件路径，缺省 /opt/socket/chrome-linux/chrome"`
}

type listenStartIn struct {
	BaseIn
	ListenPort int `json:"listen_port,omitempty" jsonschema:"监听端口，缺省 30001"`
}

type listenSaveIn struct {
	BaseIn
	File string `json:"file" jsonschema:"数据保存到靶机的绝对路径"`
}

type listenFetchIn struct {
	BaseIn
	MaxBytes int `json:"max_bytes,omitempty" jsonschema:"返回明文上限（字节），超限截断并落盘靶机，缺省 1048576"`
}

type pcapFlowsIn struct {
	BaseIn
	PcapDir string `json:"pcap_dir" jsonschema:"靶机上的 pcap 目录绝对路径"`
}

// ---- 出参 ----

type captureStartData struct {
	Started bool `json:"started" jsonschema:"true 表示抓包已启动"`
}

type captureStopData struct {
	Stopped      bool           `json:"stopped" jsonschema:"true 表示抓包已停止（或进程确认不在）"`
	ExitCode     any            `json:"exitcode,omitempty" jsonschema:"抓包进程退出码"`
	PcapComplete *bool          `json:"pcap_complete,omitempty" jsonschema:"true 表示 pcap 文件完整可用；false 表示 可能截断，后续分析结果不可信。为空表示 agent 未上报（老版本）"`
	Legacy       bool           `json:"legacy,omitempty" jsonschema:"true 表示 老版 agent 只回 {res:bool}，没有完整四态信息"`
	Warning      string         `json:"warning,omitempty" jsonschema:"非错误提示，如「该路径本来就没在抓」"`
	Detail       map[string]any `json:"detail,omitempty" jsonschema:"agent 原始回执细节"`
	Cleanup      *Cleanup       `json:"cleanup,omitempty" jsonschema:"停止后的清理回执；verified 为 false 表示无法确认进程已退出，此时抓包锁不会释放"`
}

type probeData map[string]any

type listenStartData struct {
	PID []any `json:"pid" jsonschema:"监听进程 pid 列表；空列表表示端口未绑成功（幂等返回不是错误）"`
}

type listenOKData struct {
	OK bool `json:"ok" jsonschema:"true 表示操作成功"`
}

type listenSaveData struct {
	OK   bool   `json:"ok" jsonschema:"true 表示已写入靶机文件"`
	File string `json:"file" jsonschema:"靶机上的目标文件路径"`
}

type listenFetchData struct {
	Size      int    `json:"size" jsonschema:"取回的数据字节数"`
	DataB64   string `json:"data_b64,omitempty" jsonschema:"数据的 base64 编码；超过 max_bytes 时为空"`
	Truncated bool   `json:"truncated" jsonschema:"true 表示 超过 max_bytes 被截断，完整数据在 file_path"`
	FilePath  string `json:"file_path,omitempty" jsonschema:"完整数据在靶机上的落盘路径（仅截断时有）"`
}

type listenStopData struct {
	Stopped bool     `json:"stopped" jsonschema:"true 表示监听已停止"`
	Cleanup *Cleanup `json:"cleanup,omitempty" jsonschema:"清理回执；verified 为 false 表示无法确认端口已释放"`
}

type pcapFlowsData struct {
	Flows     []any `json:"flows" jsonschema:"五元组流列表"`
	Total     int   `json:"total" jsonschema:"流总数"`
	Truncated bool  `json:"truncated" jsonschema:"true 表示 超过 1000 条已截断"`
}

func (b *Bridge) registerCaptureTools(s *mcp.Server) {
	addTyped(s, write("capture_start",
		"开始抓包",
		"启动靶机抓包，按 path 持锁。什么时候用：需要采集网卡流量做分析或回放对比时，先用它再跑业务流量。iface 留空取默认路由网卡；默认 path 全局共用，多任务务必显式传不同 path 避免互踩。返回 results[].data.started。"),
		func(ctx context.Context, a captureStartIn) Envelope[captureStartData] {
			sq := true
			if a.SingleQueue != nil {
				sq = *a.SingleQueue
			}
			path := orDefaultStr(a.Path, "/home/tmp/tmp.pcap")
			return runEnvelope[captureStartData](b, ctx, a.BaseIn, "capture_start",
				map[string]any{"iface": a.Iface, "path": path, "extended": a.Extended, "single_queue": sq},
				LkCapture, path, false, func(c *Client) (any, error) {
					d, err := c.CaptureStart(a.Iface, path, a.Extended, sq)
					if err != nil {
						return nil, err
					}
					if res, _ := d["res"].(bool); !res {
						if e, has := d["error"]; has { // 1.7.2+ 兼容分支
							return map[string]any{"_error": e}, nil
						}
						return false, nil // B23 泛化
					}
					return captureStartData{Started: true}, nil
				})
		})

	addTyped(s, write("capture_stop",
		"停止抓包",
		"停止靶机抓包并判断 pcap 是否完整。什么时候用：capture_start 之后、要取回 pcap 之前。返回 stopped/pcap_complete/legacy/warning：pcap_complete=true 表示文件完整可用，false 表示可能截断、后续分析结果不可信；stopped=true 或确认进程已不存在才释放抓包锁，否则保留锁并返回 cleanup.verified=false，避免后续任务抢同一路径。未在抓的路径返回 stopped=false + warning，这是幂等结果不是错误。"),
		func(ctx context.Context, a captureStopIn) Envelope[captureStopData] {
			path := orDefaultStr(a.Path, "/home/tmp/tmp.pcap")
			t0 := time.Now()
			raw := b.runBatchResults(ctx, a.Targets, orDefault(a.Port, 9000), LkNone, "", true,
				timeoutFor(a.BaseIn, "capture_stop"), func(c *Client) (any, error) {
					return c.CaptureStop(path)
				})
			// 逐靶机决定是否释放锁、是否判失败
			for i := range raw {
				r := &raw[i]
				if !r.Ok {
					// 方案 §6.3：没确认停止就不放锁。连接失败/超时都不代表靶机上
					// 的抓包进程已经没了，贸然放锁会让后续任务抢同一路径。
					log.Printf("capture_stop: %s 失败（%s），保留 CAPTURE 锁", r.Target, r.Err)
					// §6.2 第 5 条：超时/连接失败无法证明进程已停，必须显式给 verified=false，
					// 不能让调用方把"没回 cleanup"当成环境已释放。
					r.Cleanup = &Cleanup{Killed: false, Verified: false}
					continue
				}
				d, _ := r.Data.(map[string]any)
				stopped, _ := d["stopped"].(bool)
				cu := &Cleanup{Killed: stopped, Verified: stopped}
				// pcap_complete 是"完整"语义，不是"不完整"（HEAD 同款；评审 P1-2 曾取反）
				complete, _ := d["pcap_complete"].(bool)
				_, hasPC := d["pcap_complete"]
				if stopped {
					b.Locks.Release(r.Target, LkCapture, path)
				}
				// 真实 agent 的 dt6 只回 {"res":bool}（agent/handlers.go、handlers.py:162-168），
				// 没有 pcap_complete 四态。legacy 回执按 stopped 判成功，不能要求不存在的键。
				if stopped && !hasPC {
					r.Data = captureStopData{Stopped: true, Legacy: true, Cleanup: cu}
					continue
				}
				if stopped && hasPC && complete {
					r.Data = captureStopData{Stopped: true,
						ExitCode: d["exitcode"], PcapComplete: &complete, Cleanup: cu}
					continue
				}
				if !stopped && d["error"] == nil {
					// 未在抓：幂等成功，但不清锁（本来也没持有）
					r.Data = captureStopData{Stopped: false, Warning: "该路径未在抓包", Cleanup: cu}
					continue
				}
				reason := fmt.Sprint(d["error"])
				if reason == "<nil>" || reason == "" {
					reason = "pcap 可能不完整/未排序"
					if ec, ok := d["exitcode"]; ok {
						reason += fmt.Sprintf("(exitcode=%v)", ec)
					}
				}
				if reason == "" {
					reason = "停止抓包失败"
				}
				r.Ok = false
				r.Err = reason
				r.Data = nil
				if hasPC && !complete {
					cu.Verified = false // pcap 不完整：现场没清干净，不算已验证
				}
				r.Cleanup = cu
				if !stopped {
					// 无法确认进程已停：宁可留锁也不能让下一个任务抢同一路径
					log.Printf("capture_stop: %s 停止结果不明，保留 CAPTURE 锁", r.Target)
				}
			}
			b.writeAudit(ctx, "capture_stop", map[string]any{"path": path}, raw, t0)
			return envelopeFrom[captureStopData](raw)
		})
}

func (b *Bridge) registerTrafficTools(s *mcp.Server) {
	addTyped(s, destructive("replay_run",
		"回放 pcap 流量",
		"在靶机回放 pcap 流量。什么时候用：要复现某段流量、验证策略或对比封堵效果时。前置：先用 file_put 把 pcap 传到靶机，pcaps 填靶机上的绝对路径，如 [\"/home/tmp/a.pcap\"]。回放与抓包/拨测在同一台靶机上互斥，回放+抓包请分属两台靶机。uplink_iface 填上行网卡名（如 \"eth0\"），downlink_iface 填下行网卡；单臂回放时两者可相同，此时下载方向计数恒 0 属正常。mbps 缺省 50，显式传 0 = 不限速（打满网口）。"),
		func(ctx context.Context, a replayIn) Envelope[map[string]any] {
			var fis, fid *string
			if a.ForceIPSrc != "" {
				fis = &a.ForceIPSrc
			}
			if a.ForceIPDst != "" {
				fid = &a.ForceIPDst
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
			mbps := 50 // 原 core/pcap.py:19 的业务缺省
			if a.Mbps != nil {
				mbps = *a.Mbps // 显式 0 = 不限速（agent 侧 r.mbps>0 才限速）
			}
			log.Printf("replay_run CALLED: targets=%v pcaps=%v uplink=%s mbps=%d", a.Targets, a.Pcaps, a.UplinkIface, mbps)
			return runEnvelope[map[string]any](b, ctx, a.BaseIn, "replay_run",
				map[string]any{"pcaps": a.Pcaps, "uplink_iface": a.UplinkIface, "downlink_iface": a.DownlinkIface, "mbps": mbps},
				LkReplay, "", false, func(c *Client) (any, error) {
					m, err := c.ReplayRun(a.Pcaps, a.UplinkIface, a.DownlinkIface, upV, downV, mbps, fis, fid, fs, fd)
					if err != nil {
						return nil, err
					}
					if t, _ := m["timeout"].(bool); t {
						// 回放超时：携带已发统计一起回，避免调用方误以为什么都没发
						k, _ := m["killed"].(bool)
						ver, _ := m["verified"].(bool)
						return map[string]any{
							"_error":   "回放超时，靶机已停止发包",
							"timeout":  true,
							"killed":   k,
							"verified": ver,
						}, nil
					}
					return m, nil
				})
		})

	addTyped(s, ro("probe_visit",
		"浏览器拨测封堵/重定向",
		"用靶机浏览器访问目标 URL，判断封堵或重定向。什么时候用：验证封堵策略是否生效时。mode 目前只有「封堵」「重定向」两种有判定实现，弹窗模式未实现会恒失败。url 必填完整地址如 \"http://example.com\"；count 为拨测次数（缺省 1），thread_count 为并发线程数。timeout 同时约束整体操作与内部 HTTP 预算，下限 10 秒。"),
		func(ctx context.Context, a probeIn) Envelope[probeData] {
			to := orDefault(a.Timeout, 60)
			if to < 10 {
				return allFailedEnvelope[probeData](a.Targets, "timeout 至少 10 秒", ErrBusiness)
			}
			inner := to - 10
			if inner < 3 {
				inner = 3
			}
			a.Timeout = to + 10 // 桥侧 socket 预算比内部宽 10 秒
			return runEnvelope[probeData](b, ctx, a.BaseIn, "probe_visit",
				map[string]any{"url": a.URL, "count": orDefault(a.Count, 1), "mode": orDefaultStr(a.Mode, "封堵")},
				LkBrowser, "", false, func(c *Client) (any, error) {
					m, err := c.BoceRun(a.URL, orDefault(a.Count, 1), a.Interval, orDefault(a.ThreadCount, 1),
						inner, orDefaultStr(a.Mode, "封堵"), a.ChromiumPath)
					if err != nil {
						return nil, err
					}
					if t, _ := m["timeout"].(bool); t {
						k, _ := m["killed"].(bool)
						ver, _ := m["verified"].(bool)
						return map[string]any{"_error": "拨测超时，靶机已关闭浏览器",
							"timeout": true, "killed": k, "verified": ver}, nil
					}
					return m, nil
				})
		})
}

func (b *Bridge) registerListenTools(s *mcp.Server) {
	addTyped(s, write("listen_start",
		"开始端口监听",
		"在靶机启动 TCP 端口监听接收流量。什么时候用：要接收发往靶机某端口的会话流量时。listen_port 填靶机上要监听的端口（如 8080）。已在监听时再调为幂等，返回现有 pid；换端口要先 listen_stop。注意：TCP 监听不接收无握手的裸回放流，回放对比需回放侧重建会话或改用 UDP。"),
		func(ctx context.Context, a listenStartIn) Envelope[listenStartData] {
			port := orDefault(a.ListenPort, 30001)
			log.Printf("listen_start CALLED: targets=%v listen_port=%d", a.Targets, port)
			return runEnvelope[listenStartData](b, ctx, a.BaseIn, "listen_start",
				map[string]any{"listen_port": port}, LkSystem, "", false, func(c *Client) (any, error) {
					res, err := c.SocketListen("start", port, "", 0)
					if err != nil {
						return nil, err
					}
					if v, verr := c.Version(); verr == nil && atLeast(v, 1, 7, 1) {
						b.Registry.SetListenLiveness(c.Host, c.Port, true)
					}
					return toListenStart(res), nil
				})
		})

	addTyped(s, write("listen_clean",
		"清空监听数据",
		"清空靶机已收取的监听数据。什么时候用：同一监听端口要开始新一轮采集、不想混入上一轮数据时。顺序：listen_start → listen_clean? → 业务流量 → listen_save/listen_fetch → listen_stop。"),
		func(ctx context.Context, a BaseIn) Envelope[listenOKData] {
			return runEnvelope[listenOKData](b, ctx, a, "listen_clean", map[string]any{}, LkSystem, "", false,
				func(c *Client) (any, error) {
					if _, err := c.SocketListen("clean", 0, "", 0); err != nil {
						return nil, err
					}
					return listenOKData{OK: true}, nil
				})
		})

	addTyped(s, write("listen_save",
		"监听数据存到靶机",
		"把靶机已收取的监听数据保存到靶机本地文件。什么时候用：数据要留在靶机侧、或稍后再下载时；只要内容回桥侧请用 listen_fetch。必须在 listen_stop 之前调用——stop 之后数据已丢弃。file 填靶机上的绝对路径。"),
		func(ctx context.Context, a listenSaveIn) Envelope[listenSaveData] {
			if a.File == "" {
				return allFailedEnvelope[listenSaveData](a.Targets, "file 必填", ErrBusiness)
			}
			return runEnvelope[listenSaveData](b, ctx, a.BaseIn, "listen_save",
				map[string]any{"file": a.File}, LkSystem, "", false, func(c *Client) (any, error) {
					if _, err := c.SocketListen("save", 0, a.File, 0); err != nil {
						return nil, err
					}
					return listenSaveData{OK: true, File: a.File}, nil
				})
		})

	addTyped(s, ro("listen_fetch",
		"取回监听数据",
		"取回靶机已收取的监听数据到桥侧。什么时候用：需要立刻在桥侧分析收到的流量时；要在靶机留档请用 listen_save。必须在 listen_stop 之前调用。超过 max_bytes 时截断，并把完整数据落盘到靶机、返回 file_path。"),
		func(ctx context.Context, a listenFetchIn) Envelope[listenFetchData] {
			maxBytes := orDefault(a.MaxBytes, 1048576)
			return runEnvelope[listenFetchData](b, ctx, a.BaseIn, "listen_fetch",
				map[string]any{"max_bytes": maxBytes}, LkSystem, "", true, func(c *Client) (any, error) {
					data, err := c.SocketListen("fetch", 0, "", maxBytes)
					if err != nil {
						return nil, err
					}
					raw := data.([]byte)
					out := listenFetchData{Size: len(raw)}
					if len(raw) <= maxBytes {
						out.DataB64 = b64Encode(raw)
						return out, nil
					}
					// 先截断再编码：完整数据可能上百 MB，编码整份再丢掉是白烧内存
					out.DataB64 = b64Encode(raw[:maxBytes])
					fp := fmt.Sprintf("/home/tmp/listen_%s.log", time.Now().Format("20060102_150405"))
					if _, err := c.SocketListen("save", 0, fp, 0); err != nil {
						return nil, err
					}
					out.Truncated = true
					out.FilePath = fp
					return out, nil
				})
		})

	addTyped(s, write("listen_stop",
		"停止端口监听",
		"停止靶机端口监听并清理占端口的进程。什么时候用：采集结束、或要换端口重新 listen_start 之前。返回 stopped 与 cleanup.verified（true 表示已确认进程不在）。"),
		func(ctx context.Context, a BaseIn) Envelope[listenStopData] {
			return runEnvelope[listenStopData](b, ctx, a, "listen_stop", map[string]any{}, LkSystem, "", false,
				func(c *Client) (any, error) {
					res, err := c.SocketListen("stop", 0, "", 0)
					if err != nil {
						return nil, err // Python server.py:639-643：stop 抛错则不执行 liveness 清除
					}
					// §6.3：agent 只有确认 pid 都没了才回 "ok"（listen.go:listenStop），
					// 失败时回 {"error"} 已被 okOrErr 变成 err。所以走到这里 = 已确认停止。
					_ = res // res 恒为 "ok"（okOrErr 的唯一成功返回）
					b.Registry.SetListenLiveness(c.Host, c.Port, false)
					return listenStopData{Stopped: true,
						Cleanup: &Cleanup{Killed: true, Verified: true}}, nil
				})
		})
}

func (b *Bridge) registerPcapTools(s *mcp.Server) {
	addTyped(s, ro("pcap_extract_flows",
		"从 pcap 提五元组流",
		"从靶机 pcap 目录直接提取五元组流，不下载 pcap 文件。什么时候用：只要流统计、查误封，不需要 pcap 原件时，比 file_get 下载后本地解析快得多。pcap_dir 填靶机上的目录路径。返回流数统计，最多 1000 条，truncated=true 表示已截断。"),
		func(ctx context.Context, a pcapFlowsIn) Envelope[pcapFlowsData] {
			return runEnvelope[pcapFlowsData](b, ctx, a.BaseIn, "pcap_extract_flows",
				map[string]any{"pcap_dir": a.PcapDir}, LkNone, "", true, func(c *Client) (any, error) {
					flows, err := c.PcapFlowExtractRaw(a.PcapDir)
					if err != nil {
						return nil, err
					}
					if flows == nil {
						flows = []any{}
					}
					total := len(flows)
					truncated := false
					if total > 1000 {
						flows = flows[:1000]
						truncated = true
					}
					return pcapFlowsData{Flows: flows, Total: total, Truncated: truncated}, nil
				})
		})
}

// toListenStart 把 agent 的 start 回执（可能是 map 或 []pid）归一成 {pid[]}。
// toListenStart 把 agent 的 {"pid":["111"]} 摊平成 {pid:[...]}。
// 评审 P3-2：早先对 map 直接包一层，pid 变成了 [["111"]]。
func toListenStart(res any) listenStartData {
	out := listenStartData{PID: []any{}}
	switch v := res.(type) {
	case map[string]any:
		switch p := v["pid"].(type) {
		case []any:
			out.PID = p
		case nil:
		default:
			out.PID = []any{p}
		}
	case []any:
		out.PID = v
	}
	return out
}
