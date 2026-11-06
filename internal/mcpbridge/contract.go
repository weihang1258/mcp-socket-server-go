package mcpbridge

// 工具接入契约（方案 §5.2 / §5.6，v1.3）：
//   统一输入 BaseIn、统一输出信封 Envelope[T]、状态读取统一形状 StatData、
//   超时元数据写进 _meta（default_timeout_s / timeout_basis / danger_level）。
//
// 旧的平铺返回（{ok, results:[{target, ...字段}], failed}）在 15 个存量工具上
// 保留原语义——follow 平台与既有验收脚本按字段名取值，改形状会断链。
// 新增工具一律用 Envelope[T]。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// BaseIn 公共输入（除 target_* / bridge_* / net_set_time 外全部工具继承）。
// 字段顺序即 schema 展示顺序：targets 在最前，description 在最后。
type BaseIn struct {
	Targets     []string `json:"targets" jsonschema:"必填。靶机列表：裸 IP / host:port / @tag"`
	Port        int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口（缺省 9000）"`
	Timeout     int      `json:"timeout,omitempty" jsonschema:"单靶机总耗时上限（秒），缺省见工具描述"`
	Description string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的（进审计与界面），不超过 50 字"`
}

// Failure 单靶机失败行。error_type 三类互斥，均不自动重试（方案 §5.2）。
const (
	ErrNetwork  = "network"  // 建连失败 / 在途断连
	ErrTimeout  = "timeout"  // 到点未完成（工具内部已停）
	ErrBusiness = "business" // 设备返回失败或输出不符合预期
)

type Failure struct {
	Target    string   `json:"target"`
	Reason    string   `json:"reason"`
	ErrorType string   `json:"error_type"`
	Cleanup   *Cleanup `json:"cleanup,omitempty"` // 仅超时填充：agent 是否已杀进程组、是否复查确认
}

// Cleanup 超时后的现场清理回执（方案 §6.2 第 5 条）。verified=false 表示无法
// 确认进程已被杀——调用方不得把它当"环境已释放"。
type Cleanup struct {
	Killed   bool `json:"killed"`
	Verified bool `json:"verified"`
}

// Result 单靶机成功行：data 里是该工具自己的结构。
type Result[T any] struct {
	Target string `json:"target"`
	Data   T      `json:"data"`
}

// Envelope 所有工具的统一输出信封（方案 §1.2）。
type Envelope[T any] struct {
	Ok      int         `json:"ok"`
	Total   int         `json:"total"`
	Results []Result[T] `json:"results"`
	Failed  []Failure   `json:"failed"`
}

// StatRow 状态表一行。Name 是主键：表格式文件取第一列，扁平文件固定 "all"，
// 块结构取 "块名.键"（如 detail.0 / rule.1120847）。
type StatRow struct {
	Name   string            `json:"name"`
	Fields map[string]string `json:"fields"`
}

// StatData 状态读取统一形状（23 种 kind 共用）。源文件有多少字段就返回多少，
// 值一律按字符串——源文件本身是文本，数值口径由调用方解释。
type StatData struct {
	Kind      string    `json:"kind"`
	File      string    `json:"file"`
	Rows      []StatRow `json:"rows"`
	Count     int       `json:"count"`
	Truncated bool      `json:"truncated,omitempty"`
}

// 危险级别（方案 §5.2 danger_level）：仅标识与审计，不拦截。
const (
	DangerRead        = "read"        // 只读
	DangerWrite       = "write"       // 可重复执行的写
	DangerDestructive = "destructive" // 不可逆：删文件、装升级、改设备状态
)

// toolMeta 组装 _meta：调用方不读描述也能拿到超时默认值与依据。
func toolMeta(defaultTimeout int, basis, danger string) mcp.Meta {
	return mcp.Meta{
		"default_timeout_s": defaultTimeout,
		"timeout_basis":     basis,
		"danger_level":      danger,
	}
}

// withMeta 给工具补 _meta（default_timeout_s / timeout_basis / danger_level）。
// 工具名不在两张表里 = 漏登记，直接 panic——契约要求每个工具都有元数据。
var toolBasis = map[string]string{
	"target_list":         "本地 SQLite 查询，无网络往返",
	"target_add":          "内部 TCP 探活 3 秒 + 本地写库（server.py add_target）",
	"target_remove":       "本地操作",
	"file_stat":           "dt7/dt8/dt11 三次轻查询，沿用现有 15 秒",
	"file_list":           "底层 find，原 listdir 无超时，按文件多时变慢估 30",
	"file_mkdir":          "dt9 单次操作",
	"file_remove":         "大目录删除可能耗时，原 rm 无超时",
	"file_get":            "实测 367 MB 经 :9001 耗时 3.1 秒，2 GB 约 17 秒",
	"file_put":            "初值，待最大安装包实测校准（方案 §12 待实证 3）",
	"file_unzip":          "初值，原实现无 deadline，待最大包实测",
	"file_transfer_hint":  "零网络调用，只拼 curl 命令",
	"shell_exec":          "沿用现有 60；wait=false 时上限 15",
	"net_route":           "dt4 一次查询",
	"net_set_mtu":         "dt10 内部改完会 sleep 5 秒",
	"net_set_time":        "两条命令（date -s + hwclock -w）再读回核对",
	"capture_start":       "沿用现有 30",
	"capture_stop":        "沿用现有 30",
	"replay_run":          "50 Mbps × 300 秒 ≈ 1.8 GB；更大包由调用方显式加大",
	"probe_visit":         "沿用现有 60，最小 10；拨测内部扣 10 秒预算",
	"listen_start":        "沿用现有 30",
	"listen_clean":        "沿用现有 30",
	"listen_save":         "沿用现有 30",
	"listen_fetch":        "大数据传输，比控制类慢一倍",
	"listen_stop":         "沿用现有 30",
	"pcap_extract_flows":  "沿用现有 30；最多 1000 条",
	"dpi_get_info":        "四次只读命令（dpi.py:553-612）",
	"dpi_get_config":      "只读小文件（dpi.py:288-440）",
	"dpi_apply_config":    "停 600 + 起 600 + 余量 30",
	"dpi_service":         "restart 最坏 = stop 600 + start 600 + 30（dpi.py:97-148）",
	"dpi_agent_service":   "原 start/stop 各 30 并带轮询，加一倍冗余（dpi.py:715-807）",
	"dpi_switch_mode":     "业务调 mod_switch(timeout=900) + 30（install.py:1317）",
	"dpi_read_stat":       "一次 cat + 本地解析；kind=marex/eu_output 另给 30",
	"dpi_wait_stat":       "原 wait_until 与 wait_alive 默认 60（common.py:366、dpi.py:72）",
	"dpi_wait_file":       "原 wait_fclose 默认 600（dpistat.py:684）；业务显式传 60/100",
	"dpi_check_stalled":   "一次 cat + 一次 date +%s",
	"dpi_policy_get":      "一次读文件（dpi.py:255）",
	"dpi_policy_put":      "一次写小文件（dpi.py:278）",
	"dpi_policy_wait":     "原所有策略等待均为 60（eu_policy.py:267,296,327,366）",
	"dpi_policy_write":    "一次小文件写",
	"dpi_prepare_package": "初值，原实现下载与解压都没有总 deadline（install.py:563-844）",
	"dpi_install":         "mod_switch 900 + 30（install.py:1317）",
	"dpi_upgrade":         "启动 300 + 完成 1200（dpi.py:836,958）",
	"dpi_backup":          "初值，原目录复制无总超时（dpi.py:634）",
	"bridge_version":      "dt14 一次查询，沿用现有 15",
	"bridge_upgrade":      "沿用现有 60",
}

func withMeta(t *mcp.Tool) *mcp.Tool {
	d, okD := toolDefaultTimeout[t.Name]
	dg, okG := toolDanger[t.Name]
	if !okD || !okG {
		panic("工具未登记缺省超时或危险级别: " + t.Name)
	}
	basis := toolBasis[t.Name]
	if basis == "" {
		basis = "见方案 §7 超时缺省总表"
	}
	if t.Meta == nil {
		t.Meta = toolMeta(d, basis, dg)
	}
	return t
}

// 各工具的 danger_level（供测试与文档核对）。
var toolDanger = map[string]string{
	"target_list": DangerRead, "target_add": DangerWrite, "target_remove": DangerDestructive,
	"file_stat": DangerRead, "file_list": DangerRead, "file_mkdir": DangerWrite,
	"file_remove": DangerDestructive, "file_get": DangerRead, "file_put": DangerWrite,
	"file_unzip": DangerWrite, "file_transfer_hint": DangerRead,
	"shell_exec": DangerDestructive,
	"net_route":  DangerRead, "net_set_mtu": DangerDestructive, "net_set_time": DangerDestructive,
	"capture_start": DangerWrite, "capture_stop": DangerWrite,
	"replay_run": DangerDestructive, "probe_visit": DangerRead,
	"listen_start": DangerWrite, "listen_clean": DangerWrite, "listen_save": DangerWrite,
	"listen_fetch": DangerRead, "listen_stop": DangerWrite,
	"pcap_extract_flows": DangerRead,
	"dpi_get_info":       DangerRead, "dpi_get_config": DangerRead, "dpi_apply_config": DangerDestructive,
	"dpi_service": DangerDestructive, "dpi_agent_service": DangerDestructive, "dpi_switch_mode": DangerDestructive,
	"dpi_read_stat": DangerRead, "dpi_wait_stat": DangerRead, "dpi_wait_file": DangerRead, "dpi_check_stalled": DangerRead,
	"dpi_policy_get": DangerRead, "dpi_policy_put": DangerWrite, "dpi_policy_wait": DangerRead, "dpi_policy_write": DangerWrite,
	"dpi_prepare_package": DangerWrite, "dpi_install": DangerDestructive, "dpi_upgrade": DangerDestructive,
	"dpi_backup":     DangerWrite,
	"bridge_version": DangerRead, "bridge_upgrade": DangerDestructive,
}

// 各工具缺省超时（秒），与方案 §7 总表一一对应；测试用它核对 _meta 与行为一致。
var toolDefaultTimeout = map[string]int{
	"target_list": 5, "target_add": 10, "target_remove": 10,
	"file_stat": 15, "file_list": 30, "file_mkdir": 15, "file_remove": 60,
	"file_get": 120, "file_put": 300, "file_unzip": 600, "file_transfer_hint": 5,
	"shell_exec":          60,
	"net_route":           15,
	"net_set_mtu":         30,
	"net_set_time":        30,
	"capture_start":       30,
	"capture_stop":        30,
	"replay_run":          300,
	"probe_visit":         60,
	"listen_start":        30,
	"listen_clean":        30,
	"listen_save":         30,
	"listen_fetch":        60,
	"listen_stop":         30,
	"pcap_extract_flows":  30,
	"dpi_get_info":        15,
	"dpi_get_config":      15,
	"dpi_apply_config":    1230,
	"dpi_service":         1230,
	"dpi_agent_service":   60,
	"dpi_switch_mode":     930,
	"dpi_read_stat":       15,
	"dpi_wait_stat":       60,
	"dpi_wait_file":       600,
	"dpi_check_stalled":   30,
	"dpi_policy_get":      15,
	"dpi_policy_put":      15,
	"dpi_policy_wait":     60,
	"dpi_policy_write":    15,
	"dpi_prepare_package": 600,
	"dpi_install":         930,
	"dpi_upgrade":         1500,
	"dpi_backup":          300,
	"bridge_version":      15,
	"bridge_upgrade":      60,
}

// classifyErr 把一次失败归到 error_type 三类之一。
// 判定顺序：超时 → network（连接类文案）→ business。
func classifyErr(err error) string {
	if err == nil {
		return ErrBusiness
	}
	s := err.Error()
	if isTimeoutMsg(s) {
		return ErrTimeout
	}
	if isConnMsg(s) {
		return ErrNetwork
	}
	return ErrBusiness
}

func isTimeoutMsg(s string) bool {
	return containsAny(s, "超时", "timeout", "deadline exceeded", "i/o timeout")
}

func isConnMsg(s string) bool {
	return containsAny(s, "连接未建立", "连接已断", "connection refused", "connection reset",
		"broken pipe", "EOF", "no route to host", "network is unreachable", "连接池满")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// 工具构造器：Annotations 与 _meta 在这里统一补齐，注册处只写名字和描述。
func boolPtr(b bool) *bool { return &b }

func ro(name, desc string) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: desc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}
}

func write(name, desc string) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: desc,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)}}
}

func destructive(name, desc string) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: desc,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)}}
}

// addTyped 注册带 outputSchema（由 Out 推导）与 _meta 的工具。
func addTyped[In, Out any](s *mcp.Server, t *mcp.Tool, h func(ctx context.Context, args In) Out) {
	mcp.AddTool(s, withMeta(t), func(ctx context.Context, req *mcp.CallToolRequest, args In) (*mcp.CallToolResult, Out, error) {
		return nil, h(ctx, args), nil
	})
}

// envelopeFrom 把逐靶机结果映射成 Envelope[T]（Data 经 JSON 落到 T）。
func envelopeFrom[T any](raw []TargetResult) Envelope[T] {
	out := Envelope[T]{Total: len(raw), Results: []Result[T]{}, Failed: []Failure{}}
	for _, r := range raw {
		if !r.Ok {
			et := r.ErrType
			if et == "" {
				et = classifyErr(errors.New(r.Err))
			}
			f := Failure{Target: r.Target, Reason: r.Err, ErrorType: et}
			if r.Cleanup != nil {
				f.Cleanup = r.Cleanup
			}
			out.Failed = append(out.Failed, f)
			continue
		}
		var t T
		if err := remarshal(r.Data, &t); err != nil {
			out.Failed = append(out.Failed, Failure{Target: r.Target, Reason: "输出不符合工具 schema: " + err.Error(), ErrorType: ErrBusiness})
			continue
		}
		out.Ok++
		out.Results = append(out.Results, Result[T]{Target: r.Target, Data: t})
	}
	return out
}

// runEnvelope 是 runBatch 的 typed 版本：同样的「锁 → 池 → fn → 释放」流程，
// 产出 Envelope[T] 并写一条审计。fn 返回的 data 必须是 T 的 JSON 形态。
func runEnvelope[T any](b *Bridge, ctx context.Context, in BaseIn, tool string, params map[string]any,
	class Lk, lockKey string, retrySafe bool, fn func(c *Client) (any, error)) Envelope[T] {
	t0 := time.Now()
	raw := b.runBatchResults(ctx, in.Targets, orDefault(in.Port, 9000), class, lockKey,
		retrySafe, timeoutFor(in, tool), fn)
	b.writeAudit(ctx, tool, params, raw, t0)
	return envelopeFrom[T](raw)
}

// timeoutFor 取入参 timeout，缺省回落到工具登记表（与 _meta.default_timeout_s 同源）。
func timeoutFor(in BaseIn, tool string) int {
	if in.Timeout > 0 {
		return in.Timeout
	}
	if d, ok := toolDefaultTimeout[tool]; ok {
		return d
	}
	return 30
}

// allFailedEnvelope 全部靶机就地失败（参数校验不通过等，未发出请求）。
func allFailedEnvelope[T any](targets []string, reason, errorType string) Envelope[T] {
	out := Envelope[T]{Total: len(targets), Results: []Result[T]{}, Failed: []Failure{}}
	for _, t := range targets {
		out.Failed = append(out.Failed, Failure{Target: t, Reason: reason, ErrorType: errorType})
	}
	return out
}

// joinTargets 把用户输入的 targets 原样拼成一个可读标签（0 台时用它当 target）。
func joinTargets(targets []string) string { return strings.Join(targets, ",") }

// noResolveReason 「一台都没匹配到」的说明：未知 @tag 与错拼主机走同一句，
// 但把原输入带上，调用方一看就知道是哪个 tag 没展开。
func noResolveReason(targets []string) string {
	const base = "没有匹配到任何靶机"
	if len(targets) == 0 {
		return base + "（targets 为空）"
	}
	return base + "（targets=" + joinTargets(targets) + "，未知 @tag 或未登记的主机）"
}

// emptyResolveEnvelope 不走 runBatchResults 的工具（如纯本地的 file_transfer_hint）
// 也必须给出同样的可见失败，否则 0/0 会被读成"全成功"。
func emptyResolveEnvelope[T any](targets []string) Envelope[T] {
	return Envelope[T]{Total: 1, Results: []Result[T]{}, Failed: []Failure{{
		Target: joinTargets(targets), Reason: noResolveReason(targets), ErrorType: ErrBusiness,
	}}}
}

// shell 在靶机执行一条命令，返回 {code,stdout,stderr}。
func shell(c *Client, cmd string) (map[string]any, error) {
	return c.CmdExec(cmd, "", nil, true)
}

// shQuote 单引号包裹，内嵌单引号转义为 '\”。
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// CmdError 带清理回执的子命令错误：超时时把 agent 的 killed/verified 带出去，
// 不让多步编排的调用方丢掉"靶机上进程是否已停"这一信息（方案 §6.2 第 5 条）。
type CmdError struct {
	Msg     string
	Cleanup *Cleanup
}

func (e *CmdError) Error() string { return e.Msg }

// timeoutCleanup 识别 agent 的超时回执并取出 cleanup。
//
// 为什么不能只看 timeout 键：超时回执是 code=-1，几乎所有子命令行都有
// `code != 0 → _error` 分支。若这些分支先执行，timeout/killed/verified 就被
// 丢掉，整次调用降级成 business 且没有 cleanup——调用方既分不清"设备拒绝"
// 还是"超时被杀"，也不知道靶机上还有没有残留进程。
func timeoutCleanup(m map[string]any) (*Cleanup, bool) {
	// 自带 timeout=true 的（dt0/dt131 回执、listen 系列）直接认
	if t, _ := m["timeout"].(bool); t {
		k, _ := m["killed"].(bool)
		ver, _ := m["verified"].(bool)
		return &Cleanup{Killed: k, Verified: ver}, true
	}
	// 兜底：agent 超时回执一律 code=-1 且带 killed（timeoutGzipFrame 固定形状）；
	// 手工构造的 _error 没有 killed，不会被误判。
	if intOf(m["code"]) != -1 {
		return nil, false
	}
	k, has := m["killed"].(bool)
	if !has {
		return nil, false
	}
	ver, _ := m["verified"].(bool)
	return &Cleanup{Killed: k, Verified: ver}, true
}

// cmdErr 把子命令失败翻成 error：超时回执额外带 CmdError（killed/verified
// 由 runOne 透传到 Failure.cleanup）。
func cmdErr(m map[string]any, msg string) error {
	if cu, timedOut := timeoutCleanup(m); timedOut {
		return &CmdError{Msg: msg, Cleanup: cu}
	}
	return errors.New(msg)
}

// failMap 子命令失败的 _error 回执：超时回执的 timeout/killed/verified 必须原样
// 带进 map，否则 runOne 只看到 _error，会把"超时被杀"归成 business 且丢掉 cleanup。
func failMap(m map[string]any, msg string) map[string]any {
	out := map[string]any{"_error": msg}
	if cu, timedOut := timeoutCleanup(m); timedOut {
		out["timeout"] = true
		out["killed"] = cu.Killed
		out["verified"] = cu.Verified
	}
	return out
}

// shellOK 跑一条子命令：超时/执行异常/非零退出都直接抛错——多步编排里某一步被
// agent 到点杀掉后不能继续往下走（评审：dpi_install 超时后仍回 OK=true）。
func shellOK(c *Client, cmd string) (string, error) {
	m, err := shell(c, cmd)
	if err != nil {
		return "", err
	}
	if cu, timedOut := timeoutCleanup(m); timedOut {
		return "", &CmdError{Msg: "命令超时被终止: " + truncateRunes(cmd, 120), Cleanup: cu}
	}
	if code := intOf(m["code"]); code != 0 {
		msg := strings.TrimSpace(fmt.Sprint(m["stderr"]))
		if msg == "" {
			msg = strings.TrimSpace(fmt.Sprint(m["stdout"]))
		}
		return "", fmt.Errorf("命令退出码 %d: %s", code, truncateRunes(msg, 300))
	}
	return fmt.Sprint(m["stdout"]), nil
}

// ---- 小工具 ----

func remarshal(from any, to any) error {
	raw, err := json.Marshal(from)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, to)
}

func nowRFC3339() string { return time.Now().Format(time.RFC3339) }
