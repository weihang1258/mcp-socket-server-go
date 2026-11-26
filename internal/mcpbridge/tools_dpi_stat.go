package mcpbridge

// dpi_ 状态读取与等待（方案 §4.10.2）。
//
// 22 个 Python 解析器收敛为两套解析逻辑（表头逐行 / key: value 逐行）加一张
// kind 映射表；块结构（mirrorvlan / pcapdump / 各 marex 文件 …）先按空行切块，
// 块内再套用同样两套逻辑。所有输出统一为 StatData：Rows[].Name 是主键，
// Fields 保留源文件里的全部字段，不做裁剪、不做判定。

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const shmXsa = "/dev/shm/xsa/"

// statKind 一种 kind 的取数方式与解析模式。
type statKind struct {
	file string // 缺省文件路径（marex 由 resource 决定）
	cmd  string // 取数命令；空 = cat <file>
	mode string // header | kv | block
	// warm 秒：marex 系列原实现先 touch 再 sleep(4) 才读，保留该行为。
	warm time.Duration
}

// statKinds 35 种 kind（方案 §4.10.2 的 23 种 + flow_wait + C2 的 10 种 + raw_text 兜底）。
var statKinds = map[string]statKind{
	// —— 表头逐行 ——
	"xrt":           {file: shmXsa + "xrt.stat", mode: "header"},
	"xrtinfo":       {file: shmXsa + "xrtinfo.stat", cmd: "cat " + shmXsa + "xrtinfo.stat | grep dev -A 15", mode: "header"},
	"port_for_snmp": {file: shmXsa + "port_for_snmp.stat", mode: "header"},
	"httpxdr":       {file: shmXsa + "httpxdr.stat", mode: "header"},
	"xdrtxtlog":     {file: shmXsa + "xdrtxtlog.stat", mode: "header"},
	"xdrtxtlog2":    {file: shmXsa + "xdrtxtlog2.stat", mode: "header"},
	"eublock":       {file: shmXsa + "eublock.stat", mode: "header"},
	"proto_app":     {file: shmXsa + "proto.app.stat", mode: "header"},

	// —— key: value 逐行 ——
	"flow":           {file: shmXsa + "flow.stat", cmd: "cat " + shmXsa + "flow.stat | grep all -A 70", mode: "kv"},
	// wait_flow 场景专用（业务答复 Q2）：concurrent_cnt 在文件 113 行，
	// `grep all -A 70` 窗口会随文件增长断掉；等流超时走直取
	"flow_wait": {file: shmXsa + "flow.stat", cmd: "cat " + shmXsa + "flow.stat | grep concurrent_cnt", mode: "kv"},
	"eu_urlnode":     {file: shmXsa + "eu_urlnode.stat", cmd: "cat " + shmXsa + "eu_urlnode.stat | grep all -A20", mode: "kv"},
	"eu_restore":     {file: shmXsa + "eu_restore.stat", cmd: "cat " + shmXsa + "eu_restore.stat | grep 'all$' -A30", mode: "kv"},
	"eu_policy":      {file: shmXsa + "eu_policy.stat", cmd: "cat " + shmXsa + "eu_policy.stat | grep all -A30", mode: "kv"},
	"adms_idc_debug": {file: shmXsa + "adms_idc_debug.stat", cmd: "cat " + shmXsa + "adms_idc_debug.stat | grep 'worktask: all' -A40", mode: "kv"},
	"eu_output":      {file: shmXsa + "eu_output.stat", cmd: "cat " + shmXsa + "eu_output.stat | grep 'all:' -A50", mode: "kv"},

	// —— 块结构 ——
	"mirrorvlan":   {file: shmXsa + "mirrorvlan.stat", cmd: "cat " + shmXsa + "mirrorvlan.stat | grep total -A50", mode: "block"},
	"pcapdump":     {file: shmXsa + "pcapdump.stat", mode: "block"},
	"uploadfile":   {file: shmXsa + "uploadfile.stat", mode: "block"},
	"msgtask":      {file: shmXsa + "msgtask.stat", mode: "block"},
	"datarpt":      {file: shmXsa + "datarpt.stat", cmd: "cat " + shmXsa + "datarpt.stat | grep 'total :' -A 500", mode: "scope"},
	"datarpt_conn": {file: shmXsa + "datarpt_conn.stat", mode: "block"},
	"commem":       {file: shmXsa + "commem.stat", cmd: "cat " + shmXsa + "commem.stat | grep all -B1", mode: "block"},
	"marex":        {mode: "marex", warm: 4 * time.Second},
	"time_main":    {file: shmXsa + "time_main.stat", mode: "raw"},

	// —— C2 补充（docs/code-review-r2-2026-11-25.md §5.1，格式采自 82 真机）——
	"tcpsegment":       {file: shmXsa + "tcpsegment.stat", mode: "header"},
	"ring":             {file: shmXsa + "ring.stat", mode: "header"},
	"malicious":        {file: shmXsa + "malicious.stat", mode: "header"},
	"evilblock":        {file: shmXsa + "evilblock.stat", mode: "kv"},
	"proto_public":     {file: shmXsa + "proto.public.stat", mode: "header"},
	"mirrorvlan_limit": {file: shmXsa + "mirrorvlan_limit.stat", mode: "mvlimit"},
	"pcapdump_storage": {file: shmXsa + "pcapdump_storage.stat", mode: "header"},
	"eu_overseaip":     {file: shmXsa + "eu_overseaip.stat", mode: "kv"},
	"sysinfo":          {file: shmXsa + "sysinfo.stat", mode: "block"},
	"ext_xrt":          {file: shmXsa + "ext_xrt.stat", mode: "portkv"},
	// 任意 .stat 兜底：path 必填，按行号原样返回
	"raw_text": {mode: "rawtext"},
}

// marexResource marex 一族靠 resource 区分文件（方案 §4.10.2）。
var marexResource = map[string]string{
	"eu_plc":    shmXsa + "marex_eupolicy.stat",
	"pcapdump":  shmXsa + "marex_pcapdump.stat",
	"mirr":      shmXsa + "marex_mirrorvlan.stat",
	"vpn_block": shmXsa + "marex_vpn_block.stat",
}

// ---- 入参 / 出参 ----

type dpiReadStatIn struct {
	BaseIn
	Kind     string `json:"kind" jsonschema:"状态种类：xrt|xrtinfo|port_for_snmp|httpxdr|xdrtxtlog|xdrtxtlog2|eublock|proto_app|flow|flow_wait|eu_urlnode|eu_restore|eu_policy|adms_idc_debug|eu_output|mirrorvlan|pcapdump|uploadfile|msgtask|datarpt|datarpt_conn|commem|marex|time_main|tcpsegment|ring|malicious|evilblock|proto_public|mirrorvlan_limit|pcapdump_storage|eu_overseaip|sysinfo|ext_xrt|raw_text"`
	Resource string `json:"resource,omitempty" jsonschema:"仅 kind 为 marex 用：eu_plc | pcapdump | mirr | vpn_block"`
	Path     string `json:"path,omitempty" jsonschema:"覆盖默认文件路径（缺省取 kind 对应的 /dev/shm/xsa/*.stat）；kind=raw_text 时必填任意 .stat 绝对路径"`
}

type dpiWaitStatIn struct {
	BaseIn
	Kind     string `json:"kind" jsonschema:"状态种类，同 dpi_read_stat（raw_text 除外——兜底无结构化字段，不能等）；flow 等流超时用 flow_wait（concurrent_cnt 直取，不受 grep 窗口限制）"`
	Resource string `json:"resource,omitempty" jsonschema:"仅 kind 为 marex 用"`
	Path     string `json:"path,omitempty" jsonschema:"覆盖默认文件路径"`
	Field    string `json:"field" jsonschema:"要轮询的指标：row 名,或 row.字段名（如 all.fopen_ok；detail.all.marex_amt_loss 这类多段也支持）"`
	Operator string `json:"operator,omitempty" jsonschema:"比较方式：eq（缺省）| ne | gte | lte"`
	Value    string `json:"value" jsonschema:"目标值（按字符串比较；gte/lte 按数值）"`
	EveryS   int    `json:"every_s,omitempty" jsonschema:"轮询间隔秒，缺省 2"`
	WaitS    int    `json:"wait_s,omitempty" jsonschema:"最长等待秒数，缺省 60"`
}

// dpiCleanStatIn / dpiCleanStatData C3 清空 DPI 状态（对齐 dpi.py:190 clean_stat）。
type dpiCleanStatIn struct {
	BaseIn
	Timeout int `json:"timeout,omitempty" jsonschema:"单轮等流超时秒数，缺省 60"`
	Rounds  int `json:"rounds,omitempty" jsonschema:"最大重试轮数，缺省 3（对齐 Python）"`
}

type dpiCleanStatData struct {
	Cleaned  bool   `json:"cleaned" jsonschema:"true 表示 状态已清空（xrt total==0 且流已超时）"`
	Rounds   int    `json:"rounds" jsonschema:"实际执行的轮数"`
	LastRx   string `json:"last_rx" jsonschema:"最后一次采到的 xrt total 收包数"`
	ElapsedS float64 `json:"elapsed_s" jsonschema:"总耗时秒数"`
}

type dpiWaitFileIn struct {
	BaseIn
	Source string `json:"source" jsonschema:"xdrtxtlog（看 fopen_ok 与 fclose_cnt）| datarpt（看 proc_logfile_open_succ 与 proc_upload_file_close）"`
	Mode   string `json:"mode" jsonschema:"open 为 等开始写（两计数不等）| close 为 等写完（两计数相等）"`
	EveryS int    `json:"every_s,omitempty" jsonschema:"轮询间隔秒，缺省 2"`
	WaitS  int    `json:"wait_s,omitempty" jsonschema:"最长等待秒数，缺省 600"`
}

type dpiCheckStalledIn struct {
	BaseIn
	MaxLagS int    `json:"max_lag_s,omitempty" jsonschema:"判定阈值秒：线程时间与设备当前时间差超过它即判卡死，缺省 10"`
	Path    string `json:"path,omitempty" jsonschema:"time_main.stat 路径，缺省 /dev/shm/xsa/time_main.stat"`
}

type dpiWaitStatData struct {
	Ready     bool    `json:"ready" jsonschema:"true 表示指标已达到目标值"`
	LastValue string  `json:"last_value" jsonschema:"最近一次采到的值"`
	Field     string  `json:"field" jsonschema:"观测的字段名"`
	Samples   int     `json:"samples" jsonschema:"采样次数"`
	ElapsedS  float64 `json:"elapsed_s" jsonschema:"耗时秒数"`
	TimedOut  bool    `json:"timed_out,omitempty" jsonschema:"true 表示 超时未达到"`
}

type dpiWaitFileData struct {
	Ready    bool    `json:"ready" jsonschema:"true 表示文件已开始或结束写（取决于 mode）"`
	Left     string  `json:"left" jsonschema:"左计数实际值"`
	Right    string  `json:"right" jsonschema:"右计数实际值"`
	Samples  int     `json:"samples" jsonschema:"轮询采样次数"`
	ElapsedS float64 `json:"elapsed_s" jsonschema:"耗时秒数"`
	TimedOut bool    `json:"timed_out,omitempty" jsonschema:"true 表示 超时未达成"`
}

type dpiStalledData struct {
	Stalled   bool     `json:"stalled" jsonschema:"true 表示判定为卡死"`
	WorstLagS int64    `json:"worst_lag_s" jsonschema:"最落后的线程滞后秒数"`
	DeviceNow int64    `json:"device_now" jsonschema:"设备当前时间"`
	Samples   []string `json:"samples" jsonschema:"采样到的线程数"`
	Threshold int      `json:"threshold_s" jsonschema:"判定卡死的滞后阈值（秒）"`
}

// ---- 解析 ----

var reWord = regexp.MustCompile(`\w+`)

// Python 对表头用三套正则（dpistat.py:58/91/75）：xrt 的列名带小写后缀
// （"Enque fails"），port_for_snmp 带 RX/TX 前缀；其余用 \w+。
var reXrtHead = regexp.MustCompile(`[A-Z]\w+(?: [a-z]+)?`)
var reSnmpHead = regexp.MustCompile(`(?:RX |TX )?\w+`)

// headerRe 按 kind 选表头正则，与 Python 逐字一致。
func headerRe(kind, line string) []string {
	switch kind {
	case "xrt":
		return reXrtHead.FindAllString(line, -1)
	case "port_for_snmp":
		return reSnmpHead.FindAllString(line, -1)
	case "ring":
		// 列名带连字符（IO-WK fails），\w+ 会拆成 4 段导致整行错位；
		// 表头与数据行都是多空格分隔，统一按多空白切列才能对齐
		return splitCols(strings.TrimSpace(line))
	case "tcpsegment", "pcapdump_storage":
		// tcpsegment 真机表头 18 列全部单空格分隔（数据行多空格）——
		// 按单词切正好 18 个列名，与数据 splitCols 的 18 列对齐；
		// pcapdump_storage 列名无空格，reWord 同样安全
		return reWord.FindAllString(line, -1)
	}
	return reWord.FindAllString(line, -1)
}

// splitCols 按 2+ 空白切列（ring/tcpsegment 表头列间都是 2+ 空格，Go RE2 不支持
// 前瞻，直接手写扫描）。
func splitCols(line string) []string {
	var out []string
	start := -1
	gap := 0
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == '\t' {
			if start >= 0 {
				gap++
				if gap == 2 {
					out = append(out, line[start:i-1])
					start = -1
				}
			}
			continue
		}
		if start < 0 {
			start = i
		}
		gap = 0
	}
	if start >= 0 {
		out = append(out, line[start:])
	}
	return out
}

var reTimeField = regexp.MustCompile(`time[:=](\d{9,})`)

// parseHeaderZip 表头逐行：首行取字段名，后续行按空白切分后与表头 zip。
// 首列作为行主键；列数不足的字段直接缺省，多余列丢弃（源文件本身就是文本）。
func parseHeaderZip(lines []string) []StatRow { return parseHeaderZipKind("", lines) }

func parseHeaderZipKind(kind string, lines []string) []StatRow {
	rows := []StatRow{}
	var head []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if head == nil {
			head = headerRe(kind, line)
			continue
		}
		row := StatRow{Name: fields[0], Fields: map[string]string{}}
		// ring/tcpsegment 数据行全多空格，按 splitCols 取列；其余 kind
		// 单空格分隔，Fields 已是列切分（R5 复审 E3：别对每行重复分词）
		dataCols := fields
		if kind == "ring" || kind == "tcpsegment" || kind == "pcapdump_storage" {
			if c := splitCols(strings.TrimSpace(line)); len(c) > 1 {
				dataCols = c
			}
		}
		for i, h := range head[1:] {
			if i < len(dataCols)-1 {
				row.Fields[h] = dataCols[i+1]
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// parseKV key: value 逐行。首行可能是 "all: ..." 这样的作用域行，也一并保留。
func parseKV(lines []string) []StatRow {
	rows := []StatRow{}
	row := StatRow{Name: "all", Fields: map[string]string{}}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 原实现按空白切分后取前两个 token（dpistat.py:110-112）：值里的空格
		// 不会被吞掉，也不会把 "all: 5" 读成键 "all"。这里对齐，
		// 并保留无冒号行（原实现会 KeyError，我们只记 raw 不丢数据）。
		f := strings.Fields(line)
		if idx := strings.Index(line, ":"); idx >= 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			if key == "" {
				continue
			}
			row.Fields[key] = val
			continue
		}
		if len(f) >= 2 {
			row.Fields[strings.TrimSuffix(f[0], ":")] = f[1]
			continue
		}
		row.Fields[f[0]] = ""
	}
	if len(row.Fields) > 0 {
		rows = append(rows, row)
	}
	return rows
}

// parseBlocks 块结构：按空行切块，块内套用 KV / 表头两种逻辑，主键加块前缀
// （block.<i>.<name>）。对不上的行原样放进 raw 字段，绝不丢数据。
func parseBlocks(lines []string) []StatRow {
	var blocks [][]string
	cur := []string{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			if len(cur) > 0 {
				blocks = append(blocks, cur)
				cur = []string{}
			}
			continue
		}
		cur = append(cur, line)
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}

	rows := []StatRow{}
	for bi, blk := range blocks {
		if isTableBlock(blk) {
			rows = append(rows, parseTableBlock(blk, bi)...)
			continue
		}
		if hasColon(blk) {
			for _, r := range parseKV(blk) {
				rows = append(rows, r)
			}
			continue
		}
		// 认不出结构：原样保留，绝不把多行压成一行错位字段
		for li, line := range blk {
			rows = append(rows, StatRow{
				Name:   "block." + strconv.Itoa(bi) + ".line." + strconv.Itoa(li),
				Fields: map[string]string{"raw": strings.TrimSpace(line)},
			})
		}
	}
	return rows
}

// isTableBlock 判定"表头 + 数据行"块（pcapdump / mirrorvlan / commem 这类）：
// 块内没有冒号，且第一行各 token 数与后面的数据行一致。
func isTableBlock(blk []string) bool {
	if len(blk) < 2 || hasColon(blk) {
		return false
	}
	n := len(strings.Fields(blk[0]))
	if n < 2 {
		return false
	}
	for _, line := range blk[1:] {
		if len(strings.Fields(line)) != n {
			return false
		}
	}
	return true
}

func hasColon(blk []string) bool {
	for _, line := range blk {
		if strings.Contains(line, ":") {
			return true
		}
	}
	return false
}

// parseTableBlock 表头型块：每个数据行 → 一行，首列作行名（方案 §1.2 的
// detail.<首列>），字段名取表头其余列。块 2 起是块级汇总，行名 "total"。
func parseTableBlock(blk []string, bi int) []StatRow {
	head := strings.Fields(blk[0])
	rows := []StatRow{}
	for _, line := range blk[1:] {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		fields := map[string]string{}
		for i, h := range head[1:] {
			if i+1 < len(f) {
				fields[h] = f[i+1]
			}
		}
		name := "total"
		if bi == 0 {
			name = "detail." + f[0]
		}
		rows = append(rows, StatRow{Name: name, Fields: fields})
	}
	return rows
}

// parseMarex marex_*.stat 的真实结构（dpistat.py:623-642 marex_eupolicy2dict）：
//
//	块 1（policy）：首行是块名行，其余行以逗号分隔 key value 对；
//	块 2（rule match）：首行 "rule match: total N"，第三行起每行一对 key value。
//
// 只走通用块解析会把这些行整条塞进 raw，dpi_policy_wait 就永远读不到
// policy.total（Python 的 get_policy_total 正是取这个字段）。
// parseScope 解析 datarpt.stat 的嵌套作用域格式（dpistat.py:583-597）：
// 带冒号的行开一个新作用域（"process total :"），不带冒号的行是
// 当前作用域里的 "key value"。与 Python 行为保持一致——冒号行一律当作用域。
func parseScope(lines []string) []StatRow {
	rows := []StatRow{{Name: "all", Fields: map[string]string{}}}
	cur := &rows[0]
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if i := strings.Index(t, ":"); i >= 0 {
			rows = append(rows, StatRow{Name: strings.TrimSpace(t[:i]), Fields: map[string]string{}})
			cur = &rows[len(rows)-1]
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 {
			continue
		}
		cur.Fields[f[0]] = strings.Join(f[1:], " ")
	}
	out := rows[:0]
	for _, r := range rows {
		if len(r.Fields) > 0 {
			out = append(out, r)
		}
	}
	return out
}

func parseMarex(lines []string) []StatRow {
	// 真实格式（dpistat.py:623-642）：
	//   <块名行>
	//   key val, key val, ...            <- policy
	//   <空行>
	//   rule match: total N
	//   <表头行>                          <- 可能缺
	//   <规则ID> <计数>
	// 按内容识别（而不是按行号），空行数量变化也不会错位。
	var policy []string
	var ruleLines []string
	inRule := false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "rule match") {
			inRule = true
			ruleLines = append(ruleLines, t)
			continue
		}
		if inRule {
			ruleLines = append(ruleLines, t)
		} else {
			policy = append(policy, t)
		}
	}

	out := map[string]string{}
	for _, line := range policy {
		for _, field := range strings.Split(line, ",") {
			f := strings.Fields(field)
			if len(f) < 2 {
				continue // 块名行 / 残缺行
			}
			out[f[0]] = f[1]
		}
	}
	rows := []StatRow{{Name: "policy", Fields: out}}
	if len(ruleLines) == 0 {
		return rows
	}

	rule := map[string]string{}
	if i := strings.Index(ruleLines[0], ":"); i >= 0 {
		// "rule match: total 2" 取最后一个 token；也容忍 "rule match: 2"
		if f := strings.Fields(ruleLines[0][i+1:]); len(f) > 0 {
			rule["total"] = f[len(f)-1]
		}
	}
	for _, line := range ruleLines[1:] {
		f := strings.Fields(line)
		if len(f) < 2 || !isAllDigits(f[0]) {
			continue // 表头行
		}
		rows = append(rows, StatRow{Name: "rule." + f[0], Fields: map[string]string{"count": f[1]}})
	}
	return append(rows, StatRow{Name: "rule match", Fields: rule})
}

// parseTimeMain time_main.stat 原项目只有正则 time[:=](16\d+)，没有通用解析器。
// 这里保留全部原始行，同时把能识别的时间戳单列成 time 字段，供 dpi_check_stalled 用。
func parseTimeMain(lines []string) []StatRow {
	rows := []StatRow{}
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		f := map[string]string{"raw": t}
		if m := reTimeField.FindStringSubmatch(t); m != nil {
			f["time"] = m[1]
		}
		name := "line." + strconv.Itoa(i)
		if fields := strings.Fields(t); len(fields) > 0 {
			name = strings.TrimSuffix(fields[0], ":")
		}
		rows = append(rows, StatRow{Name: name, Fields: f})
	}
	return rows
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

// parseMirrorvlanLimit mirrorvlan_limit.stat：每 VLAN 一组 "g active limit reject"
// 表头 + 数据行，行名取 g 编号（0..N）；"per-g flow admission (total):" 段多一列
// speed，也按表头 zip。缩进的表头/数据行都有前导空白，直接 Fields 切分。
func parseMirrorvlanLimit(lines []string) []StatRow {
	rows := []StatRow{}
	var head []string
	seg := "total"
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		// 段标题行切换 seg："worktask: N" → seg=N（detail 段），
		// "per-g flow admission (total):" → seg=total（汇总段）。
		// 其它非数据行（如 "vlan mirror failed" 列头）只清 head，不动 seg
		// ——真机每个 worktask 段里都有这个列头，清 seg 会把 detail 段
		// 全部错标成 total（真机 82 实测踩过）。
		if f[0] != "g" && !isAllDigits(f[0]) {
			head = nil
			if strings.HasPrefix(f[0], "worktask:") && len(f) > 1 {
				seg = f[1]
			} else if strings.HasPrefix(f[0], "per-g") {
				seg = "total"
			}
			continue
		}
		// 表头行：含 "g" 与 "active"
		if f[0] == "g" {
			head = f
			continue
		}
		if head == nil {
			continue
		}
		row := StatRow{Name: seg + "." + f[0], Fields: map[string]string{}}
		// speed 值带单位（"0 bps"），strings.Fields 会拆成两个 token；
		// 按多空白切列保住带空格的值
		cols := f
		if c := splitCols(strings.TrimSpace(line)); len(c) >= len(head) {
			cols = c
		}
		for i, h := range head[1:] {
			if i < len(cols)-1 {
				row.Fields[h] = cols[i+1]
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// parsePortKV ext_xrt.stat："Key: value" 逐行，按 Port: 行切成一段一行
// （每块首字段如 0000:00:0b.0 / total 作行名）。重复键（RX errors 出现两次）
// 后者覆盖前者——与源文件口径一致。
func parsePortKV(lines []string) []StatRow {
	rows := []StatRow{}
	var cur *StatRow
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || t == "==========================================================" {
			continue
		}
		idx := strings.Index(t, ":")
		if idx < 0 {
			continue
		}
		key, val := strings.TrimSpace(t[:idx]), strings.TrimSpace(t[idx+1:])
		if key == "Port" && (cur == nil || cur.Name != val) {
			rows = append(rows, StatRow{Name: val, Fields: map[string]string{}})
			cur = &rows[len(rows)-1]
			continue
		}
		if cur == nil {
			continue
		}
		cur.Fields[key] = val
	}
	return rows
}

// parseRawText raw_text 兜底：不做结构化，行号 + 原文。
func parseRawText(lines []string) []StatRow {
	rows := []StatRow{}
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rows = append(rows, StatRow{
			Name:   "line." + strconv.Itoa(i),
			Fields: map[string]string{"raw": line},
		})
	}
	return rows
}

// statFromText 按 kind 的模式把文本解析成 StatData。
func statFromText(kind, file, text string) StatData {
	lines := splitLines(text)
	var rows []StatRow
	switch statKinds[kind].mode {
	case "header":
		rows = parseHeaderZipKind(kind, lines)
	case "kv":
		rows = parseKV(lines)
	case "block":
		rows = parseBlocks(lines)
	case "marex":
		rows = parseMarex(lines)
	case "scope":
		rows = parseScope(lines)
	case "raw":
		rows = parseTimeMain(lines)
	case "mvlimit":
		rows = parseMirrorvlanLimit(lines)
	case "portkv":
		rows = parsePortKV(lines)
	case "rawtext":
		rows = parseRawText(lines)
	}
	if rows == nil {
		rows = []StatRow{}
	}
	return StatData{Kind: kind, File: file, Rows: rows, Count: len(rows)}
}

// readStat 在靶机上取数并按 kind 解析；marex 保留原实现 touch + sleep(4) 的行为。
func readStat(c *Client, kind, resource, path string) (StatData, error) {
	spec, ok := statKinds[kind]
	if !ok {
		return StatData{}, fmt.Errorf("未知的 kind: %s", kind)
	}
	file := spec.file
	if path != "" {
		file = path
	}
	if kind == "raw_text" {
		if file == "" {
			return StatData{}, fmt.Errorf("kind=raw_text 需要 path（任意 .stat 文件的绝对路径）")
		}
	}
	if kind == "marex" {
		file = path
		if file == "" {
			var found bool
			file, found = marexResource[resource]
			if !found {
				return StatData{}, fmt.Errorf("kind=marex 需要 resource（eu_plc | pcapdump | mirr | vpn_block）")
			}
		}
		// 原实现刻意先 touch 触发刷新再等 4 秒（dpistat.py:628-630）
		if _, err := shell(c, "touch "+shQuote(file)); err != nil {
			return StatData{}, err
		}
		time.Sleep(spec.warm)
	}
	cmd := spec.cmd
	if kind == "marex" || cmd == "" || path != "" {
		cmd = "cat " + shQuote(file)
	}
	out, err := shell(c, cmd)
	if err != nil {
		return StatData{}, err
	}
	if code := intOf(out["code"]); code != 0 {
		return StatData{}, cmdErr(out, fmt.Sprintf("读取 %s 失败: %s", file, strings.TrimSpace(fmt.Sprint(out["stderr"]))))
	}
	return statFromText(kind, file, fmt.Sprint(out["stdout"])), nil
}

// parseStatText 纯函数（单测直接喂文本）。
func parseStatText(kind, file, text string) StatData { return statFromText(kind, file, text) }

// lookupField 在 StatData 里取指标：先按 "row.field"，再按任意行里的 field。
func lookupField(sd StatData, field string) (string, bool) {
	if field == "" {
		return "", false
	}
	if i := strings.LastIndex(field, "."); i > 0 {
		rowName, f := field[:i], field[i+1:]
		for _, r := range sd.Rows {
			if r.Name == rowName {
				if v, ok := r.Fields[f]; ok {
					return v, true
				}
			}
		}
	}
	for _, r := range sd.Rows {
		if v, ok := r.Fields[field]; ok {
			return v, true
		}
		if r.Name == field {
			for _, v := range r.Fields {
				return v, true
			}
		}
	}
	return "", false
}

func compareValues(actual, want, op string) bool {
	switch op {
	case "ne":
		return actual != want
	case "gte", "lte":
		a, errA := strconv.ParseFloat(actual, 64)
		w, errW := strconv.ParseFloat(want, 64)
		if errA != nil || errW != nil {
			return false
		}
		if op == "gte" {
			return a >= w
		}
		return a <= w
	default: // eq
		return actual == want
	}
}

// ---- 工具 ----

func (b *Bridge) registerDpiStatTools(s *mcp.Server) {
	addTyped(s, ro("dpi_read_stat",
		"读 DPI 状态文件",
		"按 kind 读 DPI 状态文件并解析成统一行结构，只读不判定。什么时候用：要看当前值（一次性快照）时用它；要等某个值变化到目标请用 dpi_wait_stat。kind 可选 35 种（见参数说明，含 tcpsegment/ring/malicious/evilblock/proto_public/mirrorvlan_limit/pcapdump_storage/eu_overseaip/sysinfo/ext_xrt、flow_wait（concurrent_cnt 直取）与 raw_text 兜底——raw_text 需 path 传任意 .stat 绝对路径，按行号原样返回）。返回 data{kind,file,rows[],count,truncated}，rows 每项含 name 与 fields。"),
		func(ctx context.Context, a dpiReadStatIn) Envelope[StatData] {
			// 方案 §7：marex（固定 touch + sleep 4）与 eu_output（grep 后解析）给 30 秒
			if a.Timeout == 0 && (a.Kind == "marex" || a.Kind == "eu_output") {
				a.Timeout = 30
			}
			return runEnvelope[StatData](b, ctx, a.BaseIn, "dpi_read_stat",
				map[string]any{"kind": a.Kind, "resource": a.Resource}, LkNone, "", true,
				func(c *Client) (any, error) {
					return readStat(c, a.Kind, a.Resource, a.Path)
				})
		})

	addTyped(s, ro("dpi_wait_stat",
		"等 DPI 指标到目标值",
		"轮询单个 DPI 指标直到达到目标值。什么时候用：下发策略或起停 DPI 后，要确认某指标确实变了（而不是立刻读一次碰运气）时。与 dpi_read_stat 的区别：read 读一次，wait 轮询到满足条件或超时。field 支持 row 名或 row.字段名（如 \"all.fopen_ok\"）；operator 取 eq/ne/gte/lte；value 为目标值，wait_s 为最长等待，every_s 为轮询间隔。"),
		func(ctx context.Context, a dpiWaitStatIn) Envelope[dpiWaitStatData] {
			every := orDefault(a.EveryS, 2)
			wait := orDefault(a.WaitS, 60)
			if every <= 0 || wait <= 0 {
				return allFailedEnvelope[dpiWaitStatData](b.resolve(a.Targets), "every_s 与 wait_s 必须为正整数", ErrBusiness)
			}
			op := orDefaultStr(a.Operator, "eq")
			return runEnvelope[dpiWaitStatData](b, ctx, a.BaseIn, "dpi_wait_stat",
				map[string]any{"kind": a.Kind, "field": a.Field, "operator": op, "value": a.Value},
				LkNone, "", true, func(c *Client) (any, error) {
					start := time.Now()
					out := dpiWaitStatData{Field: a.Field}
					deadline := start.Add(time.Duration(wait) * time.Second)
					for {
						sd, err := readStat(c, a.Kind, a.Resource, a.Path)
						if err != nil {
							return nil, err
						}
						out.Samples++
						v, _ := lookupField(sd, a.Field)
						out.LastValue = v
						if compareValues(v, a.Value, op) {
							out.Ready = true
							out.ElapsedS = time.Since(start).Seconds()
							return out, nil
						}
						if time.Now().After(deadline) {
							out.TimedOut = true
							out.ElapsedS = time.Since(start).Seconds()
							return out, nil
						}
						time.Sleep(time.Duration(every) * time.Second)
					}
				})
		})

	addTyped(s, ro("dpi_wait_file",
		"等 DPI 文件写完",
		"等 DPI 开始或结束写某个文件，通过比较两个计数跨字段判断。什么时候用：要确认 DPI 已经真的开始处理流量（文件在长大）或已经收尾（写完了）时。source=xdrtxtlog 看 fopen_ok 与 fclose_cnt；mode 决定等「开始」还是「结束」。"),
		func(ctx context.Context, a dpiWaitFileIn) Envelope[dpiWaitFileData] {
			every := orDefault(a.EveryS, 2)
			wait := orDefault(a.WaitS, 600)
			if every <= 0 || wait <= 0 {
				return allFailedEnvelope[dpiWaitFileData](b.resolve(a.Targets), "every_s 与 wait_s 必须为正整数", ErrBusiness)
			}
			src := orDefaultStr(a.Source, "xdrtxtlog")
			mode := orDefaultStr(a.Mode, "close")
			var kind, rowName, leftKey, rightKey string
			switch src {
			case "xdrtxtlog":
				kind, rowName, leftKey, rightKey = "xdrtxtlog", "all", "fopen_ok", "fclose_cnt"
			case "datarpt":
				kind, rowName, leftKey, rightKey = "datarpt", "process total", "proc_logfile_open_succ", "proc_upload_file_close"
			default:
				return allFailedEnvelope[dpiWaitFileData](a.Targets, "source 只能是 xdrtxtlog 或 datarpt", ErrBusiness)
			}
			if mode != "open" && mode != "close" {
				return allFailedEnvelope[dpiWaitFileData](a.Targets, "mode 只能是 open 或 close", ErrBusiness)
			}
			return runEnvelope[dpiWaitFileData](b, ctx, a.BaseIn, "dpi_wait_file",
				map[string]any{"source": src, "mode": mode}, LkNone, "", true,
				func(c *Client) (any, error) {
					start := time.Now()
					out := dpiWaitFileData{}
					deadline := start.Add(time.Duration(wait) * time.Second)
					// datarpt 的 mode=open 必须先取基线再判"变了"：上一轮采集若没收尾，
					// 调用前就已是 l != r，只看"不等"会立刻 ready=true
					// （对齐 dpistat.py:705-727 wait_socket_fopen 的 fopen_ok_s 基线）。
					baseL, baseR, hasBase := "", "", false
					for {
						sd, err := readStat(c, kind, "", "")
						if err != nil {
							return nil, err
						}
						out.Samples++
						l := rowField(sd, rowName, leftKey)
						r := rowField(sd, rowName, rightKey)
						out.Left, out.Right = l, r
						equal := l == r && l != ""
						started := !equal && l != "" && r != ""
						if mode == "open" && src == "datarpt" {
							if !hasBase {
								if l != "" && r != "" {
									baseL, baseR, hasBase = l, r, true
								}
								started = false // 首轮只建基线
							} else {
								started = started && (l != baseL || r != baseR)
							}
						}
						if (mode == "close" && equal) || (mode == "open" && started) {
							out.Ready = true
							out.ElapsedS = time.Since(start).Seconds()
							return out, nil
						}
						if time.Now().After(deadline) {
							out.TimedOut = true
							out.ElapsedS = time.Since(start).Seconds()
							return out, nil
						}
						time.Sleep(time.Duration(every) * time.Second)
					}
				})
		})

	addTyped(s, destructive("dpi_clean_stat",
		"清空 DPI 状态",
		"执行 /opt/dpi/cmdmsg xsa 1 清空 DPI 统计，等 flow.stat concurrent_cnt 降为 0（流超时），再校验 xrt.stat total 收包为 0；不满足则重新下发并重试，对齐 Python clean_stat（dpi.py:190）的三轮编排。什么时候用：压测/回放前把计数器归零，让新一轮数据不被上一轮污染。返回 data{cleaned,rounds,last_rx,elapsed_s}。"),
		func(ctx context.Context, a dpiCleanStatIn) Envelope[dpiCleanStatData] {
			timeout := orDefault(a.Timeout, 60)
			rounds := orDefault(a.Rounds, 3)
			if timeout <= 0 || rounds <= 0 {
				return allFailedEnvelope[dpiCleanStatData](b.resolve(a.Targets), "timeout 与 rounds 必须为正整数", ErrBusiness)
			}
			return runEnvelope[dpiCleanStatData](b, ctx, a.BaseIn, "dpi_clean_stat",
				map[string]any{"timeout": timeout, "rounds": rounds}, LkSystem, "", false,
				func(c *Client) (any, error) {
					start := time.Now()
					cmd1 := "sudo /opt/dpi/cmdmsg xsa 1"
					// Python clean_stat（dpiAutoExcel 死代码，从未被业务调用）首轮不发 cmd1、
					// 只等流超时——依赖调用方先手动清空。工具版必须自洽：先下发再验证，
					// 保证"调用即清空"语义（cmd1 幂等，多发无害）。
					if res, err := shell(c, cmd1); err != nil {
						return nil, err
					} else if code := intOf(res["code"]); code != 0 {
						return nil, cmdErr(res, fmt.Sprintf("执行 %s 失败", cmd1))
					}
					out := dpiCleanStatData{}
					for i := 1; i <= rounds; i++ {
						out.Rounds = i
						// 等流超时（wait_flow_timeout，dpi.py:241）：
						// concurrent_cnt 直取（Q2 答复），等不到说明清空没生效或还有活流
						if err := waitFlowTimeout(c, timeout); err != nil {
							return nil, err // "等待流超时失败" 直接判失败（Python 同语义）
						}
						// 校验 xrt total 收包数
						rxOut, err := shell(c, "cat /dev/shm/xsa/xrt.stat |grep total|awk '{print $4}'")
						if err != nil {
							return nil, err
						}
						rx := strings.TrimSpace(fmt.Sprint(rxOut["stdout"]))
						out.LastRx = rx
						if rx == "0" {
							out.Cleaned = true
							out.ElapsedS = time.Since(start).Seconds()
							return out, nil
						}
						// 未归零 → 重新下发清空命令（下发失败立即报错）
						if res, err := shell(c, cmd1); err != nil {
							return nil, err
						} else if code := intOf(res["code"]); code != 0 {
							return nil, cmdErr(res, fmt.Sprintf("执行 %s 失败", cmd1))
						}
						time.Sleep(5 * time.Second)
					}
					out.ElapsedS = time.Since(start).Seconds()
					return out, nil // 轮次用尽未归零：cleaned=false，调用方按需重试
				})
		})

	addTyped(s, ro("dpi_check_stalled",
		"查 DPI 线程卡死",
		"检查 DPI 线程是否卡死：读取各线程的时间戳，与设备当前时间比对，落后超过 max_lag_s 秒判为卡死。什么时候用：怀疑 DPI 无响应、流量不处理时，先跑这个确认。返回 data{stalled,samples,threshold_s,worst_lag_s,device_now}。"),
		func(ctx context.Context, a dpiCheckStalledIn) Envelope[dpiStalledData] {
			threshold := orDefault(a.MaxLagS, 10)
			return runEnvelope[dpiStalledData](b, ctx, a.BaseIn, "dpi_check_stalled",
				map[string]any{"max_lag_s": threshold}, LkNone, "", true,
				func(c *Client) (any, error) {
					sd, err := readStat(c, "time_main", "", a.Path)
					if err != nil {
						return nil, err
					}
					nowOut, err := shell(c, "date +%s")
					if err != nil {
						return nil, err
					}
					// 被杀留空会被读成 now=0，进而把所有线程算成"落后几十年"→ 假卡死
					if _, to := timeoutCleanup(nowOut); to {
						return map[string]any{"_error": "读取设备当前时间超时，无法判定是否卡死"}, nil
					}
					now := intOf2(strings.TrimSpace(fmt.Sprint(nowOut["stdout"])))
					if now == 0 {
						return map[string]any{"_error": "读取设备当前时间失败"}, nil
					}
					out := dpiStalledData{DeviceNow: now, Threshold: threshold, Samples: []string{}}
					for _, r := range sd.Rows {
						tv, ok := r.Fields["time"]
						if !ok {
							continue
						}
						ts := intOf2(tv)
						if ts == 0 {
							continue
						}
						lag := now - ts
						out.Samples = append(out.Samples, fmt.Sprintf("%s=%d", r.Name, lag))
						if lag > out.WorstLagS {
							out.WorstLagS = lag
						}
					}
					out.Stalled = out.WorstLagS > int64(threshold)
					return out, nil
				})
		})
}

// waitFlowTimeout 等 flow.stat concurrent_cnt 降为 0（dpi.py:241 wait_flow_timeout）。
// 用 flow_wait kind 的 grep 直取路径（业务答复 Q2），不受 `grep all -A 70` 窗口限制。
func waitFlowTimeout(c *Client, timeoutS int) error {
	sd, err := readStat(c, "flow_wait", "", "")
	if err != nil {
		return err
	}
	v, _ := lookupField(sd, "concurrent_cnt")
	if v == "0" {
		return nil
	}
	deadline := time.Now().Add(time.Duration(timeoutS) * time.Second)
	for {
		time.Sleep(2 * time.Second)
		if time.Now().After(deadline) {
			return fmt.Errorf("等待流超时失败，等待时间：%ds（concurrent_cnt=%s）", timeoutS, v)
		}
		sd, err = readStat(c, "flow_wait", "", "")
		if err != nil {
			return err
		}
		if v, _ = lookupField(sd, "concurrent_cnt"); v == "0" {
			return nil
		}
	}
}

// rowField 取指定行的指定字段。
func rowField(sd StatData, rowName, key string) string {
	for _, r := range sd.Rows {
		if r.Name == rowName || strings.HasSuffix(r.Name, "."+rowName) {
			return r.Fields[key]
		}
	}
	return ""
}
