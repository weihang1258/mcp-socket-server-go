package mcpbridge

// 23 种 kind 收敛成两套解析逻辑（表头逐行 / key:value）+ 块切分。
// 这里锁住三个纯函数的行为：字段不丢、主键稳定、异常行不外溢。

import "testing"

func TestParseHeaderZip(t *testing.T) {
	text := "name total ok (unit)\nall 10 9\nb 3 2\n"
	sd := parseStatText("xdrtxtlog", "/dev/shm/xsa/xdrtxtlog.stat", text)
	if sd.Count != 2 {
		t.Fatalf("rows=%d: %+v", sd.Count, sd.Rows)
	}
	if sd.Rows[0].Name != "all" || sd.Rows[0].Fields["total"] != "10" || sd.Rows[0].Fields["ok"] != "9" {
		t.Fatalf("首行解析: %+v", sd.Rows[0])
	}
	// 表头里的括号单位不进字段名
	for k := range sd.Rows[0].Fields {
		if k == "unit" || k == "unit)" {
			t.Fatalf("括号单位被当成字段: %v", sd.Rows[0].Fields)
		}
	}
}

// xrt 表头用 [A-Z]\w+(?: [a-z]+)?（dpistat.py:58）："Enque fails" 是一个字段，
// 拆成两列会让后面所有数值整体错位。
func TestParseXrtHeaderKeepsTwoWordColumn(t *testing.T) {
	text := "Dev Enque fails Deque pkts\nxrt0 3 7\n"
	sd := parseStatText("xrt", "/dev/shm/xsa/xrt.stat", text)
	if v := rowField(sd, "xrt0", "Enque fails"); v != "3" {
		t.Fatalf("两词列名: %+v", sd.Rows)
	}
	if v := rowField(sd, "xrt0", "Deque pkts"); v != "7" {
		t.Fatalf("两词列名: %+v", sd.Rows)
	}
}

// port_for_snmp 表头带 RX/TX 前缀（dpistat.py:91）。
func TestParseSnmpHeaderKeepsRxTxPrefix(t *testing.T) {
	text := "port RX pkts TX pkts\neth0 11 22\n"
	sd := parseStatText("port_for_snmp", "/dev/shm/xsa/port_for_snmp.stat", text)
	if v := rowField(sd, "eth0", "RX pkts"); v != "11" {
		t.Fatalf("RX 列: %+v", sd.Rows)
	}
	if v := rowField(sd, "eth0", "TX pkts"); v != "22" {
		t.Fatalf("TX 列: %+v", sd.Rows)
	}
}

func TestParseKVKeepsAllFields(t *testing.T) {
	text := "all:\n  fopen_ok: 12\n  fclose_cnt: 11\n  note\n"
	sd := parseStatText("flow", "/dev/shm/xsa/flow.stat", text)
	if sd.Count != 1 || sd.Rows[0].Name != "all" {
		t.Fatalf("rows=%+v", sd.Rows)
	}
	f := sd.Rows[0].Fields
	if f["fopen_ok"] != "12" || f["fclose_cnt"] != "11" {
		t.Fatalf("字段: %v", f)
	}
	if _, ok := f["note"]; !ok {
		t.Fatalf("无冒号行也不得丢: %v", f)
	}
}

func TestParseBlocksPrefixesRows(t *testing.T) {
	// 真实结构见 dpistat.py:623-642：块 1 首行是块名，其后是逗号分隔的 key value；
	// 块 2 首行是 "rule match: total N"，第二行是表头，之后是 规则ID 计数
	text := "eu policy stat\ntotal 5, rule 3, drop 1\n\nrule match: total 2\nrule_id hit\n1120847 9\n2234567 4\n"
	sd := parseStatText("marex", "/dev/shm/xsa/marex_eupolicy.stat", text)
	if v, ok := lookupField(sd, "policy.total"); !ok || v != "5" {
		t.Fatalf("policy.total（dpi_policy_wait 依赖）: %+v", sd.Rows)
	}
	if v, ok := lookupField(sd, "rule match.total"); !ok || v != "2" {
		t.Fatalf("rule match.total: %+v", sd.Rows)
	}
	if v, ok := lookupField(sd, "rule.1120847.count"); !ok || v != "9" {
		t.Fatalf("规则明细: %+v", sd.Rows)
	}
}

func TestParseScopeNestedDatarpt(t *testing.T) {
	// dpistat.py:583-597 的真实形态：冒号行开作用域，其余是 "key value"
	text := "some total : 5\n  thread 3\nprocess total :\n  proc_logfile_open_succ 12\n  proc_upload_file_close 11\n"
	sd := parseStatText("datarpt", "/dev/shm/xsa/datarpt.stat", text)
	if v := rowField(sd, "process total", "proc_logfile_open_succ"); v != "12" {
		t.Fatalf("嵌套作用域取值错误: %+v", sd.Rows)
	}
	if v := rowField(sd, "process total", "proc_upload_file_close"); v != "11" {
		t.Fatalf("嵌套作用域取值错误: %+v", sd.Rows)
	}
}

func TestParseBlocksTableNotFlattened(t *testing.T) {
	// dpistat.py:314-332 的真实 pcapdump 结构：块 1 是表头 + 多行数据，
	// 块 2 是块级汇总。按 Python 语义 detail[<首列>] / 顶层字段。
	text := "thread pkt_cnt err_cnt\n0 10 0\n1 20 1\n\nwrite_blk pcap_err\n5 0\n"
	sd := parseStatText("pcapdump", "/dev/shm/xsa/pcapdump.stat", text)
	if v := rowField(sd, "detail.0", "pkt_cnt"); v != "10" {
		t.Fatalf("detail.0.pkt_cnt: %+v", sd.Rows)
	}
	if v := rowField(sd, "detail.1", "err_cnt"); v != "1" {
		t.Fatalf("detail.1.err_cnt: %+v", sd.Rows)
	}
	if v := rowField(sd, "total", "pcap_err"); v != "0" {
		t.Fatalf("块级汇总 total.pcap_err: %+v", sd.Rows)
	}
	// 多行不能被压成一行
	if len(sd.Rows) < 3 {
		t.Fatalf("行数不足，疑似被拍平: %+v", sd.Rows)
	}
}

func TestParseTimeMainExtractsTimestamp(t *testing.T) {
	sd := parseStatText("time_main", "/dev/shm/xsa/time_main.stat", "workthread: time=1762300000\n")
	if v := rowField(sd, "workthread", "time"); v != "1762300000" {
		t.Fatalf("time 字段: %+v", sd.Rows)
	}
	if sd.Rows[0].Fields["raw"] == "" {
		t.Fatalf("原始行必须保留: %+v", sd.Rows[0])
	}
}

func TestCompareValues(t *testing.T) {
	cases := []struct {
		a, w, op string
		want     bool
	}{
		{"10", "10", "eq", true},
		{"10", "9", "ne", true},
		{"10", "10", "gte", true},
		{"9", "10", "gte", false},
		{"10", "10", "lte", true},
		{"a", "1", "gte", false}, // 非数值比较不成立，不能静默算真
	}
	for _, c := range cases {
		if got := compareValues(c.a, c.w, c.op); got != c.want {
			t.Fatalf("%s %s %s = %v, want %v", c.a, c.op, c.w, got, c.want)
		}
	}
}

// ---- C2 补充 kind（格式采自 82 真机）----

// 表头型：tcpsegment / ring / malicious / proto_public / pcapdump_storage
func TestParseC2HeaderKinds(t *testing.T) {
	// 真机格式：表头前 3 列单空格连体（worktask lost_cnt up_pkts），第 4 列起
	// 多空格分隔；数据行全多空格。连体列名按一格保留，dn_pkts 起可寻址。
	sd := parseStatText("tcpsegment", "", "worktask lost_cnt up_pkts    dn_pkts\n0        0          1          0\nall      0          2          5\n")
	if v := rowField(sd, "all", "dn_pkts"); v != "5" {
		t.Fatalf("tcpsegment: %+v", sd.Rows)
	}
	// 真机格式：表头与数据行都是多空格分隔
	sd = parseStatText("ring", "", "Port               IO-WK fails        TX-IO fails\n0000:00:0b.0       0                  0\ntotal              0                  1\n")
	if v := rowField(sd, "total", "IO-WK fails"); v != "0" {
		t.Fatalf("ring: %+v", sd.Rows)
	}
	if v := rowField(sd, "total", "TX-IO fails"); v != "1" {
		t.Fatalf("ring TX-IO: %+v", sd.Rows)
	}
	sd = parseStatText("malicious", "", "wtask flow_cnt block_cnt\n0 6 1\nall 7 2\n")
	if v := rowField(sd, "all", "flow_cnt"); v != "7" {
		t.Fatalf("malicious: %+v", sd.Rows)
	}
	sd = parseStatText("proto_public", "", "inner_ppid up_pkts proto_name\n1 25 HTTP\n")
	if v := rowField(sd, "1", "proto_name"); v != "HTTP" {
		t.Fatalf("proto_public: %+v", sd.Rows)
	}
	sd = parseStatText("pcapdump_storage", "", "CommandId StorageAmount\nC1 100\n")
	if v := rowField(sd, "C1", "StorageAmount"); v != "100" {
		t.Fatalf("pcapdump_storage: %+v", sd.Rows)
	}
}

// kv 型：evilblock / eu_overseaip
func TestParseC2KVKinds(t *testing.T) {
	sd := parseStatText("evilblock", "", "all:\nevilblk_sts_need_drop 0\nevilblk_sts_not_proc 25\n")
	if v := rowField(sd, "all", "evilblk_sts_not_proc"); v != "25" {
		t.Fatalf("evilblock: %+v", sd.Rows)
	}
	// 真机格式："worktask: N" 是 KV 内容行（worktask 键、N 值），全部进单行 all
	sd = parseStatText("eu_overseaip", "", "worktask: 0\ndns_no_overseaip: 0\n\nworktask: all\nvpnblock_no_overseaip: 3\n")
	if rowField(sd, "all", "dns_no_overseaip") != "0" || rowField(sd, "all", "vpnblock_no_overseaip") != "3" || rowField(sd, "all", "worktask") != "all" {
		t.Fatalf("eu_overseaip: %+v", sd.Rows)
	}
}

// mirrorvlan_limit：两段（worktask 0 / per-g total），第二段多 speed 列
func TestParseMirrorvlanLimit(t *testing.T) {
	text := `worktask: 0
    g    active             limit              reject
    0    0                  10000              0
    g    active             limit              reject
    1    5                  10000              2

per-g flow admission (total):
    g    active             limit              reject             speed
    0    1                  10000              0                  0 bps
`
	sd := parseStatText("mirrorvlan_limit", "", text)
	if v := rowField(sd, "0.1", "reject"); v != "2" {
		t.Fatalf("第一段: %+v", sd.Rows)
	}
	if v := rowField(sd, "total.0", "speed"); v != "0 bps" {
		t.Fatalf("第二段 speed: %+v", sd.Rows)
	}
}

// ext_xrt：Port: 行开块，重复键后者覆盖
func TestParsePortKVExtXrt(t *testing.T) {
	text := `Port:          0000:00:0b.0
RX pkts:       37
RX errors:     0
TX fails:      0
==========
Port:          total
RX pkts:       40
RX errors:     2
`
	sd := parseStatText("ext_xrt", "", text)
	if v := rowField(sd, "0000:00:0b.0", "RX pkts"); v != "37" {
		t.Fatalf("端口块: %+v", sd.Rows)
	}
	if v := rowField(sd, "total", "RX errors"); v != "2" {
		t.Fatalf("total 块: %+v", sd.Rows)
	}
}

// sysinfo：块结构套 parseBlocks
func TestParseSysinfoBlocks(t *testing.T) {
	text := "cpu type\n  1 io\n  2 wk\n\nnuma msg:0\n"
	sd := parseStatText("sysinfo", "", text)
	if sd.Count == 0 {
		t.Fatalf("sysinfo 应解析出内容: %+v", sd.Rows)
	}
}

// raw_text 兜底：行号 + 原文
func TestParseRawText(t *testing.T) {
	sd := parseStatText("raw_text", "/dev/shm/xsa/whatever.stat", "first line\n\nsecond line\n")
	if sd.Count != 2 {
		t.Fatalf("rows=%d", sd.Count)
	}
	if sd.Rows[0].Name != "line.0" || sd.Rows[0].Fields["raw"] != "first line" {
		t.Fatalf("行号行: %+v", sd.Rows[0])
	}
	if sd.Rows[1].Name != "line.2" {
		t.Fatalf("空行跳过但保留行号: %+v", sd.Rows[1])
	}
}
