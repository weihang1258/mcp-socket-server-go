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
