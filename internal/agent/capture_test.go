package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ---- 测试用 fake 包源 ----

type fakeSource struct {
	mu     sync.Mutex
	frames [][]byte // 待收取帧（含 OOB 分离存放）
	oobs   [][]byte
	closed chan struct{}
	reads  int
	onRead func()
}

func newFakeSource() *fakeSource { return &fakeSource{closed: make(chan struct{})} }

func (f *fakeSource) push(frame, oob []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames = append(f.frames, frame)
	f.oobs = append(f.oobs, oob)
}

func (f *fakeSource) recvFrame(b []byte, deadline time.Time) (int, []byte, error) {
	for {
		f.mu.Lock()
		if len(f.frames) > 0 {
			fr := f.frames[0]
			f.frames = f.frames[1:]
			oob := f.oobs[0]
			f.oobs = f.oobs[1:]
			f.reads++
			f.mu.Unlock()
			n := copy(b, fr)
			return n, oob, nil
		}
		f.mu.Unlock()
		if !deadline.IsZero() && time.Now().After(deadline) {
			return 0, nil, errTimeout
		}
		select {
		case <-f.closed:
			return 0, nil, io.EOF
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (f *fakeSource) close() error { close(f.closed); return nil }

func (f *fakeSource) stats() (uint64, uint64) { return 0, 0 }

var errTimeout = timeoutErr{}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "timeout" }
func (timeoutErr) Timeout() bool { return true }

// ---- cmsg 构造（对齐内核 ABI）----

func cmsgTimestamping(hwSec, hwNsec, swSec, swNsec int64) []byte {
	// 64 位 ABI：cmsghdr{len u64@0, level i32@8, type i32@12} + 3×timespec(16B)
	b := make([]byte, 16+48)
	binary.LittleEndian.PutUint64(b[0:], 64)
	binary.LittleEndian.PutUint32(b[8:], 1) // SOL_SOCKET
	binary.LittleEndian.PutUint32(b[12:], 37)
	binary.LittleEndian.PutUint64(b[16:], uint64(hwSec))
	binary.LittleEndian.PutUint64(b[24:], uint64(hwNsec))
	binary.LittleEndian.PutUint64(b[32:], uint64(swSec))
	binary.LittleEndian.PutUint64(b[40:], uint64(swNsec))
	return b
}

func cmsgAuxdata(tci uint16) []byte {
	// 64 位 ABI：cmsghdr{len u64@0, level i32@8, type i32@12} + tpacket_auxdata(20B)
	b := make([]byte, 16+20)
	binary.LittleEndian.PutUint64(b[0:], 36)
	binary.LittleEndian.PutUint32(b[8:], 263) // SOL_PACKET
	binary.LittleEndian.PutUint32(b[12:], 8)  // PACKET_AUXDATA
	// tp_status: VLAN_VALID(0x10) 置位
	binary.LittleEndian.PutUint32(b[16:], 0x10)
	// tp_vlan_tci @ offset 16+12
	binary.LittleEndian.PutUint16(b[16+12:], tci)
	return b
}

func testEthPayload() []byte {
	eth := make([]byte, 60)
	for i := range eth {
		eth[i] = byte(i)
	}
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	return eth
}

// ---- 用例 ----

func captureTestStart(t *testing.T, src *fakeSource, path string) (bool, error) {
	t.Helper()
	prev := openPacketSocketFn
	openPacketSocketFn = func(eth string) (pktSource, error) { return src, nil }
	t.Cleanup(func() { openPacketSocketFn = prev })
	return tcpdumpStart("eth0", path, "", true)
}

// dt5：正常启动 → {"res":true}；同 path 重启先停旧
func TestCaptureStartStopCycle(t *testing.T) {
	resetCapture(t)
	path := filepath.Join(t.TempDir(), "cap.pcap")
	src := newFakeSource()
	if ok, _ := captureTestStart(t, src, path); !ok {
		t.Fatal("start want true")
	}
	// 帧 → pcap 落盘
	src.push(testEthPayload(), nil)
	time.Sleep(150 * time.Millisecond)
	if resp, err := runDT(t, 6, mustJSON(t, map[string]string{"path": path})); err != nil || string(resp) != `{"res":true}` {
		t.Fatalf("dt6: %q %v", resp, err)
	}
	// pcap 内容：全局头 ns magic + 记录
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(data[:4]) != 0xA1B23C4D {
		t.Fatalf("want ns magic, got %x", data[:4])
	}
	if len(data) < 24+16+60 {
		t.Fatalf("pcap too small: %d", len(data))
	}
	if binary.LittleEndian.Uint32(data[24+8:]) != 60 {
		t.Fatalf("incl_len want 60")
	}
	// 幂等 stop：未在抓 stopped=true res:true
	if resp, _ := runDT(t, 6, mustJSON(t, map[string]string{"path": path})); string(resp) != `{"res":true}` {
		t.Fatalf("idempotent stop: %q", resp)
	}
}

// dt5 同 path 已在抓：先停旧再启新
func TestCaptureRestartSamePath(t *testing.T) {
	resetCapture(t)
	path := filepath.Join(t.TempDir(), "cap.pcap")
	src1 := newFakeSource()
	if ok, _ := captureTestStart(t, src1, path); !ok {
		t.Fatal("first start")
	}
	src2 := newFakeSource()
	prev := openPacketSocketFn
	openPacketSocketFn = func(string) (pktSource, error) { return src2, nil }
	if ok, _ := tcpdumpStart("eth0", path, "", true); !ok {
		t.Fatal("second start")
	}
	openPacketSocketFn = prev
	if resp, _ := runDT(t, 6, mustJSON(t, map[string]string{"path": path})); string(resp) != `{"res":true}` {
		t.Fatal("stop after restart")
	}
	// 旧实例已停：push 不再写入
	src1.push(testEthPayload(), nil)
	time.Sleep(100 * time.Millisecond)
}

// dt5 失败：socket 打不开 → {"res":false}（无 error 字段，回退后契约）
func TestCaptureStartFail(t *testing.T) {
	resetCapture(t)
	prev := openPacketSocketFn
	openPacketSocketFn = func(string) (pktSource, error) { return nil, errors.New("permission denied") }
	t.Cleanup(func() { openPacketSocketFn = prev })
	resp, err := runDT(t, 5, mustJSON(t, map[string]string{"eth": "eth0", "path": "/tmp/x.pcap"}))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != `{"res":false}` {
		t.Fatalf("want res:false no error, got %q", resp)
	}
}

// BPF 编译失败（tcpdump 不可用）→ 启动失败 res:false
func TestCaptureBPFUnavailableFails(t *testing.T) {
	resetCapture(t)
	fake := t.TempDir()
	t.Setenv("PATH", fake) // 无 tcpdump
	prev := openPacketSocketFn
	openPacketSocketFn = func(string) (pktSource, error) { return newFakeSource(), nil }
	t.Cleanup(func() { openPacketSocketFn = prev })
	resp, err := runDT(t, 5, mustJSON(t, map[string]string{"eth": "eth0", "path": "/tmp/y.pcap", "extended": "port 80"}))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != `{"res":false}` {
		t.Fatalf("BPF fail want res:false, got %q", resp)
	}
}

// BPF 编译成功：tcpdump -ddd 输出注入（fake tcpdump 记录表达式并回指令）
func TestCaptureBPFParsed(t *testing.T) {
	resetCapture(t)
	fake := t.TempDir()
	t.Setenv("PATH", fake)
	calls := filepath.Join(fake, "tcpdump.calls")
	os.WriteFile(filepath.Join(fake, "tcpdump"), []byte(
		"#!/bin/sh\necho \"$@\" >> "+calls+"\necho \"2\"\necho \"96 0 0 0\"\necho \"0 0 0 262144\"\n"), 0o755)
	src := newFakeSource()
	prev := openPacketSocketFn
	var gotBPF []bpfInstr
	setBPFCapture(func(ins []bpfInstr) { gotBPF = ins }) // compileBPF 先于 open socket
	openPacketSocketFn = func(string) (pktSource, error) { return src, nil }
	t.Cleanup(func() { openPacketSocketFn = prev; setBPFCapture(nil) })
	if ok, _ := tcpdumpStart("eth0", filepath.Join(t.TempDir(), "z.pcap"), "port 80", true); !ok {
		t.Fatal("start with BPF")
	}
	data, _ := os.ReadFile(calls)
	if !bytes.Contains(data, []byte("port 80")) || !bytes.Contains(data, []byte("-ddd")) {
		t.Fatalf("tcpdump -ddd not invoked right: %q", data)
	}
	if len(gotBPF) != 2 || gotBPF[1].K != 0x40000 {
		t.Fatalf("BPF instr parse wrong: %+v", gotBPF)
	}
}

// 停止 drain 语义：stop 前已进队列的帧全部落盘后才关文件
func TestCaptureStopDrainsQueue(t *testing.T) {
	resetCapture(t)
	path := filepath.Join(t.TempDir(), "drain.pcap")
	src := newFakeSource()
	if ok, _ := captureTestStart(t, src, path); !ok {
		t.Fatal("start")
	}
	// 立刻塞 3 帧并马上 stop（帧可能尚未被 recv 线程读走）
	for i := 0; i < 3; i++ {
		src.push(testEthPayload(), nil)
	}
	if resp, _ := runDT(t, 6, mustJSON(t, map[string]string{"path": path})); string(resp) != `{"res":true}` {
		t.Fatal("stop")
	}
	data, _ := os.ReadFile(path)
	// 至少全局头；drain 语义下 queued 帧应尽收（宽松：≥1 帧）
	if len(data) < 24+16+60 {
		t.Fatalf("drain lost frames: %d bytes", len(data))
	}
}

// VLAN 还原：auxdata tci → offset 12 插 4B 标签
func TestCaptureVLANRestore(t *testing.T) {
	resetCapture(t)
	path := filepath.Join(t.TempDir(), "vlan.pcap")
	src := newFakeSource()
	if ok, _ := captureTestStart(t, src, path); !ok {
		t.Fatal("start")
	}
	src.push(testEthPayload(), cmsgAuxdata(100))
	time.Sleep(150 * time.Millisecond)
	runDT(t, 6, mustJSON(t, map[string]string{"path": path}))
	data, _ := os.ReadFile(path)
	rec := data[24+16:] // 第一帧数据
	if binary.BigEndian.Uint16(rec[12:]) != 0x8100 {
		t.Fatalf("VLAN tag not restored: %x", rec[12:16])
	}
	if binary.BigEndian.Uint16(rec[14:]) != 100 {
		t.Fatalf("tci wrong: %x", rec[14:16])
	}
	if binary.BigEndian.Uint16(rec[16:]) != 0x0800 {
		t.Fatalf("inner ethertype misplaced: %x", rec[16:18])
	}
}

// 时间戳解码：SCM_TIMESTAMPING hw 非 0 用 hw；hw 全 0 退化 sw；全 0 → monotonic
func TestCaptureTimestampDecode(t *testing.T) {
	cases := []struct {
		oob     []byte
		wantSec uint64
	}{
		{cmsgTimestamping(1700000000, 123, 1, 1), 1700000000}, // hw 生效
		{cmsgTimestamping(0, 0, 1700000001, 5), 1700000001},   // hw 0 → sw
	}
	for i, c := range cases {
		if got := decodeTimestampNs(c.oob); got/1e9 != c.wantSec {
			t.Fatalf("case %d: want sec %d got %d", i, c.wantSec, got/1e9)
		}
	}
}

// 无 auxdata：帧原样（无 VLAN 插入）
func TestCaptureNoAuxdataUntouched(t *testing.T) {
	resetCapture(t)
	path := filepath.Join(t.TempDir(), "plain.pcap")
	src := newFakeSource()
	if ok, _ := captureTestStart(t, src, path); !ok {
		t.Fatal("start")
	}
	orig := testEthPayload()
	src.push(orig, nil)
	time.Sleep(150 * time.Millisecond)
	runDT(t, 6, mustJSON(t, map[string]string{"path": path}))
	data, _ := os.ReadFile(path)
	rec := data[24+16:]
	if binary.BigEndian.Uint16(rec[12:]) != 0x0800 {
		t.Fatal("frame mutated without auxdata")
	}
}

// dt5 eth 空：routeinfo 默认路由网卡
func TestCaptureDefaultIface(t *testing.T) {
	resetCapture(t)
	// 原生 routeinfo：注入 /proc/net/route fixture
	fixture := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT   \n" +
		"ens19\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0    \n"
	p := filepath.Join(t.TempDir(), "route")
	os.WriteFile(p, []byte(fixture), 0o644)
	prevProc := routeTablePath
	routeTablePath = p
	t.Cleanup(func() { routeTablePath = prevProc })
	var gotEth string
	src := newFakeSource()
	prev := openPacketSocketFn
	openPacketSocketFn = func(eth string) (pktSource, error) { gotEth = eth; return src, nil }
	t.Cleanup(func() { openPacketSocketFn = prev })
	if ok, _ := tcpdumpStart("", filepath.Join(t.TempDir(), "d.pcap"), "", true); !ok {
		t.Fatal("start")
	}
	if gotEth != "ens19" {
		t.Fatalf("default iface wrong: %q", gotEth)
	}
}

// dt5 eth 空且无默认路由 → res:false（routeinfo 成功但无 Iface）
func TestCaptureNoDefaultRoute(t *testing.T) {
	resetCapture(t)
	// 只有头行、无数据行 = 无默认路由（/proc/net/route 空表形态）
	prevProc := routeTablePath
	routeTablePath = filepath.Join(t.TempDir(), "route")
	os.WriteFile(routeTablePath, []byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT   \n"), 0o644)
	t.Cleanup(func() { routeTablePath = prevProc })
	resp, err := runDT(t, 5, mustJSON(t, map[string]string{"path": "/tmp/nr.pcap"}))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != `{"res":false}` {
		t.Fatalf("no default route want res:false, got %q", resp)
	}
}

// 单队列 best-effort（原生 SIOCETHTOOL ioctl）：读到多队列 → 设置 combined=1；
// 任何失败不影响抓包继续。
func TestCaptureSingleQueueBestEffort(t *testing.T) {
	resetCapture(t)
	prevCtl, prevSleep := ethtoolCtlFn, queueSleepFn
	defer func() { ethtoolCtlFn, queueSleepFn = prevCtl, prevSleep }()
	var setCalls []string
	ethtoolCtlFn = func(eth string, ch *ethtoolChannels) error {
		if ch.cmd == 0x3c { // ETHTOOL_GCHANNELS
			ch.combinedCount = 4 // 多队列
			return nil
		}
		setCalls = append(setCalls, fmt.Sprintf("combined=%d rx=%d tx=%d", ch.combinedCount, ch.rxCount, ch.txCount))
		return nil
	}
	queueSleepFn = func(time.Duration) {}
	src := newFakeSource()
	prev := openPacketSocketFn
	openPacketSocketFn = func(string) (pktSource, error) { return src, nil }
	t.Cleanup(func() { openPacketSocketFn = prev })
	// single_queue=true：单队列配置执行（失败也继续）
	if ok, _ := tcpdumpStart("eth0", filepath.Join(t.TempDir(), "sq.pcap"), "", true); !ok {
		t.Fatal("start with single_queue")
	}
	if len(setCalls) != 1 || setCalls[0] != "combined=1 rx=0 tx=0" {
		t.Fatalf("ethtool set not invoked for single_queue=true: %v", setCalls)
	}
}

// 已是单队列 → 不再调用设置（仍绑 CPU，capture.py:841-844 语义）
func TestConfigureSingleQueueAlreadySingle(t *testing.T) {
	prevCtl := ethtoolCtlFn
	defer func() { ethtoolCtlFn = prevCtl }()
	var setCalls int
	ethtoolCtlFn = func(eth string, ch *ethtoolChannels) error {
		if ch.cmd == 0x3c {
			ch.combinedCount = 1
			return nil
		}
		setCalls++
		return nil
	}
	configureSingleQueue("eth9-fake", 1) // 假网卡：bindIRQ 读不到 /sys，全空转
	if setCalls != 0 {
		t.Fatalf("已是单队列不该再设置，实际 %d 次", setCalls)
	}
}

// combined 设置失败 → 回退 rx/tx 分开设（capture.py:847-848 语义）
func TestConfigureSingleQueueFallbackRxTx(t *testing.T) {
	prevCtl, prevSleep := ethtoolCtlFn, queueSleepFn
	defer func() { ethtoolCtlFn, queueSleepFn = prevCtl, prevSleep }()
	queueSleepFn = func(time.Duration) {}
	var attempts []string
	ethtoolCtlFn = func(eth string, ch *ethtoolChannels) error {
		if ch.cmd == 0x3c {
			ch.combinedCount = 4
			return nil
		}
		if ch.combinedCount == 1 {
			return errors.New("combined not supported") // 第一次设置失败
		}
		attempts = append(attempts, fmt.Sprintf("rx=%d tx=%d", ch.rxCount, ch.txCount))
		return nil
	}
	configureSingleQueue("eth9-fake", 1)
	if len(attempts) != 1 || attempts[0] != "rx=1 tx=1" {
		t.Fatalf("应回退到 rx/tx 设置，实际 %v", attempts)
	}
}

// 读队列数失败 → 直接返回（不设置、不 panic）
func TestConfigureSingleQueueReadFailNoop(t *testing.T) {
	prevCtl := ethtoolCtlFn
	defer func() { ethtoolCtlFn = prevCtl }()
	var setCalls int
	ethtoolCtlFn = func(eth string, ch *ethtoolChannels) error {
		if ch.cmd == 0x3c {
			return errors.New("not supported")
		}
		setCalls++
		return nil
	}
	configureSingleQueue("eth9-fake", 1)
	if setCalls != 0 {
		t.Fatalf("读取失败不该设置，实际 %d 次", setCalls)
	}
}

// resetCapture 清空抓包注册表（capturesReset 已删——逐实例停）
func resetCapture(t *testing.T) {
	t.Helper()
	stopAllCapturesForTest()
	t.Cleanup(func() { stopAllCapturesForTest() })
}

var _ = json.Marshal

// 持续流量下 stop 必须能结束。真机实测（ens3 背景 ~10pps）：drain 只靠"1 秒内
// 收不到新帧"判断空，流量不断时永远不成立 → recv 线程永不退出 → stop 30s 超时，
// 抓包实例一直持有 CAPTURE 锁，期间同靶机 cmd_exec 全被拒，只能重启服务。
func TestCaptureStopWithSustainedTraffic(t *testing.T) {
	resetCapture(t)
	path := filepath.Join(t.TempDir(), "busy.pcap")
	src := newFakeSource()
	if ok, _ := captureTestStart(t, src, path); !ok {
		t.Fatal("start")
	}
	// 持续灌帧，直到用例结束（模拟 background 10pps 以上）
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			src.push(testEthPayload(), nil)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	defer close(done)
	time.Sleep(200 * time.Millisecond) // 确保已经在持续收包

	start := time.Now()
	resp, _ := runDT(t, 6, mustJSON(t, map[string]string{"path": path}))
	elapsed := time.Since(start)
	if string(resp) != `{"res":true}` {
		t.Fatalf("持续流量下 stop 必须成功，实际 %s（耗时 %v）", resp, elapsed)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("stop 耗时 %v，drain 需要硬上限", elapsed)
	}
}

// 持续流量下 stop 成功后，实例必须从注册表移除、pcap 可正常读回。
// 真机反馈的连带影响是"锁不释放、cmd_exec 全被拒"——stop 一旦成功，
// tcpdumpStop 会 delete 注册表项，锁由 mcp 侧释放；这里锁住"stop 后不再残留"。
func TestCaptureStopRemovesInstanceUnderLoad(t *testing.T) {
	resetCapture(t)
	path := filepath.Join(t.TempDir(), "busy2.pcap")
	src := newFakeSource()
	if ok, _ := captureTestStart(t, src, path); !ok {
		t.Fatal("start")
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			src.push(testEthPayload(), nil)
			time.Sleep(3 * time.Millisecond)
		}
	}()
	defer close(done)
	time.Sleep(150 * time.Millisecond)

	if resp, _ := runDT(t, 6, mustJSON(t, map[string]string{"path": path})); string(resp) != `{"res":true}` {
		t.Fatalf("stop 失败: %s", resp)
	}
	// 再 stop 一次必须是幂等真（实例已移除，未在抓）
	if resp, _ := runDT(t, 6, mustJSON(t, map[string]string{"path": path})); string(resp) != `{"res":true}` {
		t.Fatalf("stop 后实例应已移除（幂等 true），实际 %s", resp)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() <= 24 {
		t.Fatalf("pcap 应已落盘且有帧: %v", err)
	}
}
