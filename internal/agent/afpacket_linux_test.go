//go:build linux

package agent

// 发送 socket 缓存的并发安全（裸 TCP 多连接可并发发 dt0）。
// 非 root 无法真开 AF_PACKET，用 openSendSocket 注入假构造器，专测 sendSockets 的锁。

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
	"time"
)

func TestReplaySenderForConcurrentCacheSafe(t *testing.T) {
	sendMu.Lock()
	savedSockets := sendSockets
	savedOpen := openSendSocket
	sendSockets = map[string]*rawPacketSender{}
	var built atomic.Int32
	openSendSocket = func(iface string) (*rawPacketSender, error) {
		built.Add(1)
		time.Sleep(2 * time.Millisecond)                 // 撑开竞争窗口：锁一旦缺失必然重复建
		return &rawPacketSender{fd: -1, ifindex: 7}, nil // -1：unix.Close(-1) 只回 EBADF，绝不误关真实 fd
	}
	sendMu.Unlock()
	t.Cleanup(func() {
		sendMu.Lock()
		sendSockets = savedSockets
		openSendSocket = savedOpen
		sendMu.Unlock()
	})

	const n = 64
	var wg sync.WaitGroup
	got := make([]*rawPacketSender, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := replaySenderFor("lo")
			if err != nil {
				t.Errorf("replaySenderFor: %v", err)
				return
			}
			got[i] = s
		}(i)
	}
	wg.Wait()

	// 并发下必须只建一次（锁内 double-check 生效），且所有调用者拿到同一实例
	if b := built.Load(); b != 1 {
		t.Fatalf("并发下构造器被调用 %d 次，want 1（缺锁/缺 double-check）", b)
	}
	first := got[0]
	if first == nil {
		t.Fatal("未取到实例")
	}
	for i, s := range got {
		if s != first {
			t.Fatalf("第 %d 个调用者拿到不同实例（缓存失效）", i)
		}
	}
}

// 网卡删除重建（ifindex 变化）后缓存句柄失效 → 丢弃重建，而不是永久报错。
// Python 每次回放新建 socket 故无此问题；Go 常驻缓存靠这条自愈（§12#26）。
func TestReplaySendStaleSocketRebuilds(t *testing.T) {
	sendMu.Lock()
	savedSockets, savedOpen := sendSockets, openSendSocket
	sendSockets = map[string]*rawPacketSender{}
	var built atomic.Int32
	openSendSocket = func(iface string) (*rawPacketSender, error) {
		built.Add(1)
		return &rawPacketSender{fd: -1, ifindex: 7}, nil // -1：Close 只回 EBADF，不误关真实 fd
	}
	sendMu.Unlock()
	t.Cleanup(func() {
		sendMu.Lock()
		sendSockets, openSendSocket = savedSockets, savedOpen
		sendMu.Unlock()
	})

	s, err := replaySenderFor("lo")
	if err != nil {
		t.Fatal(err)
	}
	// 旧句柄被判定失效 → 缓存里应被删除
	dropSendSocket("lo", s)
	sendMu.Lock()
	_, still := sendSockets["lo"]
	sendMu.Unlock()
	if still {
		t.Fatal("dropSendSocket 后缓存须清空")
	}
	// 再次获取应重建（构造器第二次调用）
	s2, err := replaySenderFor("lo")
	if err != nil || s2 == nil {
		t.Fatalf("重建失败: %v", err)
	}
	if built.Load() != 2 {
		t.Fatalf("构造器应被调用 2 次，实际 %d", built.Load())
	}
	// dropSendSocket 对已替换的句柄不得误删新句柄（并发安全）
	dropSendSocket("lo", s)
	sendMu.Lock()
	cur := sendSockets["lo"]
	sendMu.Unlock()
	if cur != s2 {
		t.Fatal("drop 陈旧句柄不得删除已重建的新句柄")
	}
}

// sendSocketStale 只认句柄失效一类错误，普通错误不触发重建。
func TestSendSocketStaleClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{unix.ENXIO, true}, // 网卡删除/重建的真机返回值（dummy 网卡实测）
		{unix.ENETDOWN, true},
		{unix.EBADF, true},
		{unix.EINVAL, true},
		{unix.ENODEV, true},
		{unix.ENOBUFS, false},
		{nil, false},
		{errors.New("other"), false},
	} {
		if got := sendSocketStale(tc.err); got != tc.want {
			t.Errorf("%v: got %v want %v", tc.err, got, tc.want)
		}
	}
}

// 端到端自愈：真正经过 sendSocketStale 判定 → drop → 重建 → 重发。
// 这条能抓住「判定漏了某个 errno」（如 ENXIO）这类回归——旧的
// TestReplaySendStaleSocketRebuilds 直接调 dropSendSocket，抓不到。
func TestReplaySendSelfHealsOnStaleErrno(t *testing.T) {
	sendMu.Lock()
	savedSockets, savedOpen, savedSendTo := sendSockets, openSendSocket, sendToFn
	sendSockets = map[string]*rawPacketSender{}
	var built atomic.Int32
	openSendSocket = func(iface string) (*rawPacketSender, error) {
		built.Add(1)
		return &rawPacketSender{fd: -1, ifindex: 7 + int(built.Load())}, nil
	}
	var firstCall atomic.Bool
	sendToFn = func(fd int, pkt []byte, ifindex int) error {
		if firstCall.CompareAndSwap(false, true) {
			return unix.ENXIO // 首次发送：模拟网卡已被删除
		}
		return nil
	}
	sendMu.Unlock()
	t.Cleanup(func() {
		sendMu.Lock()
		sendSockets, openSendSocket, sendToFn = savedSockets, savedOpen, savedSendTo
		sendMu.Unlock()
		rebuildBackoffMu.Lock()
		rebuildBackoffAt = nil
		rebuildBackoffMu.Unlock()
	})

	if err := replaySendLinux("lo", make([]byte, 16)); err != nil {
		t.Fatalf("ENXIO 须自愈重试成功，实际: %v", err)
	}
	if built.Load() != 2 {
		t.Fatalf("须重建一次（构造器 2 次），实际 %d", built.Load())
	}
	// 非失效类错误不得触发重建
	firstCall.Store(false)
	sendToFn = func(fd int, pkt []byte, ifindex int) error { return unix.ENOBUFS }
	before := built.Load()
	if err := replaySendLinux("lo", make([]byte, 16)); err == nil {
		t.Fatal("普通错误须原样返回")
	}
	if built.Load() != before {
		t.Fatal("普通错误不得触发重建")
	}
}

// 网卡长期不可用（重建持续失败）时不得每包都建 socket：冷却期内跳过重建。
func TestReplaySendRebuildBackoff(t *testing.T) {
	sendMu.Lock()
	savedSockets, savedOpen, savedSendTo := sendSockets, openSendSocket, sendToFn
	sendSockets = map[string]*rawPacketSender{}
	var attempts atomic.Int32
	openSendSocket = func(iface string) (*rawPacketSender, error) {
		if attempts.Add(1) == 1 {
			return &rawPacketSender{fd: -1, ifindex: 7}, nil // 首次建成功
		}
		return nil, unix.ENODEV // 之后的重建恒失败（网卡长期不存在）
	}
	sendToFn = func(fd int, pkt []byte, ifindex int) error { return unix.ENXIO }
	sendMu.Unlock()
	t.Cleanup(func() {
		sendMu.Lock()
		sendSockets, openSendSocket, sendToFn = savedSockets, savedOpen, savedSendTo
		sendMu.Unlock()
		rebuildBackoffMu.Lock()
		rebuildBackoffAt = nil
		rebuildBackoffMu.Unlock()
	})

	// 首次：建成功 → 发送 ENXIO → drop → 重建失败（attempts=2）
	if err := replaySendLinux("lo", make([]byte, 16)); err == nil {
		t.Fatal("重建失败须返回错误")
	}
	first := attempts.Load()
	if first != 2 {
		t.Fatalf("首次应建 1 次 + 重建失败 1 次 = 2，实际 %d", first)
	}
	for i := 0; i < 5; i++ {
		replaySendLinux("lo", make([]byte, 16))
	}
	if got := attempts.Load(); got != first {
		t.Fatalf("冷却期内不得重复重建：首次 %d 次，5 次调用后 %d 次", first, got)
	}
}
