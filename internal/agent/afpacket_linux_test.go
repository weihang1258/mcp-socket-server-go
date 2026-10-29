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
		// ENETDOWN **不是**句柄失效：网卡 down 时 Bind 照样成功，且同一句柄在网卡
		// up 回来后立刻可发（真机实测 down→ENETDOWN、up→nil，全程未重建）。
		// 归为 stale 会让持续 down 的网卡每包重建一次 socket（实测 built 1→2→3→4）。
		{unix.ENETDOWN, false},
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

// 网卡持续 down：不得重建 socket（ENETDOWN 是链路状态，不是句柄失效）。
// 真机实测绑定 down 的网卡成功、网卡 up 回来后同一句柄立刻可发。
func TestReplaySendDownIfaceDoesNotRebuild(t *testing.T) {
	sendMu.Lock()
	savedSockets, savedOpen, savedSendTo := sendSockets, openSendSocket, sendToFn
	sendSockets = map[string]*rawPacketSender{}
	var built atomic.Int32
	openSendSocket = func(iface string) (*rawPacketSender, error) {
		built.Add(1)
		return &rawPacketSender{fd: -1, ifindex: 7}, nil
	}
	sendToFn = func(fd int, pkt []byte, ifindex int) error { return unix.ENETDOWN }
	sendMu.Unlock()
	t.Cleanup(func() {
		sendMu.Lock()
		sendSockets, openSendSocket, sendToFn = savedSockets, savedOpen, savedSendTo
		sendMu.Unlock()
		rebuildBackoffMu.Lock()
		rebuildBackoffAt = nil
		rebuildBackoffMu.Unlock()
	})

	for i := 0; i < 3; i++ {
		if err := replaySendLinux("lo", make([]byte, 16)); !errors.Is(err, unix.ENETDOWN) {
			t.Fatalf("第 %d 包须原样返回 ENETDOWN，实际 %v", i, err)
		}
	}
	if got := built.Load(); got != 1 {
		t.Fatalf("网卡 down 期间不得重建：应只建 1 次，实际 %d 次（每包重建一次）", got)
	}
	// 网卡 up 回来：同一句柄直接可发，仍不新建
	sendToFn = func(fd int, pkt []byte, ifindex int) error { return nil }
	if err := replaySendLinux("lo", make([]byte, 16)); err != nil {
		t.Fatalf("网卡恢复后同一句柄须能发送: %v", err)
	}
	if got := built.Load(); got != 1 {
		t.Fatalf("恢复后不得重建，实际 %d 次", got)
	}
}

// 两个 goroutine 同时撞上同一失效句柄：两个包都必须发出去。
// Sendto 报 ENXIO 的那次根本没上线（真机实测接收端 0 包），所以两边各自重试
// 是正确的——不构成重复报文；反过来"只有抢到删除的才重试"会让另一个包静默丢失
// （replayer 逐包失败只计数不报错，见 TestReplayerPerPacketSendFailureKeepsStats）。
func TestReplaySendConcurrentStaleNoPacketLost(t *testing.T) {
	sendMu.Lock()
	savedSockets, savedOpen, savedSendTo := sendSockets, openSendSocket, sendToFn
	sendSockets = map[string]*rawPacketSender{}
	var built atomic.Int32
	openSendSocket = func(iface string) (*rawPacketSender, error) {
		built.Add(1)
		return &rawPacketSender{fd: -1, ifindex: 7}, nil
	}
	// 前两次调用（两个 goroutine 各自的首发）都卡在同一点，确保拿到的是同一个
	// 失效前句柄；之后的重试直接放行。
	release := make(chan struct{})
	var firstTwo atomic.Int32
	var failedSends, okSends atomic.Int32
	sendToFn = func(fd int, pkt []byte, ifindex int) error {
		if firstTwo.Add(1) <= 2 {
			<-release
			failedSends.Add(1)
			return unix.ENXIO
		}
		okSends.Add(1)
		return nil
	}
	sendMu.Unlock()
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		sendMu.Lock()
		sendSockets, openSendSocket, sendToFn = savedSockets, savedOpen, savedSendTo
		sendMu.Unlock()
		rebuildBackoffMu.Lock()
		rebuildBackoffAt = nil
		rebuildBackoffMu.Unlock()
	})

	if _, err := replaySenderFor("lo"); err != nil {
		t.Fatal(err)
	}
	built.Store(1)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs[i] = replaySendLinux("lo", make([]byte, 16)) }(i)
	}
	for firstTwo.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Fatalf("第 %d 个包未送达（并发下被丢弃）: %v", i, e)
		}
	}
	// 两个 goroutine 持有的是同一个失效前句柄，所以两人的首发都该失败（各 1 次 ENXIO），
	// 然后各自重试成功 → 一共 2 失败 + 2 成功。任一包没送达就是丢了。
	if got := failedSends.Load(); got != 2 {
		t.Fatalf("两个 goroutine 的首发都该遇到 ENXIO，实际 %d 次", got)
	}
	if got := okSends.Load(); got != 2 {
		t.Fatalf("两个包都须成功送达（各自一次重试），实际成功 %d 次", got)
	}
}
