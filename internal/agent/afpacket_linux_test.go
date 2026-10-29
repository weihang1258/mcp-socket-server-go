//go:build linux

package agent

// 发送 socket 缓存的并发安全（裸 TCP 多连接可并发发 dt0）。
// 非 root 无法真开 AF_PACKET，用 openSendSocket 注入假构造器，专测 sendSockets 的锁。

import (
	"sync"
	"sync/atomic"
	"testing"
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
		time.Sleep(2 * time.Millisecond)                // 撑开竞争窗口：锁一旦缺失必然重复建
		return &rawPacketSender{fd: 1, ifindex: 7}, nil // 假 fd，不碰内核
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
