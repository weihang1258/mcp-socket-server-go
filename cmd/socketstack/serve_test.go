package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/weihang1258/mcp-socket-server-go/internal/config"
	"github.com/weihang1258/mcp-socket-server-go/internal/frame"
)

// serve 编排顺序：自愈 → :9001 → TCP（:9001 失败不影响 :9000）
func TestAgentServeOrchestration(t *testing.T) {
	cfg := config.Load("")
	cfg.Agent.TCPPort = 0 // 随机端口
	_, addr, stop := startAgent(cfg, true /*testMode 跳过环境初始化*/)
	defer stop()
	if addr == "" {
		t.Fatal("agent not listening")
	}
	// dt14 烟测
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(frame.Encode(14, nil))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if n, _ := c.Read(buf); n == 0 {
		t.Fatal("no dt14 response")
	}
}

// 非 testMode 启动时须触发 chromium 后台预取（消掉首次 boce 现场下载撑爆超时）。
func TestStartAgentPrefetchesChromium(t *testing.T) {
	prev := prefetchChromium
	var called atomic.Int32
	prefetchChromium = func() { called.Add(1) }
	prevSetup := setupEnv
	setupEnv = func() {}
	prevHTTP, prevPort := startHTTPFile, readHTTPPort
	startHTTPFile = func(int) (func(), error) { return func() {}, nil }
	readHTTPPort = func() int { return 0 }
	t.Cleanup(func() {
		prefetchChromium = prev
		setupEnv = prevSetup
		startHTTPFile, readHTTPPort = prevHTTP, prevPort
	})

	cfg := config.Load("")
	cfg.Agent.TCPPort = 0
	cfg.Agent.ChromiumPrefetch = true
	_, _, stop := startAgent(cfg, false)
	defer stop()
	if called.Load() != 1 {
		t.Fatalf("开关打开时启动须预取 1 次，实际 %d", called.Load())
	}
}

// 默认关闭：内网靶机（连不上 npmmirror）每次重启都不该白跑一次 536MB 下载。
func TestStartAgentNoPrefetchWhenDisabled(t *testing.T) {
	prev := prefetchChromium
	var called atomic.Int32
	prefetchChromium = func() { called.Add(1) }
	prevSetup := setupEnv
	setupEnv = func() {}
	prevHTTP, prevPort := startHTTPFile, readHTTPPort
	startHTTPFile = func(int) (func(), error) { return func() {}, nil }
	readHTTPPort = func() int { return 0 }
	t.Cleanup(func() {
		prefetchChromium = prev
		setupEnv = prevSetup
		startHTTPFile, readHTTPPort = prevHTTP, prevPort
	})

	cfg := config.Load("") // 默认配置：chromium_prefetch 未开
	cfg.Agent.TCPPort = 0
	_, _, stop := startAgent(cfg, false)
	defer stop()
	if called.Load() != 0 {
		t.Fatalf("默认配置不得预取，实际调用 %d 次", called.Load())
	}
}
