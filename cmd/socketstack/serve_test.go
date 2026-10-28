package main

import (
	"net"
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
