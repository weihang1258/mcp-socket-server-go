package mcpbridge

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// A4+A5 回归：假 FTP 服务器——多行 banner（220-）+ PASV 返回不可达内网 IP。
// 桥必须：跳过多行 banner 正常走完登录；数据连接用控制连接对端 IP（127.0.0.1）。
func TestFtpDownloadMultilineAndPASVHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port, _ := strconv.Atoi(ln.Addr().String()[len("127.0.0.1:"):])

	content := "ftp-payload-12345"
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		w := func(s string) { conn.Write([]byte(s + "\r\n")) }
		// 多行 banner
		w("220-Welcome to FTP")
		w("220-Second line")
		w("220 ready")
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			cmd := string(buf[:n])
			switch {
			case len(cmd) >= 4 && cmd[:4] == "USER":
				w("331 please spec")
			case len(cmd) >= 4 && cmd[:4] == "PASS":
				w("230 logged in")
			case len(cmd) >= 4 && cmd[:4] == "TYPE":
				w("200 type set")
			case len(cmd) >= 4 && cmd[:4] == "PASV":
				// 先建数据监听再回 PASV（消除 dial 早于 listen 的竞态）
				dl, err := net.Listen("tcp", "127.0.0.1:51024")
				if err != nil {
					done <- err
					return
				}
				go func() {
					dc, err := dl.Accept()
					if err != nil {
						dl.Close()
						return
					}
					dc.Write([]byte(content))
					dc.Close()
					dl.Close()
				}()
				// 返回不可达内网地址——若桥采信此 IP 会连不上
				w("227 Entering Passive Mode (10,255,255,1,199,80)")
			case len(cmd) >= 4 && cmd[:4] == "RETR":
				w("150 opening BINARY")
				go func() {
					time.Sleep(300 * time.Millisecond) // 等数据连接传完
					w("226 transfer complete")
				}()
			case len(cmd) >= 4 && cmd[:4] == "QUIT":
				w("221 bye")
				done <- nil
				return
			}
		}
	}()

	dest := filepath.Join(t.TempDir(), "dl.bin")
	err = ftpDownload("ftp://127.0.0.1:"+strconv.Itoa(port)+"/pkg.tar.gz", dest, "u", "p", 10)
	if err != nil {
		t.Fatalf("ftpDownload: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatalf("内容 %q != %q", got, content)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}
