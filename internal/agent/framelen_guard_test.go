package agent

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// A7 回归：负帧长与超限帧长必须断连（此前负数=静默僵死）
func TestFrameLenGuard(t *testing.T) {
	srv, cli := net.Pipe()
	go handleConn(srv, Do)
	defer cli.Close()
	cli.SetDeadline(time.Now().Add(3 * time.Second))

	// 负帧长：0xFFFFFFFF
	f := make([]byte, 8)
	binary.LittleEndian.PutUint32(f, 0xFFFFFFFF)
	copy(f[4:], []byte{1, 0, 0, 0})
	cli.Write(f)
	buf := make([]byte, 64)
	_, err := cli.Read(buf) // 对端断连 → EOF
	if err == nil {
		t.Fatal("负帧长未断连（A7 回归）")
	}
	cli.Close()
	srv.Close()
}
