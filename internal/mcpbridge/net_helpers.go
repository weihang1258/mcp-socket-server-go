package mcpbridge

import (
	"encoding/base64"
	"net"
	"time"
)

func netDialTimeout(host string, port, timeoutSec int) (net.Conn, error) {
	return net.DialTimeout("tcp", net.JoinHostPort(host, itoa(port)), time.Duration(timeoutSec)*time.Second)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func b64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
