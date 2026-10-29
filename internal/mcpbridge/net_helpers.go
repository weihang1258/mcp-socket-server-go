package mcpbridge

import (
	"encoding/base64"
	"net"
	"strconv"
	"time"
)

func netDialTimeout(host string, port, timeoutSec int) (net.Conn, error) {
	return net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), time.Duration(timeoutSec)*time.Second)
}

func b64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
