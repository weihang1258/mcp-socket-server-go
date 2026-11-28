package mcpbridge

import (
	"strings"
	"testing"
)

// 客户端本地文件必须直连靶机，不能经桥侧文件路径中转。
func TestFileTransferReturnsClientCurlEndpoint(t *testing.T) {
	b := newTestBridge(t)
	b.Registry.AddTarget("10.12.131.82", 9000, nil, "")
	b.Registry.AddTarget("fd00::5", 9000, nil, "")
	out := fileTransferCommands(b, fileTransferIn{BaseIn: BaseIn{
		Targets: []string{"10.12.131.82:9000", "fd00::5"},
	}})
	if out.Ok != 2 || out.Total != 2 || len(out.Failed) != 0 {
		t.Fatalf("resolve: %+v", out)
	}
	got := out.Results[0].Data
	if got.IP != "10.12.131.82" || got.HTTPPort != 9001 {
		t.Fatalf("endpoint: %+v", got)
	}
	wantDownload := `curl -f -o 本地文件 "http://10.12.131.82:9001/files?path=<靶机文件绝对路径>"`
	wantUpload := `curl -f -F "path=<靶机文件绝对路径>" -F "file=@客户端本地文件" http://10.12.131.82:9001/files`
	if got.Download != wantDownload || got.Upload != wantUpload {
		t.Fatalf("commands:\n%s\n%s", got.Download, got.Upload)
	}
	if got = out.Results[1].Data; got.IP != "fd00::5" || !strings.Contains(got.Download, "http://[fd00::5]:9001/") {
		t.Fatalf("IPv6 endpoint: %+v", got)
	}
}

// 纯指引不得因 :9001 未启动而失败，也不得发起探测。
func TestFileTransferDoesNotDialTarget(t *testing.T) {
	b := newTestBridge(t)
	b.Registry.AddTarget("192.0.2.1", 9000, nil, "")
	out := fileTransferCommands(b, fileTransferIn{BaseIn: BaseIn{Targets: []string{"@missing"}}})
	if out.Ok != 0 || len(out.Failed) != 1 {
		t.Fatalf("unknown tag: %+v", out)
	}
	out = fileTransferCommands(b, fileTransferIn{BaseIn: BaseIn{Targets: []string{"192.0.2.1"}}})
	if out.Ok != 1 || out.Results[0].Data.HTTPPort != 9001 {
		t.Fatalf("local generation must not dial: %+v", out)
	}
}
