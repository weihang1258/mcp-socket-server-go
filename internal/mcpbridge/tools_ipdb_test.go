package mcpbridge

import (
	"net"
	"net/netip"
	"testing"
)

// C1 集成：mock 靶机回 ipsegs 文件内容 → ip_db_load 建库 → ip_lookup 四态
func TestIPDBLoadAndLookup(t *testing.T) {
	house := "################\n//time:2026-11-20|ver:9|\n" +
		"1000|90134|20.1.1.1|20.255.255.254\n1001|90135|192.168.1.1|192.168.1.1\n//POLICY_FILE_END\n"
	m := newMockServer(t, stdMockHandler(t)) // dt3 由 std handler 覆盖不了，自己搭：
	_ = m
	// 直测 Loader + Manager（协议层 downloadFile 已有独立覆盖）
	b := testBridge(t)
	fetcher := fakeFetcher{files: map[string]string{ipdbDefaultPath: house}}
	res := b.IPDB.Load(fetcher, []string{ipdbDefaultPath})
	if len(res) != 1 || res[0].Error != "" {
		t.Fatalf("load: %+v", res)
	}
	if res[0].Entries != 2 || res[0].Prefixes < 2 {
		t.Fatalf("entries=%d prefixes=%d", res[0].Entries, res[0].Prefixes)
	}
	// sha 跳过
	res2 := b.IPDB.Load(fetcher, []string{ipdbDefaultPath})
	if !res2[0].Skipped {
		t.Fatal("sha 未变应跳过")
	}
	// 四态
	snap := b.IPDB.Manager().Get(ipdbDefaultPath)
	cases := []struct{ src, dst, want string }{
		{"20.1.1.2", "8.8.8.8", "outbound"},
		{"8.8.8.8", "20.1.1.2", "inbound"},
		{"20.1.1.2", "192.168.1.1", "internal"},
		{"8.8.8.8", "1.1.1.1", "external"},
	}
	for _, c := range cases {
		got := snap.Direction(parseIP(t, c.src), parseIP(t, c.dst))
		if got != c.want {
			t.Errorf("%s→%s: %s want %s", c.src, c.dst, got, c.want)
		}
	}
}

type fakeFetcher struct{ files map[string]string }

func (f fakeFetcher) DownloadFile(path string) ([]byte, error) {
	if c, ok := f.files[path]; ok {
		return []byte(c), nil
	}
	return nil, &net.OpError{Op: "open", Err: errNotFound{}}
}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

func parseIP(t *testing.T, s string) netip.Addr {
	t.Helper()
	return netip.MustParseAddr(s)
}

func testBridge(t *testing.T) *Bridge {
	t.Helper()
	return Init(BridgeConfig{DBPath: t.TempDir() + "/t.db", AuditDays: 1})
}
