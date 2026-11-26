package mcpbridge

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/weihang1258/mcp-socket-server-go/internal/ipdb"
)

// ---- C1：机房 IP 段库（设计 docs/dpi-ipdb-direction-design-2026-11-25.md 第九节） ----

type ipdbLoadIn struct {
	BaseIn
	Paths []string `json:"paths,omitempty" jsonschema:"ipsegs 文件路径数组（每份一个独立库）；缺省 /opt/dpi/xsaconf/rule/house_ipsegs.txt"`
}

type ipdbLoadData struct {
	Libs map[string]ipdb.LoadResult `json:"libs" jsonschema:"按路径分组的建库结果：entries/prefixes/sha256/elapsed_ms/skipped"`
}

type ipLookupIn struct {
	BaseIn
	Lib   string           `json:"lib,omitempty" jsonschema:"判定基准库的文件路径；缺省 = 默认路径（house_ipsegs.txt）建的库"`
	Pairs []ipLookupPairIn `json:"pairs" jsonschema:"(源IP,目的IP) 数组，上限 10000 对"`
}

type ipLookupPairIn struct {
	Src string `json:"src" jsonschema:"源 IP（v4/v6）"`
	Dst string `json:"dst" jsonschema:"目的 IP（v4/v6）"`
}

type ipLookupPairOut struct {
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	SrcIn     bool   `json:"src_in"`
	DstIn     bool   `json:"dst_in"`
	Direction string `json:"direction" jsonschema:"internal|inbound|outbound|external（相对 lib 库）"`
}

type ipLookupData struct {
	Lib   string            `json:"lib" jsonschema:"判定使用的基准库路径"`
	Pairs []ipLookupPairOut `json:"pairs" jsonschema:"逐对判定结果（顺序与入参一致）"`
}

const (
	ipdbDefaultPath = "/opt/dpi/xsaconf/rule/house_ipsegs.txt"
	ipLookupMaxPair = 10000
)

func (b *Bridge) registerIPDBTools(s *mcp.Server) {
	addTyped(s, write("ip_db_load",
		"加载机房 IP 段库",
		"从靶机读 IP 段文件建内存库（供 ip_lookup 与 pcap 流方向判定复用）。什么时候用：首次使用 ip_lookup 前；设备上 ipsegs 文件变更后重新加载。paths 每份文件建一个独立库，缺省 house_ipsegs.txt；sha256 没变的文件自动跳过重建。注意：库按路径全局唯一（不带靶机维度），多台靶机同路径文件不同时后加载的覆盖先加载的——多机差异化 IP 段请逐台加载并显式传 lib。返回 results[].data.libs{路径:{entries,prefixes,sha256,elapsed_ms,skipped}}。"),
		func(ctx context.Context, a ipdbLoadIn) Envelope[ipdbLoadData] {
			paths := a.Paths
			if len(paths) == 0 {
				paths = []string{ipdbDefaultPath}
			}
			return runEnvelope[ipdbLoadData](b, ctx, a.BaseIn, "ip_db_load",
				map[string]any{"paths": paths}, LkNone, "", true, func(c *Client) (any, error) {
					results := b.IPDB.Load(c, paths)
					libs := map[string]ipdb.LoadResult{}
					for _, r := range results {
						libs[r.Path] = r
						if r.Error != "" {
							return ipdbLoadData{Libs: libs}, fmt.Errorf("%s: %s", r.Path, r.Error)
						}
					}
					return ipdbLoadData{Libs: libs}, nil
				})
		})

	addTyped(s, ro("ip_lookup",
		"IP 方向判定",
		"判定 (源IP,目的IP) 相对机房 IP 段库的四态方向：internal（都在机房内）/inbound（入向）/outbound（出向）/external（都在机房外）。什么时候用：分析五元组流、确认 pcap 报文方向、核查策略命中面。前置：先 ip_db_load 建库（或依赖上次加载的库）。pairs 上限 10000 对，纯内存查询。lib 指定基准库路径，缺省默认库。"),
		func(ctx context.Context, a ipLookupIn) Envelope[ipLookupData] {
			if len(a.Pairs) == 0 {
				return allFailedEnvelope[ipLookupData](b.resolve(a.Targets), "pairs 为空", ErrBusiness)
			}
			if len(a.Pairs) > ipLookupMaxPair {
				return allFailedEnvelope[ipLookupData](b.resolve(a.Targets),
					fmt.Sprintf("pairs 超上限: %d（上限 %d，请分批）", len(a.Pairs), ipLookupMaxPair), ErrBusiness)
			}
			lib := a.Lib
			if lib == "" {
				lib = ipdbDefaultPath
			}
			snap := b.IPDB.Manager().Get(lib)
			if snap == nil {
				return allFailedEnvelope[ipLookupData](b.resolve(a.Targets),
					fmt.Sprintf("库未加载: %s（先调 ip_db_load）", lib), ErrBusiness)
			}
			// 解析失败的对直接报错，静默错判比报错危险
			out := make([]ipLookupPairOut, 0, len(a.Pairs))
			for i, p := range a.Pairs {
				src, err := netip.ParseAddr(strings.TrimSpace(p.Src))
				if err != nil {
					return allFailedEnvelope[ipLookupData](b.resolve(a.Targets),
						fmt.Sprintf("pairs[%d].src 非法 IP: %q", i, p.Src), ErrBusiness)
				}
				dst, err := netip.ParseAddr(strings.TrimSpace(p.Dst))
				if err != nil {
					return allFailedEnvelope[ipLookupData](b.resolve(a.Targets),
						fmt.Sprintf("pairs[%d].dst 非法 IP: %q", i, p.Dst), ErrBusiness)
				}
				srcIn := snap.Contains(src)
				dstIn := snap.Contains(dst)
				out = append(out, ipLookupPairOut{
					Src: p.Src, Dst: p.Dst, SrcIn: srcIn, DstIn: dstIn,
					Direction: snap.Direction(src, dst), // 四态唯一真相在 Snapshot.Direction
				})
			}
			return runEnvelope[ipLookupData](b, ctx, a.BaseIn, "ip_lookup",
				map[string]any{"lib": lib, "count": len(a.Pairs)}, LkNone, "", true,
				func(c *Client) (any, error) {
					return ipLookupData{Lib: lib, Pairs: out}, nil // 纯内存：不触达靶机
				})
		})
}

