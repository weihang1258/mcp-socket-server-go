package mcpbridge

// file_ 与 net_ 分类（方案 §4.2 / §4.4）。

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---- 入参 ----

type filePathIn struct {
	BaseIn
	Path string `json:"path" jsonschema:"靶机上的绝对路径"`
}

type fileListIn struct {
	BaseIn
	Path       string `json:"path" jsonschema:"靶机上的目录绝对路径"`
	NameFilter string `json:"name_filter,omitempty" jsonschema:"find -name 过滤表达式，如 '*.tar.gz'（缺省不过滤）"`
	MaxDepth   int    `json:"max_depth,omitempty" jsonschema:"目录深度上限，缺省 1（只列一层）；要更深显式加大"`
	Sorted     bool   `json:"sorted,omitempty" jsonschema:"true 表示 按版本排序（sort -V），缺省 false"`
}

type fileRemoveIn struct {
	BaseIn
	Path      string `json:"path" jsonschema:"要删除的文件或目录绝对路径"`
	Recursive *bool  `json:"recursive,omitempty" jsonschema:"目录是否递归删除，缺省 true（rm -rf）；传 false 只删空目录"`
}

type fileGetIn struct {
	BaseIn
	RemotePath string `json:"remote_path" jsonschema:"靶机上的文件绝对路径"`
	LocalName  string `json:"local_name,omitempty" jsonschema:"桥本地文件名（只能落在桥的下载目录，禁止绝对路径；缺省取远端文件名）"`
	HTTPPort   int    `json:"http_port,omitempty" jsonschema:"靶机 :9001 文件服务端口，缺省 9001"`
}

type filePutIn struct {
	BaseIn
	LocalPath  string `json:"local_path" jsonschema:"桥本地文件绝对路径"`
	RemotePath string `json:"remote_path" jsonschema:"靶机上的目标绝对路径"`
	HTTPPort   int    `json:"http_port,omitempty" jsonschema:"靶机 :9001 文件服务端口，缺省 9001"`
}

type fileUnzipIn struct {
	BaseIn
	File        string `json:"file" jsonschema:"靶机上的 zip 绝对路径"`
	Outdir      string `json:"outdir,omitempty" jsonschema:"解压目标目录（缺省与 zip 同目录）"`
	PasswordRef string `json:"password_ref,omitempty" jsonschema:"密码引用名（桥本地配置键），明文密码不得出现在工具参数里"`
}

type fileTransferHintIn struct {
	BaseIn
	HTTPPort int `json:"http_port,omitempty" jsonschema:"靶机 :9001 文件服务端口，缺省 9001"`
}

type netSetMTUIn struct {
	BaseIn
	Iface string `json:"iface" jsonschema:"网卡名，如 eth0"`
	MTU   int    `json:"mtu,omitempty" jsonschema:"目标 MTU，缺省 2000（回放前常用值）"`
}

type netSetTimeIn struct {
	BaseIn
	Time string `json:"time,omitempty" jsonschema:"目标时间，格式 YYYY-MM-DD HH:MM:SS；缺省取桥当前时间"`
}

// ---- 出参 ----

type FileData struct {
	Name      string `json:"name" jsonschema:"文件名（不含目录）"`
	SizeBytes int64  `json:"size_bytes" jsonschema:"文件字节数"`
	SHA256    string `json:"sha256,omitempty" jsonschema:"文件内容的 sha256 十六进制；用于校验传输完整性"`
}

type fileStatData struct {
	Exists    bool  `json:"exists" jsonschema:"true 表示路径存在。注意不存在是正常结果不是错误"`
	IsDir     bool  `json:"is_dir" jsonschema:"true 表示 是目录；false 表示 是文件（Exists=false 时无意义）"`
	SizeBytes int64 `json:"size_bytes" jsonschema:"文件字节数（目录时为 0）"`
}

type fileListData struct {
	Entries []string `json:"entries" jsonschema:"目录条目名称列表"`
	Count   int      `json:"count" jsonschema:"条目数"`
}

type fileOpData struct {
	OK   bool   `json:"ok" jsonschema:"true 表示操作成功"`
	Path string `json:"path" jsonschema:"被操作的目标路径"`
}

type fileUnzipData struct {
	OK         bool   `json:"ok" jsonschema:"true 表示解压成功且已复核出文件"`
	Outdir     string `json:"outdir" jsonschema:"解压目标目录"`
	VerifiedBy string `json:"verified_by" jsonschema:"复核方式，通常为 file_list"`
	EntryCount int64  `json:"entry_count" jsonschema:"解压后目录内条目总数"`
	NewEntries int    `json:"new_entries" jsonschema:"本次解压新增的条目数；为 0 会判失败（设备回 ok 但实际没解出东西）"`
}

type fileTransferHintData struct {
	Download string `json:"download" jsonschema:"下载命令模板（curl）"`
	Upload   string `json:"upload" jsonschema:"上传命令模板（curl -F）"`
	Target   string `json:"target" jsonschema:"该命令对应的靶机"`
}

type netRouteData struct {
	Routes map[string]any `json:"routes" jsonschema:"路由表，含默认路由与网卡名"`
}

type netMTUData struct {
	Changed bool   `json:"changed" jsonschema:"true 表示 MTU 确实被改动；false 表示原本就是该值"`
	Iface   string `json:"iface" jsonschema:"网卡名"`
	Current string `json:"current" jsonschema:"设置后读回的 MTU；与请求值不一致会判业务失败"`
}

type netTimeData struct {
	Set     string `json:"set" jsonschema:"已设置的时间"`
	Verify  string `json:"verify" jsonschema:"从设备读回的时间"`
	Match   bool   `json:"match" jsonschema:"true 表示 设置值与读回值一致"`
	Warning string `json:"warning,omitempty" jsonschema:"非致命告警，如容器/VM 无 RTC 导致写硬件时钟失败（系统时间已生效）"` // 例如容器里 hwclock 不可用（系统时间已生效）
}

func (b *Bridge) registerFileTools(s *mcp.Server) {
	// file_stat：一次返回存在性、是否目录、字节数（原 isfile + isdir + getsize 三次调用）。
	addTyped(s, ro("file_stat",
		"查远程路径状态",
		"查靶机上一个路径是否存在、是否目录、有多少字节。什么时候用：操作远程文件前先确认状态，避免盲删盲建。一次调用替代「是否存在+是否目录+多大」三件事。关键语义：不存在 = 成功结果 exists=false，不是失败。返回 exists/is_dir/size_bytes。"),
		func(ctx context.Context, a filePathIn) Envelope[fileStatData] {
			return runEnvelope[fileStatData](b, ctx, a.BaseIn, "file_stat", map[string]any{"path": a.Path},
				LkNone, "", true, func(c *Client) (any, error) {
					isFile, err := c.Isfile(a.Path)
					if err != nil {
						return nil, err
					}
					if !isFile {
						// dt7 说「不是文件」= 不存在或目录；用 dt8 分开，否则调用方
						// 拿不到 is_dir，只能自己再发一次 file_stat+shell test。
						isDir, derr := c.Isdir(a.Path)
						if derr != nil {
							return nil, derr
						}
						return fileStatData{Exists: isDir, IsDir: isDir}, nil
					}
					size, err := c.getsize(a.Path)
					if err != nil {
						return nil, err
					}
					return fileStatData{Exists: true, SizeBytes: size}, nil
				})
		})

	addTyped(s, ro("file_list",
		"列远程目录",
		"列靶机目录内容。什么时候用：浏览远程目录、找安装包或 pcap 时；本地目录请用 Glob。path 填靶机绝对路径；name_filter 按名字过滤；max_depth 限制递归深度（缺省 1）；sorted=true 按版本排序（用于挑最新安装包）。返回 entries[]。"),
		func(ctx context.Context, a fileListIn) Envelope[fileListData] {
			depth := orDefault(a.MaxDepth, 1)
			if depth < 1 {
				depth = 1
			}
			cmd := "cd " + shQuote(a.Path) + " && find ./ -maxdepth " + strconv.Itoa(depth)
			if strings.TrimSpace(a.NameFilter) != "" {
				cmd += " -name " + shQuote(a.NameFilter)
			}
			if a.Sorted {
				cmd += " | sort -V"
			}
			return runEnvelope[fileListData](b, ctx, a.BaseIn, "file_list",
				map[string]any{"path": a.Path, "name_filter": a.NameFilter}, LkNone, "", true,
				func(c *Client) (any, error) {
					out, err := shell(c, cmd)
					if err != nil {
						return nil, err
					}
					if code := intOf(out["code"]); code != 0 {
						return failMap(out, fmt.Sprint(out["stderr"])), nil
					}
					entries := []string{}
					for _, line := range strings.Split(strings.TrimSpace(fmt.Sprint(out["stdout"])), "\n") {
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}
						entries = append(entries, strings.TrimPrefix(line, "./"))
					}
					return fileListData{Entries: entries, Count: len(entries)}, nil
				})
		})

	addTyped(s, write("file_mkdir",
		"创建远程目录",
		"在靶机递归创建目录。什么时候用：上传文件或解压前要确保目标目录存在时。目录已存在时设备会返回失败（Python os.makedirs 语义，不幂等）——需要幂等请先用 file_stat 判断。path 填靶机绝对路径。"),
		func(ctx context.Context, a filePathIn) Envelope[fileOpData] {
			return runEnvelope[fileOpData](b, ctx, a.BaseIn, "file_mkdir", map[string]any{"path": a.Path},
				LkNone, "", false, func(c *Client) (any, error) {
					return fileOpData{OK: true, Path: a.Path}, c.Mkdir(a.Path)
				})
		})

	addTyped(s, destructive("file_remove",
		"删除远程文件/目录",
		"删除靶机上的文件或目录，recursive=true 时递归删除。什么时候用：清理临时文件、安装包、旧备份时。不可恢复，删目录务必确认路径。path 填靶机绝对路径。"),
		func(ctx context.Context, a fileRemoveIn) Envelope[fileOpData] {
			// 缺省 true：与 schema 描述、方案 §4.10 一致。`rm -f <dir>` 必然非零退出，
			// 模型按描述省略参数来删目录会直接失败。
			recursive := true
			if a.Recursive != nil {
				recursive = *a.Recursive
			}
			flags := "-rf"
			if !recursive {
				flags = "-f"
			}
			cmd := "rm " + flags + " " + shQuote(a.Path)
			return runEnvelope[fileOpData](b, ctx, a.BaseIn, "file_remove", map[string]any{"path": a.Path},
				LkNone, "", false, func(c *Client) (any, error) {
					out, err := shell(c, cmd)
					if err != nil {
						return nil, err
					}
					if code := intOf(out["code"]); code != 0 {
						return failMap(out, fmt.Sprint(out["stderr"])), nil
					}
					return fileOpData{OK: true, Path: a.Path}, nil
				})
		})

	addTyped(s, ro("file_get",
		"下载远程文件到桥",
		"把靶机上的文件下载到桥的下载目录。什么时候用：文件在远程靶机上、本地读不到时（pcap、日志、安装包回传）；本地文件请用 Read。remote_path 填靶机绝对路径；local_name 只能填文件名，会拼在桥的下载目录下，禁止绝对路径。返回 {name,size_bytes,sha256}。"),
		func(ctx context.Context, a fileGetIn) Envelope[FileData] {
			name := a.LocalName
			if name == "" {
				name = filepath.Base(a.RemotePath)
			}
			if strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
				return allFailedEnvelope[FileData](a.Targets, "local_name 只能是文件名，不能带路径", ErrBusiness)
			}
			return runEnvelope[FileData](b, ctx, a.BaseIn, "file_get",
				map[string]any{"remote_path": a.RemotePath, "local_name": name}, LkNone, "", true,
				func(c *Client) (any, error) {
					dest := filepath.Join(b.DownloadDir, name)
					n, sum, err := httpDownload(c.Host, orDefault(a.HTTPPort, 9001), a.RemotePath, dest,
						timeoutFor(a.BaseIn, "file_get"))
					if err != nil {
						return nil, err
					}
					return FileData{Name: name, SizeBytes: n, SHA256: sum}, nil
				})
		})

	addTyped(s, write("file_put",
		"上传本地文件到靶机",
		"把桥本地文件上传到靶机指定路径。什么时候用：要在靶机上执行脚本、或把 pcap 交给 replay_run 前。local_path 填桥上的路径；remote_path 填靶机绝对路径。返回 {name,size_bytes,sha256}。上传后需要执行权限的，接 shell_exec chmod +x。"),
		func(ctx context.Context, a filePutIn) Envelope[FileData] {
			if _, err := os.Stat(a.LocalPath); err != nil {
				return allFailedEnvelope[FileData](a.Targets, "桥本地文件不存在: "+a.LocalPath, ErrBusiness)
			}
			return runEnvelope[FileData](b, ctx, a.BaseIn, "file_put",
				map[string]any{"local_path": a.LocalPath, "remote_path": a.RemotePath}, LkNone, "", false,
				func(c *Client) (any, error) {
					n, sum, err := httpUpload(c.Host, orDefault(a.HTTPPort, 9001), a.LocalPath, a.RemotePath,
						timeoutFor(a.BaseIn, "file_put"))
					if err != nil {
						return nil, err
					}
					return FileData{Name: filepath.Base(a.RemotePath), SizeBytes: n, SHA256: sum}, nil
				})
		})

	addTyped(s, write("file_unzip",
		"解压远程 zip",
		"解压靶机上的 zip 文件。什么时候用：安装包或日志包需要展开时。关键语义：设备侧解压失败常仍返回 ok，因此本工具会在解压后用 file_list 复核目标目录非空，为空则判 business 失败——调用方看到失败不代表命令没跑，可能只是包损坏。password_ref 传密码引用（密码只在桥内存，不出现在参数里）。"),
		func(ctx context.Context, a fileUnzipIn) Envelope[fileUnzipData] {
			passwd, ok := resolvePasswordRef(a.PasswordRef)
			if !ok {
				return allFailedEnvelope[fileUnzipData](a.Targets,
					"未知的 password_ref: "+a.PasswordRef+"（可用: "+strings.Join(passwordRefNames(), ", ")+"）", ErrBusiness)
			}
			outdir := a.Outdir
			return runEnvelope[fileUnzipData](b, ctx, a.BaseIn, "file_unzip",
				map[string]any{"file": a.File, "outdir": outdir, "password_ref": a.PasswordRef}, LkNone, "", false,
				func(c *Client) (any, error) {
					dir := outdir
					if dir == "" {
						dir = filepath.Dir(a.File)
					}
					// 解压前先记下已有条目：设备侧 unzip 失败常仍回 ok，
					// 只看"非空"会被同目录里的旧文件骗过去。
					before, err := listEntries(c, dir)
					if err != nil {
						return nil, err
					}
					if err := c.Unzip(a.File, outdir, passwd, true); err != nil {
						return nil, err
					}
					after, err := listEntries(c, dir)
					if err != nil {
						return nil, err
					}
					fresh := 0
					for k := range after {
						if !before[k] {
							fresh++
						}
					}
					if len(after) == 0 { // 假成功：设备回 ok 但目录为空
						return map[string]any{"_error": "解压后目标目录为空（设备侧 unzip 可能失败）: " + dir}, nil
					}
					if fresh == 0 {
						return map[string]any{"_error": "解压未产生新文件（设备侧 unzip 可能失败）: " + dir}, nil
					}
					return fileUnzipData{OK: true, Outdir: dir, VerifiedBy: "file_list",
						EntryCount: int64(len(after)), NewEntries: fresh}, nil
				})
		})

	addTyped(s, ro("file_transfer_hint",
		"生成传文件 curl 命令",
		"生成桥与靶机之间点对点传文件的 curl 命令，零网络调用、不执行传输。什么时候用：需要在别处（如另一台机器）人工执行 curl 时；直接传文件请用 file_get/file_put。返回每个靶机的 download/upload 命令模板。"),
		func(ctx context.Context, a fileTransferHintIn) Envelope[fileTransferHintData] {
			out := Envelope[fileTransferHintData]{Results: []Result[fileTransferHintData]{}, Failed: []Failure{}}
			resolved := b.resolve(a.Targets)
			if len(resolved) == 0 { // 同 runBatchResults：0/0 读起来像"全成功"
				return emptyResolveEnvelope[fileTransferHintData](a.Targets)
			}
			for _, t := range resolved {
				host := stripPortForURL(t)
				if strings.Contains(host, ":") {
					host = "[" + host + "]"
				}
				port := orDefault(a.HTTPPort, 9001)
				out.Ok++
				out.Results = append(out.Results, Result[fileTransferHintData]{Target: t, Data: fileTransferHintData{
					Target:   t,
					Download: fmt.Sprintf("curl -o 本地文件 \"http://%s:%d/files?path=<远端绝对路径>\"", host, port),
					Upload:   fmt.Sprintf("curl -F \"path=<远端绝对路径>\" -F \"file=@本地文件\" http://%s:%d/files", host, port),
				}})
			}
			out.Total = out.Ok
			return out
		})
}

func (b *Bridge) registerNetTools(s *mcp.Server) {
	addTyped(s, ro("net_route",
		"查默认路由与网卡",
		"查靶机默认路由与网卡名。什么时候用：抓包或回放前确认该用哪个网卡时。返回 routes{}，含默认路由与网卡。"),
		func(ctx context.Context, a BaseIn) Envelope[netRouteData] {
			return runEnvelope[netRouteData](b, ctx, a, "net_route", map[string]any{}, LkNone, "", true,
				func(c *Client) (any, error) {
					m, err := c.RouteInfo()
					if err != nil {
						return nil, err
					}
					return netRouteData{Routes: m}, nil
				})
		})

	addTyped(s, destructive("net_set_mtu",
		"设置网卡 MTU",
		"设置靶机网卡 MTU。什么时候用：回放前常需要把网卡 MTU 调大（如 2000）以承载大包；改完设备侧会等 5 秒。iface 填网卡名（如 \"eth0\"），mtu 填目标值。返回 {changed,iface,current}，读回不一致会判业务失败。"),
		func(ctx context.Context, a netSetMTUIn) Envelope[netMTUData] {
			mtu := orDefault(a.MTU, 2000)
			return runEnvelope[netMTUData](b, ctx, a.BaseIn, "net_set_mtu",
				map[string]any{"iface": a.Iface, "mtu": mtu}, LkNone, "", false,
				func(c *Client) (any, error) {
					if err := c.SetMTU(a.Iface, mtu); err != nil {
						return nil, err
					}
					cur, err := shell(c, "cat /sys/class/net/"+shQuote(a.Iface)+"/mtu")
					if err != nil {
						return nil, err
					}
					// 读回被杀留空会被判成"MTU 未生效"（假失败）——两者必须分开
					if cu, to := timeoutCleanup(cur); to {
						return nil, &CmdError{Msg: "MTU 已下发，但读回超时，无法确认是否生效", Cleanup: cu}
					}
					now := strings.TrimSpace(fmt.Sprint(cur["stdout"]))
					if now != strconv.Itoa(mtu) {
						// dt10 回执说成功但读回不一致 = 实际没生效，必须是失败而不是 ok+changed=false
						return map[string]any{"_error": fmt.Sprintf("MTU 未生效：期望 %d，读回 %q", mtu, now)}, nil
					}
					return netMTUData{Changed: true, Iface: a.Iface, Current: now}, nil
				})
		})

	addTyped(s, destructive("net_set_time",
		"设置靶机系统时间",
		"把靶机系统时间设为指定值并写入硬件时钟，随后读回核对。什么时候用：抓包时间戳需要对齐、或要多机同源时。time 留空取桥当前时间；格式如 \"2026-11-06 15:30:00\"。返回 {set,verify,match}。注意：无 RTC 的容器/虚拟机上写硬件时钟会失败，此时只记 warning，系统时间已生效。"),
		func(ctx context.Context, a netSetTimeIn) Envelope[netTimeData] {
			want := a.Time
			if strings.TrimSpace(want) == "" {
				want = time.Now().Format("2006-01-02 15:04:05")
			}
			return runEnvelope[netTimeData](b, ctx, a.BaseIn, "net_set_time",
				map[string]any{"time": want}, LkNone, "", false,
				func(c *Client) (any, error) {
					// date -s 失败 = 系统时间没改，必须报错；
					// hwclock -w 失败只警告——容器/VM 里没有 RTC，这条必然失败，
					// 但系统时间已经改好了。判整体失败会"报失败但实际做了"（评审 P3-7，
					// 方案 §12 #7 也预警了容器场景）。
					out, err := shell(c, "date -s "+shQuote(want))
					if err != nil {
						return nil, err
					}
					if code := intOf(out["code"]); code != 0 {
						return failMap(out, "设置时间失败: "+fmt.Sprint(out["stderr"])), nil
					}
					var warnings []string
					hw, err := shell(c, "hwclock -w")
					if err != nil {
						return nil, err
					}
					if cu, to := timeoutCleanup(hw); to {
						_ = cu
						warnings = append(warnings, "写硬件时钟超时（系统时间已设置）")
					} else if code := intOf(hw["code"]); code != 0 {
						warnings = append(warnings, "写硬件时钟失败: "+strings.TrimSpace(fmt.Sprint(hw["stderr"]))+"（系统时间已设置）")
					}
					cur, err := shell(c, "date '+%Y-%m-%d %H:%M:%S'")
					if err != nil {
						return nil, err
					}
					if _, to := timeoutCleanup(cur); to {
						return nil, &CmdError{Msg: "设置时间后读回超时", Cleanup: nil}
					}
					got := strings.TrimSpace(fmt.Sprint(cur["stdout"]))
					// 读回与目标可能差 1~2 秒（写入与读回之间走了一小段），超过 2 秒才算没生效
					const layout = "2006-01-02 15:04:05"
					tWant, e1 := time.ParseInLocation(layout, want, time.Local)
					tGot, e2 := time.ParseInLocation(layout, got, time.Local)
					match := got == want
					if e1 == nil && e2 == nil {
						diff := tGot.Sub(tWant)
						match = diff >= -2*time.Second && diff <= 2*time.Second
					}
					if !match {
						return map[string]any{"_error": fmt.Sprintf("对时未生效：期望 %q，读回 %q", want, got)}, nil
					}
					return netTimeData{Set: want, Verify: got, Match: true, Warning: strings.Join(warnings, "；")}, nil
				})
		})
}

// ---- 小工具 ----

// passwordRefs 密码引用名 → 密码。明文只存在于桥进程内存，不进工具参数、
// 不进审计、不落到靶机命令行。
var passwordRefs = map[string]string{
	"dpi_package": dpiPackagePassword, // 厂商发布包内层 zip 密码（install.py:753）
}

func resolvePasswordRef(ref string) (string, bool) {
	if ref == "" {
		return "", true
	}
	p, ok := passwordRefs[ref]
	return p, ok
}

func passwordRefNames() []string {
	out := make([]string, 0, len(passwordRefs))
	for k := range passwordRefs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// listEntries 列目录条目集合（相对路径），用于解压前后对比。
func listEntries(c *Client, dir string) (map[string]bool, error) {
	out, err := shell(c, "ls -A "+shQuote(dir)+" 2>/dev/null")
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, line := range strings.Split(fmt.Sprint(out["stdout"]), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			set[line] = true
		}
	}
	return set, nil
}

// getsize 未在 protocol.go 暴露成方法时补一个（dt11）。
func (c *Client) getsize(path string) (int64, error) {
	p, _ := json.Marshal(map[string]string{"path": path})
	if err := c.send(11, p); err != nil {
		return 0, err
	}
	b, err := c.recvUntilTimeout(500 * time.Millisecond)
	if err != nil {
		return 0, err
	}
	// agent dt11 回裸数字（os.path.getsize 的返回值直接 marshal）；兼容 {"res":n} 形态。
	var n int64
	if err := json.Unmarshal(b, &n); err == nil {
		return n, nil
	}
	var m struct {
		Res int64 `json:"res"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return 0, err
	}
	return m.Res, nil
}

// RouteInfo dt4：{"<iface>": {...}}。
func (c *Client) RouteInfo() (map[string]any, error) {
	if err := c.send(4, nil); err != nil {
		return nil, err
	}
	b, err := c.recvUntilTimeout(500 * time.Millisecond)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// SetMTU dt10（value=null 时设备只等 5 秒不改动，这里不暴露该分支）。
func (c *Client) SetMTU(eth string, mtu int) error {
	p, _ := json.Marshal(map[string]any{"eth": eth, "value": mtu})
	if err := c.send(10, p); err != nil {
		return err
	}
	if _, err := c.recvUntilTimeout(500 * time.Millisecond); err != nil {
		return err
	}
	return nil
}

// Mkdir dt9。
func (c *Client) Mkdir(dir string) error {
	p, _ := json.Marshal(map[string]string{"dir": dir})
	if err := c.send(9, p); err != nil {
		return err
	}
	b, err := c.recvUntilTimeout(500 * time.Millisecond)
	if err != nil {
		return err
	}
	// dt9 正常回 null。recvUntilTimeout 在真超时时返回空切片——空回包不等于成功，
	// 否则超时会被伪装成"目录已创建"。
	if len(b) == 0 {
		return fmt.Errorf("mkdir 无回执（超时或连接异常）: %s", dir)
	}
	if strings.TrimSpace(string(b)) != "null" {
		// 设备异常时会给 {"error": ...}
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			if e, has := m["error"]; has {
				return fmt.Errorf("mkdir 失败: %v", e)
			}
		}
	}
	return nil
}

// Unzip dt15：设备恒回裸 "ok"（失败也 ok），调用方需自行复核。
func (c *Client) Unzip(file, outdir, passwd string, overwrite bool) error {
	payload := map[string]any{"file": file, "overwrite": overwrite}
	if outdir != "" {
		payload["outdir"] = outdir
	}
	if passwd != "" {
		payload["passwd"] = passwd
	}
	// 与 dt1/dt0/dt131 同一条版本门：老 agent 收到未知键会 strictKeys 断连
	if v := c.agentTimeoutS(); v > 0 && c.supportsTimeoutS() {
		payload["timeout_s"] = v
	}
	p, _ := json.Marshal(payload)
	if err := c.send(15, p); err != nil {
		return err
	}
	b, err := c.recvUntilTimeout(500 * time.Millisecond)
	if err != nil {
		return err
	}
	// 老语义是裸 "ok"；只有新版 agent 超时才会回 gzip 结构化回执（见 unzipCmd）。
	if m := decodeGzipFrame(b); m != nil {
		if cu, timedOut := timeoutCleanup(m); timedOut {
			return &CmdError{Msg: "解压超时，靶机已终止 unzip", Cleanup: cu}
		}
	}
	return nil
}

// decodeGzipFrame 尝试把 [4B len][gzip JSON] 解成 map；不是该形状返回 nil。
func decodeGzipFrame(b []byte) map[string]any {
	if len(b) < 8 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(b[:4]))
	if n <= 0 || 4+n > len(b) || b[4] != 0x1f || b[5] != 0x8b {
		return nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(b[4 : 4+n]))
	if err != nil {
		return nil
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil
	}
	m := map[string]any{}
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// httpDownload 经 :9001 流式下载到本地文件，返回字节数与 sha256。
func httpDownload(host string, port int, remotePath, dest string, timeoutSec int) (int64, string, error) {
	u := fmt.Sprintf("http://%s:%d/files?path=%s", urlHost(host), port, url.QueryEscape(remotePath))
	cli := httpClient(timeoutSec, "")
	resp, err := cli.Get(u)
	if err != nil {
		return 0, "", fmt.Errorf("下载失败（需靶机 1.7.0+ 开启 :9001）: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, "", fmt.Errorf("下载失败: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return 0, "", err
	}
	f, err := os.Create(dest)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(f, h), resp.Body, make([]byte, 1<<20))
	if err != nil {
		os.Remove(dest)
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// httpUpload 经 :9001 multipart 上传本地文件到远端绝对路径。
func httpUpload(host string, port int, localPath, remotePath string, timeoutSec int) (int64, string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	body := io.TeeReader(f, h)
	var buf strings.Builder
	boundary := "socketstackput"
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	fmt.Fprintf(&buf, "Content-Disposition: form-data; name=\"path\"\r\n\r\n")
	fmt.Fprintf(&buf, "%s\r\n", remotePath)
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	fmt.Fprintf(&buf, "Content-Disposition: form-data; name=\"file\"; filename=%q\r\n\r\n", filepath.Base(localPath))
	head := buf.String()

	pr, pw := io.Pipe()
	go func() {
		if _, err := io.WriteString(pw, head); err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.CopyBuffer(pw, body, make([]byte, 1<<20)); err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.WriteString(pw, "\r\n--"+boundary+"--\r\n"); err != nil {
			pw.CloseWithError(err)
			return
		}
		pw.Close()
	}()

	u := fmt.Sprintf("http://%s:%d/files", urlHost(host), port)
	req, err := http.NewRequest("POST", u, pr)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	resp, err := httpClient(timeoutSec, "").Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("上传失败（需靶机 1.7.0+ 开启 :9001）: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 {
		return 0, "", fmt.Errorf("上传失败: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return fi.Size(), hex.EncodeToString(h.Sum(nil)), nil
}

func urlHost(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func intOf(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int:
		return int64(x)
	case int64:
		return x
	case string:
		return intOf2(x)
	}
	return 0
}

func intOf2(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

// ---- shell_ ----

type shellExecIn struct {
	BaseIn
	Args string            `json:"args" jsonschema:"要执行的命令字符串，如 systemctl status xsa；不是数组（白名单非空时须命中前缀）"`
	Cwd  string            `json:"cwd,omitempty" jsonschema:"命令工作目录；留空用靶机登录用户的默认目录"`
	Env  map[string]string `json:"env,omitempty" jsonschema:"命令环境变量键值对（整替换子进程环境）。禁止传密码/Token——凭据由桥本地配置读取"`
	Wait *bool             `json:"wait,omitempty" jsonschema:"true 表示 等命令结束返回结果（缺省）；false 表示 立即返回无回显"`
}

type shellExecData struct {
	Code            int      `json:"code" jsonschema:"命令退出码；0 为成功；-1 表示 agent 侧超时并已杀进程组"`
	Stdout          string   `json:"stdout" jsonschema:"标准输出；超 64KB 会截断（见 stdout_truncated）"`
	Stderr          string   `json:"stderr" jsonschema:"标准错误"`
	StdoutTruncated bool     `json:"stdout_truncated,omitempty" jsonschema:"true 表示 stdout 已截断，内容不完整"`
	Note            string   `json:"note,omitempty" jsonschema:"补充说明，如 wait=false 时提示未返回回显"`
	Timeout         bool     `json:"timeout,omitempty" jsonschema:"true 表示 agent 到点终止了命令（配合 cleanup 看进程是否真停）"`
	Cleanup         *Cleanup `json:"cleanup,omitempty" jsonschema:"超时后的清理回执；verified 为 false 表示无法确认进程已退出"`
}

func (b *Bridge) registerShellTools(s *mcp.Server) {
	addTyped(s, destructive("shell_exec",
		"在靶机执行命令",
		"在靶机执行一条命令。什么时候用：操作远程靶机；本地命令请用 Bash。args 填完整命令字符串，如 \"systemctl status xsa\"（不是数组）。返回 results[].data{code,stdout,stderr}；stdout 超 64KB 截断并带 stdout_truncated=true。wait=false 为异步执行不返回回显。大段脚本或文件请先用 file_put 上传再执行，不要经命令内嵌。env 禁止传密码或 Token——凭据由桥本地配置读取。"),
		func(ctx context.Context, a shellExecIn) Envelope[shellExecData] {
			wait := true
			if a.Wait != nil {
				wait = *a.Wait
			}
			timeout := orDefault(a.Timeout, 60)
			if !wait && timeout > 15 {
				timeout = 15
			}
			log.Printf("shell_exec CALLED: targets=%v wait=%v args=%.120q", a.Targets, wait, a.Args)
			if len(b.Whitelist) > 0 {
				hit := false
				for _, w := range b.Whitelist {
					if strings.HasPrefix(strings.TrimSpace(a.Args), w) {
						hit = true
						break
					}
				}
				if !hit {
					log.Printf("shell_exec REJECTED by whitelist (allowed=%v)", b.Whitelist)
					return allFailedEnvelope[shellExecData](a.Targets, "命令不在白名单: "+a.Args, ErrBusiness)
				}
			}
			in := a.BaseIn
			in.Timeout = timeout
			return runEnvelope[shellExecData](b, ctx, in, "shell_exec",
				map[string]any{"args": a.Args, "cwd": a.Cwd, "wait": wait}, LkShell, "", false,
				func(c *Client) (any, error) {
					m, err := c.CmdExec(a.Args, a.Cwd, a.Env, wait)
					if err != nil {
						return nil, err
					}
					if m == nil {
						return map[string]any{"note": "wait=false 为异步执行不返回回显;需要 stdout 请 wait=true"}, nil
					}
					return m, nil
				})
		})
}
