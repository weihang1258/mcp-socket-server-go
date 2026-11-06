// 传输（transport.py 移植）：stdio（本地）+ Streamable HTTP（:PORT/mcp）。
// DNS rebinding 保护关闭对齐 Python（内网信任，设计 §1 非目标）。
package mcpbridge

import (
	"context"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ServerInstructions 服务级说明：客户端在 initialize 时拿到，作为独立的
// MCP instructions 块交给模型。这是「这组工具管什么」的唯一服务级入口——
// 45 个子工具描述装不下整体认知，没有它模型只知道有一堆 file_get/shell_exec，
// 不知道该在什么场景想起来。
//
// 写作原则：
//   - 只说自己是什么（远程主机操作），不说别的工具该用什么——harness 各不相同，
//     内置工具集不在本服务管辖范围内。
//   - 列全 11 类能力 + 触发关键词：ToolSearch 只做字面量匹配，模型得先想到
//     对应的词才搜得到。
const ServerInstructions = `本服务用于操作**远程主机**（也称靶机/服务器/设备）：通过 socket_server 协议连接
远端执行命令、传文件、抓包分析、流量回放、DPI 设备管理。所有操作发生在被连接的那台
机器上，不是运行本客户端的那台。

【能力总览（11 类 45 个工具）】
1. 主机登记：target_list（列出已登记）、target_add（登记新主机，会先探活）、target_remove（移除）。
2. 远程命令：shell_exec（在远端执行任意命令，返回 code/stdout/stderr）。
3. 文件传输：file_get（远端下载到本地）、file_put（本地上传到远端）、file_stat（查存在性/大小）、
   file_list（列目录）、file_mkdir、file_remove、file_unzip（解压）、file_transfer_hint（生成 curl 命令）。
4. 网络信息：net_route（默认路由与网卡）、net_set_mtu（改 MTU）、net_set_time（设系统时间）。
5. 抓包：capture_start（启动抓包，可指定网卡与过滤表达式）、capture_stop（停止并判断 pcap 完整性）。
6. 流量回放：replay_run（回放 pcap 文件，可限速、改五元组）。
7. 流量分析：pcap_extract_flows（从 pcap 直接提五元组流，不下载文件）。
8. 端口收流：listen_start（监听端口收流量）、listen_fetch（取回数据）、listen_save（存到远端）、
   listen_clean（清空）、listen_stop。
9. 拨测验证：probe_visit（用远端浏览器访问 URL，判断封堵/重定向是否生效）。
10. 服务端自身：bridge_version（查远端 socket_server 版本）、bridge_upgrade（升级它）。
11. DPI 设备（深度包检测/防火墙类设备，18 个工具）：dpi_get_info（版本/模式/PCI）、dpi_service（启停主程序）、
    dpi_agent_service（启停升级 agent）、dpi_switch_mode（切工作模式）、dpi_apply_config（改配置并重启）、
    dpi_get_config、dpi_read_stat（读状态文件）、dpi_wait_stat（等指标达标）、dpi_wait_file（等文件写完）、
    dpi_check_stalled（查线程卡死）、dpi_policy_get（读策略）、dpi_policy_put（下发策略）、
    dpi_policy_write（写策略资产）、dpi_policy_wait（等策略生效）、
    dpi_backup、dpi_prepare_package（准备安装包）、dpi_install（全新安装）、dpi_upgrade（升级固件）。

【什么时候该用本服务——看到这些词就该找这里】
远程 / 远端 / 靶机 / 测试机 / 被测设备 / 目标主机 / 某台机器 / 那台服务器；
抓包 / 抓流量 / tcpdump / pcap / 报文 / 五元组 / 流统计 / 流量分析；
回放 / 重放 / replay / 打流 / 压测流量 / 限速回放；
端口监听 / 收流量 / 收包 / 监听某端口；
上传到远端 / 下载回来 / 传到靶机 / 取回文件 / 远端路径 / 远端目录；
DPI / 防火墙 / 策略下发 / 封堵 / 重定向 / 模式切换 / 安装固件 / 升级设备 / 设备备份；
拨测 / 验证封堵 / 访问某 URL 看通不通；
远端执行命令 / 在靶机上跑 / 远程 shell。

【典型调用序列】
- 第一次接触：target_list 看有哪些 → target_add 登记（会先探活）。
- 执行远端命令：shell_exec（args 是完整命令字符串，如 "systemctl status xsa"）。
- 传文件：file_put 上传 → shell_exec chmod +x → 执行；回传用 file_get。
- 抓包分析：net_route 确认网卡 → capture_start → 跑业务流量 → capture_stop → file_get 取回 pcap。
- 回放对比：file_put 传 pcap → replay_run；要同时抓包请用另一台主机（同机互斥）。
- 端口收流：listen_start → 业务流量 → listen_fetch（回本地）或 listen_save（留远端）→ listen_stop。
- DPI 设备：dpi_get_info 看现状 → dpi_prepare_package → dpi_install / dpi_upgrade → dpi_get_info 复核。

【结果约定】
所有工具返回统一信封：{ok, total, results[], failed[]}。
- results[].data 是该工具的具体结果，字段含义见各工具 outputSchema。
- failed[] 每项含 target / reason / error_type（network | timeout | business）。
- error_type=timeout 时可能带 cleanup{killed,verified}；verified 为 false 表示
  无法确认远端进程已退出，不要假定环境已释放。
- 多台主机用 targets 传数组，或 @tag 按标签批量选；工具名不带服务前缀但都属于本服务。
- 不可逆操作（file_remove / dpi_install / dpi_upgrade / dpi_switch_mode）先确认路径和目标。`

// NewServer 构建 mcp.Server（serverInfo.version = 桥版本 0.4.0，与 dt14 分离）。
func NewServer(b *Bridge) *mcp.Server {
	impl := &mcp.Implementation{Name: "mcp-socket-server", Version: BridgeVersion}
	s := mcp.NewServer(impl, &mcp.ServerOptions{Instructions: ServerInstructions})
	b.RegisterTools(s)
	return s
}

// RunStdio 本地 stdio 模式（阻塞）。
func RunStdio(ctx context.Context, b *Bridge) error {
	s := NewServer(b)
	return s.Run(ctx, &mcp.StdioTransport{})
}

// listenAddrs MCP HTTP 监听地址列表（2026-11-02：所有监听端口 0.0.0.0 双栈）。
// host 为 IPv4 通配时补 [::] 一条（tcp4/tcp6 分开绑——net.Listen("tcp","0.0.0.0:p")
// 实际生成 AF_INET6 通配，直接叠加会 EADDRINUSE）；其余 host 原样单条。
func listenAddrs(host string, port int) []string {
	p := strconv.Itoa(port)
	if host == "0.0.0.0" {
		return []string{net.JoinHostPort("0.0.0.0", p), net.JoinHostPort("::", p)}
	}
	return []string{net.JoinHostPort(host, p)}
}

// RunStreamableHTTP Streamable HTTP（端点 /mcp），绑定 cfg host:port（阻塞）。
// host 为 IPv4 通配时双栈：v6 绑定失败降级仅 v4（与 agent :9000/:9001 同策略）。
func RunStreamableHTTP(ctx context.Context, b *Bridge, host string, port int) error {
	s := NewServer(b)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true}) // 对齐 Python 显式关闭 rebinding 保护
	// WithSourceIP 必须在 handler 外层：go-sdk 用 req.Context() 建会话，
	// 中间件注入的值才能传到工具 handler（streamable.go:700）。
	srv := &http.Server{Handler: WithSourceIP(handler)}
	addrs := listenAddrs(host, port)
	network := "tcp4"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "tcp6" // 具体 IPv6 地址（::1 等）不能用 tcp4；双栈通配仍显式分绑
	}
	ln, err := net.Listen(network, addrs[0])
	if err != nil {
		return err
	}
	if len(addrs) == 2 {
		if ln6, err6 := net.Listen("tcp6", addrs[1]); err6 == nil {
			defer ln6.Close()
			go srv.Serve(ln6) //nolint:errcheck // Serve 在 Close 后返回 ErrServerClosed
			log.Printf("MCP Streamable HTTP 监听 %s/mcp (IPv6, 双栈)", addrs[1])
		} else {
			log.Printf("MCP Streamable HTTP IPv6 监听失败:%v,降级为仅 IPv4 模式", err6)
		}
	}
	log.Printf("MCP Streamable HTTP 监听 %s/mcp (log_level=%s)", addrs[0], b.Cfg.LogLevel)
	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
