// Package agent 复刻 socket_server 靶机侧服务（设计文档 §2/§3）。
package agent

import "encoding/json"

// Version 靶机版本号（dt14/dt19 上报；发行时 -ldflags 覆盖）。
var Version = "1.9.0"

// Repo 升级互操作的仓库标识（dt19）。
const Repo = "weihang1258/socket_server"

// Do 是业务处理器：返回响应字节（nil = 无响应，连接继续）；
// 返回 error → 记日志并断连（对齐 Python do() 异常 → 顶层捕获 → close 无响应）。
type DoFunc func(cs *ConnState, dt int32, payload []byte) ([]byte, error)

// Do datatype 分发（handlers 逐模块补齐）。
func Do(cs *ConnState, dt int32, payload []byte) ([]byte, error) {
	switch dt {
	case 14: // 获版本号：json.dumps(VERSION) 带引号 JSON 字符串
		return json.Marshal(Version)
	case 200: // pcap 五元组提取（完整实现在 pcapflow 模块；此处先契约化错误路径）
		return pcapFlowExtract(payload)
	}
	return nil, nil
}
