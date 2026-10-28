package agent

import (
	"errors"
	"sync/atomic"
)

// ConnState 连接级状态（设计 §2）。
// Python protocol.setup() 只初始化 filepath="tmp"/content/bin_recv_flag/length；
// gzip 由 dt21 首次赋值 —— 未经 dt21 触碰 dt24 即 AttributeError 断连（quirk，gzipSet 复刻）。
type ConnState struct {
	filepath *string // nil = Python 的 None（dt21 缺 filepath 后 dt3/dt24 均断连）
	content  []byte
	bin      bool
	length   uint64
	gzipSet  bool
	gzip     bool
}

func newConnState() *ConnState {
	tmp := "tmp"
	return &ConnState{filepath: &tmp}
}

// Filepath 返回连接级文件路径（dt3 下载用）；nil 对应 Python None（调用方必须断连）。
func (cs *ConnState) Filepath() *string { return cs.filepath }

// activeClients 活跃客户端计数（覆盖所有 :9000 连接，含 MCP 桥空闲池连接——dt20
// 的 active_clients>1 拒绝升级按此语义；计数含 dt20 自身这条连接）。
var activeClients atomic.Int64

func clientConnected()    { activeClients.Add(1) }
func clientDisconnected() { activeClients.Add(-1) }

// Clients 当前活跃连接数（dt20 升级判定用）。
func Clients() int64 { return activeClients.Load() }

// errNilFilepath dt3/dt24 在 filepath=None 时的断连错误（对齐 Python open(None)）。
var errNilFilepath = errors.New("filepath is None (dt21 未提供)")
