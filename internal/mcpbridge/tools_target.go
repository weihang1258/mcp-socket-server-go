package mcpbridge

// target_ 分类：登记、查看、移除靶机（方案 §4.1）。
// 这三个工具不继承 BaseIn——它们操作的是桥自己的登记表，不是靶机上的动作。

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type targetInfo struct {
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Tags      []string `json:"tags"`
	Note      string   `json:"note"`
	CreatedAt string   `json:"created_at"`
}

type targetListOut struct {
	Targets []targetInfo `json:"targets"`
}

type targetAddIn struct {
	Host        string   `json:"host" jsonschema:"靶机 IP 或主机名（IPv6 裸地址，自动剥方括号）"`
	Port        int      `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口，缺省 9000"`
	Tags        []string `json:"tags,omitempty" jsonschema:"标签列表，用于 @tag 选机"`
	Note        string   `json:"note,omitempty" jsonschema:"备注（如机器用途）"`
	Force       bool     `json:"force,omitempty" jsonschema:"true = 跳过探活强制注册离线靶机，缺省 false"`
	Description string   `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的（进审计与界面），不超过 50 字"`
}

type targetAddOut struct {
	Registered bool   `json:"registered"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Error      string `json:"error,omitempty"`
}

type targetRemoveIn struct {
	Host        string `json:"host" jsonschema:"靶机 IP 或主机名"`
	Port        int    `json:"port,omitempty" jsonschema:"靶机 socket_server TCP 端口，缺省 9000"`
	Description string `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的（进审计与界面），不超过 50 字"`
}

type targetRemoveOut struct {
	Removed bool   `json:"removed"`
	Error   string `json:"error,omitempty"`
}

func (b *Bridge) registerTargetTools(s *mcp.Server) {
	addTyped(s, ro("target_list",
		"列出已登记靶机（本机 SQLite，不发网络请求）。选机、排查「为什么 @tag 没展开」时先调。返回 targets[]，每项含 host/port/tags/note/created_at。超时缺省 5 秒，依据：本地查询。"),
		func(ctx context.Context, a targetListArgs) targetListOut {
			rows := b.Registry.ListTargets()
			out := targetListOut{Targets: make([]targetInfo, 0, len(rows))}
			for _, r := range rows {
				ti := targetInfo{}
				ti.Host, _ = r["host"].(string)
				ti.Port, _ = r["port"].(int)
				ti.Note, _ = r["note"].(string)
				ti.CreatedAt, _ = r["created_at"].(string)
				ti.Tags, _ = r["tags"].([]string)
				if ti.Tags == nil {
					ti.Tags = []string{}
				}
				out.Targets = append(out.Targets, ti)
			}
			return out
		})

	addTyped(s, write("target_add",
		"登记靶机；注册前先 TCP 探活，不通则拒绝（force=true 跳过）。tags 用于 @tag 选机。返回 {registered,host,port}；失败时 registered=false 且 error 说明原因（探活失败 / 重复登记）。超时缺省 10 秒，依据：内部探活 3 秒 + 本地写库。"),
		func(ctx context.Context, a targetAddIn) targetAddOut {
			host := strings.Trim(a.Host, "[]")
			port := orDefault(a.Port, 9000)
			if !a.Force {
				if err := probe(host, port, 3); err != nil {
					return targetAddOut{Host: host, Port: port,
						Error: fmt.Sprintf("%s:%d 不可达（TCP connect 失败: %v），未注册；force=true 可强制注册", host, port, err)}
				}
			}
			r := b.Registry.AddTarget(host, port, a.Tags, a.Note)
			if ok, _ := r["ok"].(bool); !ok {
				msg, _ := r["error"].(string)
				return targetAddOut{Host: host, Port: port, Error: msg}
			}
			return targetAddOut{Registered: true, Host: host, Port: port}
		})

	addTyped(s, destructive("target_remove",
		"从登记表移除靶机；有活跃锁或活跃监听时拒绝（先 listen_stop）。返回 {removed} 或错误原因。超时缺省 10 秒，依据：本地操作。"),
		func(ctx context.Context, a targetRemoveIn) targetRemoveOut {
			port := orDefault(a.Port, 9000)
			// quirk：锁/liveness/删除键全用原始 host（不剥方括号）
			if b.Locks.HasActive(a.Host) {
				return targetRemoveOut{Error: fmt.Sprintf("靶机 %s 有活跃锁，无法移除", a.Host)}
			}
			if b.Registry.GetListenLiveness(a.Host, port) {
				return targetRemoveOut{Error: fmt.Sprintf("靶机 %s 有活跃监听，请先 listen_stop", a.Host)}
			}
			r := b.Registry.RemoveTarget(a.Host, port)
			if ok, _ := r["ok"].(bool); !ok {
				msg, _ := r["error"].(string)
				return targetRemoveOut{Error: msg}
			}
			return targetRemoveOut{Removed: true}
		})
}

type targetListArgs struct {
	Description string `json:"description,omitempty" jsonschema:"一句话说明本次调用的目的（进审计与界面），不超过 50 字"`
}
