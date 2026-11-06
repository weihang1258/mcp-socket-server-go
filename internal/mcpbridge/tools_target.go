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
	Force       bool     `json:"force,omitempty" jsonschema:"true 表示 跳过探活强制注册离线靶机，缺省 false"`
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
		"列出已登记靶机",
		"列出已登记靶机，读本机登记表不发网络请求。什么时候用：任何靶机操作的第一步——先确认有哪些靶机、各自标签，或排查「为什么 @tag 没展开」时。返回 targets[]，每项含 host/port/tags/note/created_at。"),
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
		"登记靶机",
		"登记靶机到桥的登记表。什么时候用：新机器要纳入管理时；登记后其它工具才能用 host 或 @tag 选中它。注册前会先做 TCP 探活，不通则拒绝；force=true 可跳过探活登记离线机器。tags 用于后续 @tag 批量选机，如 [\"lab\",\"dpi\"]。返回 {registered,host,port}；失败时 registered=false 且 error 说明原因（探活失败/重复登记）。"),
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
		"移除靶机",
		"从登记表移除靶机。什么时候用：机器下线、或要重新登记前。有活跃锁或活跃监听时会被拒绝——先 listen_stop 再移除。返回 {removed} 或错误原因。"),
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
