// Package agent 复刻 socket_server 靶机侧服务（设计文档 §2/§3）。
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Version 靶机版本号（dt14/dt19 上报；发行时 -ldflags 覆盖）。
var Version = "1.9.0"

// Repo 升级互操作的仓库标识（dt19）。
const Repo = "weihang1258/socket_server"

// ReleaseNotes/NotesVersion dt19 版本说明（打包/构建时注入；本地构建二者同源 → has_upgrade=false）。
var (
	ReleaseNotes = ""
	NotesVersion = Version
)

// Do 是业务处理器：返回响应字节（nil = 无响应，连接继续）；
// 返回 error → 记日志并断连（对齐 Python do() 异常 → 顶层捕获 → close 无响应）。
type DoFunc func(cs *ConnState, dt int32, payload []byte) ([]byte, error)

// Do datatype 分发（handlers 逐模块补齐）。
func Do(cs *ConnState, dt int32, payload []byte) ([]byte, error) {
	switch dt {
	case 1: // 命令执行：[4B i][gzip {code,stdout,stderr}]；wait=false 回 "null" 帧
		return cmdExec(payload)
	case 3: // 文件下载：路径读连接级 filepath（payload 仅 {"gzip":bool}）；[8B <Q][content]
		return downloadFile(cs, payload)
	case 4: // routeinfo：失败 → error → 断连（Python 抛 RuntimeError）
		m, err := routeinfo()
		if err != nil {
			return nil, err
		}
		return json.Marshal(m)
	case 7: // isfile：{"file": path} → {"res":bool}
		var p struct {
			File string `json:"file"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		fi, err := os.Stat(p.File)
		return json.Marshal(resBool(err == nil && !fi.IsDir()))
	case 8: // isdir：{"dir": path} → {"res":bool}
		var p struct {
			Dir string `json:"dir"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		fi, err := os.Stat(p.Dir)
		return json.Marshal(resBool(err == nil && fi.IsDir()))
	case 9: // mkdir：os.makedirs 语义——已存在 → FileExistsError → 断连（quirk）；递归创建
		var p struct {
			Dir string `json:"dir"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if _, err := os.Stat(p.Dir); err == nil {
			return nil, fmt.Errorf("os.makedirs: %s 已存在（Python FileExistsError）", p.Dir)
		}
		if err := os.MkdirAll(p.Dir, 0o777); err != nil {
			return nil, err
		}
		return json.Marshal(resNull())
	case 10: // 改 MTU：解析两种格式；不等则设置 + sleep 5s；ifconfig 缺失 → 断连
		var p struct {
			Eth   string `json:"eth"`
			Value int    `json:"value"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		set, err := setMTU(p.Eth, p.Value)
		if err != nil {
			return nil, err
		}
		if set {
			time.Sleep(5 * time.Second)
		}
		return json.Marshal(resNull())
	case 11: // 取字节数：os.path.getsize，失败 → 断连
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		fi, err := os.Stat(p.Path)
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			Res int64 `json:"res"`
		}{fi.Size()})
	case 14: // 获版本号：json.dumps(VERSION) 带引号 JSON 字符串
		return json.Marshal(Version)
	case 15: // 解压 zip：恒回裸 b"ok"（unzip 缺失/失败也 ok）
		return unzipCmd(payload)
	case 171: // socket监听-启动
		return listenStart(payload)
	case 172: // socket监听-清理数据
		return listenClean()
	case 173: // socket监听-保存数据
		return listenSave(payload)
	case 174: // socket监听-传输数据流
		return listenFetch()
	case 175: // socket监听-停止监听
		return listenStop()
	case 18: // ensure_command：PATH 查找 → {"res":bool}
		var p struct {
			Cmd string `json:"cmd"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		return json.Marshal(resBool(ensureCommand(p.Cmd)))
	case 19: // 版本详情（纯本地，键序对齐 Python 字典插入序）
		return json.Marshal(struct {
			Version       string `json:"version"`
			Repo          string `json:"repo"`
			ReleaseNotes  string `json:"release_notes"`
			LatestVersion string `json:"latest_version"`
			HasUpgrade    bool   `json:"has_upgrade"`
		}{Version, Repo, ReleaseNotes, NotesVersion, NotesVersion != Version})
	case 5: // 抓包开始：{"res":bool}（回退后契约，无 error）
		var p struct {
			Eth         string `json:"eth"`
			Path        string `json:"path"`
			Extended    string `json:"extended"`
			SingleQueue *bool  `json:"single_queue"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		sq := true
		if p.SingleQueue != nil {
			sq = *p.SingleQueue
		}
		if p.Path == "" {
			p.Path = "/home/tmp/tmp.pcap"
		}
		return json.Marshal(resBool(tcpdumpStart(p.Eth, p.Path, p.Extended, sq)))
	case 6: // 抓包停止：{"res":bool}；幂等（未在抓 res:true）
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		if p.Path == "" {
			p.Path = "/home/tmp/tmp.pcap"
		}
		return json.Marshal(resBool(tcpdumpStop(p.Path)))
	case 131: // 拨测（预检链 + 封堵/重定向）
		return doBoce(payload)
	case 200: // pcap 五元组提取（完整实现在 pcapflow 模块；此处先契约化错误路径）
		return pcapFlowExtract(payload)
	}
	return nil, nil
}

// resBool/resNull 统一 {"res":...} 包装（Python json.dumps({"res": ...})）。
func resBool(b bool) resWrapBool { return resWrapBool{Res: b} }
func resNull() resWrapNull       { return resWrapNull{} }

type resWrapBool struct {
	Res bool `json:"res"`
}

type resWrapNull struct {
	Res *struct{} `json:"res"`
}
