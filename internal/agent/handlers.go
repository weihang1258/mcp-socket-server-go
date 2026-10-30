// Package agent 复刻 socket_server 靶机侧服务（设计文档 §2/§3）。
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Version 靶机版本号（dt14/dt19 上报；发行时 -ldflags 覆盖）。
var Version = "1.9.4"

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
	case 7: // isfile：{"file": path} → {"res":bool}；**data 未知键 TypeError → 断连
		if err := strictKeys("isfile", payload, "file"); err != nil {
			return nil, err
		}
		if err := requireKeys("isfile", payload, "file"); err != nil {
			return nil, err
		}
		var p struct {
			File string `json:"file"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		fi, err := os.Stat(p.File)
		return json.Marshal(resBool(err == nil && !fi.IsDir()))
	case 8: // isdir：{"dir": path} → {"res":bool}；**data 未知键 → 断连
		if err := strictKeys("isdir", payload, "dir"); err != nil {
			return nil, err
		}
		if err := requireKeys("isdir", payload, "dir"); err != nil {
			return nil, err
		}
		var p struct {
			Dir string `json:"dir"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		fi, err := os.Stat(p.Dir)
		return json.Marshal(resBool(err == nil && fi.IsDir()))
	case 9: // mkdir：os.makedirs 语义——已存在 → FileExistsError → 断连（quirk）；递归创建；未知键 → 断连
		if err := strictKeys("mkdir", payload, "dir"); err != nil {
			return nil, err
		}
		if err := requireKeys("mkdir", payload, "dir"); err != nil {
			return nil, err
		}
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
	case 10: // 改 MTU：解析两种格式；不等则设置 + sleep 5s；ifconfig 缺失 → 断连；未知键 → 断连
		if err := strictKeys("mtu", payload, "eth", "value"); err != nil {
			return nil, err
		}
		if err := requireKeys("mtu", payload, "eth"); err != nil {
			return nil, err
		}
		var p struct {
			Eth   string `json:"eth"`
			Value *int   `json:"value"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		value := 2000 // Python mtu(eth, value=2000) 默认值（netutils.py:113）
		var rawMTU map[string]json.RawMessage
		json.Unmarshal(payload, &rawMTU)
		valueNone := string(rawMTU["value"]) == "null"
		if p.Value != nil {
			value = *p.Value
		}
		if valueNone {
			// Python value=None：`int != None` 恒真 → `ifconfig eth mtu None` 必败
			// （exec 吞错误）→ sleep(5) → res null，网卡不被改动
			time.Sleep(5 * time.Second)
			return json.Marshal(resNull())
		}
		set, err := setMTU(p.Eth, value)
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
	case 15: // 解压 zip：恒回裸 b"ok"（unzip 缺失/失败也 ok）；**data 未知键 → 断连
		if err := strictKeys("unzip", payload, "file", "outdir", "passwd", "overwrite"); err != nil {
			return nil, err
		}
		if err := requireKeys("unzip", payload, "file"); err != nil {
			return nil, err
		}
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
	case 18: // ensure_command：which → 装后复查（install_cmd shell 跑一次再查）；未知键 → 断连
		if err := strictKeys("ensure_command", payload, "cmd", "install_cmd"); err != nil {
			return nil, err
		}
		if err := requireKeys("ensure_command", payload, "cmd"); err != nil {
			return nil, err
		}
		var p struct {
			Cmd        string `json:"cmd"`
			InstallCmd string `json:"install_cmd"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		return json.Marshal(resBool(ensureCommand(p.Cmd, p.InstallCmd)))
	case 19: // 版本详情（纯本地，键序对齐 Python 字典插入序）
		return json.Marshal(struct {
			Version       string `json:"version"`
			Repo          string `json:"repo"`
			ReleaseNotes  string `json:"release_notes"`
			LatestVersion string `json:"latest_version"`
			HasUpgrade    bool   `json:"has_upgrade"`
		}{Version, Repo, ReleaseNotes, NotesVersion, NotesVersion != Version})
	case 0: // pcap 回放：truthy 校验固定文案；stats JSON 裸文本
		return replayFiles(payload)
	case 5: // 抓包开始：{"res":bool}（回退后契约，无 error）；严格键（**data TypeError）
		if err := strictKeys("tcpdump_start", payload, "eth", "path", "extended", "single_queue"); err != nil {
			return nil, err
		}
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
		ok, err := tcpdumpStart(p.Eth, p.Path, p.Extended, sq)
		if err != nil {
			return nil, err // routeinfo 等异常冒泡断连
		}
		return json.Marshal(resBool(ok))
	case 6: // 抓包停止：严格键
		if err := strictKeys("tcpdump_stop", payload, "path"); err != nil {
			return nil, err
		}
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
	case 20: // 升级推送落地：同步段返回终态；后台 0.3s 后切链+重启
		resp, rv := applyPushedUpgrade(payload)
		if rv != "" {
			go restartAfterUpgrade(rv)
		}
		return resp, nil
	case 131: // 拨测（预检链 + 封堵/重定向）
		return doBoce(payload)
	case 200: // pcap 五元组提取（完整实现在 pcapflow 模块；此处先契约化错误路径）
		return pcapFlowExtract(payload)
	}
	return nil, nil
}

// strictKeys 校验 payload 键白名单（Python **data 未知键 TypeError → 断连）；
// fn 仅用于错误文案对齐 Python TypeError 的真实函数名。
func strictKeys(fn string, payload []byte, allowed ...string) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return err
	}
	set := map[string]bool{}
	for _, a := range allowed {
		set[a] = true
	}
	for k := range raw {
		if !set[k] {
			return fmt.Errorf("%s() got unexpected keyword argument %q", fn, k)
		}
	}
	return nil
}

// requireKeys 缺必需键/值为 null → TypeError（Python **data 缺位置参数 → 断连）。
func requireKeys(fn string, payload []byte, required ...string) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return err
	}
	for _, k := range required {
		r, ok := raw[k]
		if !ok || string(r) == "null" {
			return fmt.Errorf("%s() missing required argument: '%s'", fn, k)
		}
	}
	return nil
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
