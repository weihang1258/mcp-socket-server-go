package mcpbridge

// dpi_ 设备、配置、策略、安装升级（方案 §4.10.1 / §4.10.3 / §4.10.4）。
//
// 原项目所有 DPI 动作最终都落到 dt1 `cmd`（device/dpi.py 里统一用 self.cmd），
// 所以这些工具全部是桥侧编排：拼命令 → 在靶机执行 → 解析输出，不需要改 agent 协议。

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const dpiPath = "/opt/dpi"

// policyFiles 策略/配置资产白名单（device/dpi_constants.py:action2policyfile 等）。
// resource_id 只能取这里的键，禁止传任意路径。
var policyFiles = map[string]string{
	"eu_plc":    "/opt/dpi/euconf/rule/eu_policy.rule",
	"pcapdump":  "/opt/dpi/xsaconf/rule/pcapdump.rule",
	"mirr":      "/opt/dpi/xsaconf/rule/mirror.rule",
	"vpn_block": "/opt/dpi/xsaconf/rule/vpn_block.rule",

	"house_ipsegs":     "/opt/dpi/xsaconf/rule/house_ipsegs.txt",
	"pcip_ipsegs":      "/opt/dpi/xsaconf/rule/pcip_ipsegs.txt",
	"commem_ini":       "/opt/dpi/xsaconf/common.ini",
	"access_log":       "/opt/dpi/euconf/rule/access_log.rule",
	"xdr_filter":       "/opt/dpi/xdrconf/rule/xdr_filter.rule",
	"bzip_ipsegs":      "/opt/dpi/xsaconf/rule/zcip_ipsegs.txt",
	"overseaip_ipsegs": "/opt/dpi/xsaconf/rule/overseaip_ipsegs.txt",
}

// ---- 入参 ----

type dpiConfigIn struct {
	BaseIn
	Kind string `json:"kind" jsonschema:"配置种类：xsa（xsaconf/xsa.json）| mod_cfg（模块配置文件）| xdr_template（xdrconf/rule/xdr_template.json）"`
}

type dpiApplyConfigIn struct {
	BaseIn
	Xsa            map[string]any `json:"xsa,omitempty" jsonschema:"xsa.json 改动，键用点号表示嵌套路径，如 {\"devinfo.province_id\": 117}"`
	ModCfg         map[string]any `json:"mod_cfg,omitempty" jsonschema:"模块配置开关，如 {\"httpproto\": 1}"`
	XdrTemplate    map[string]any `json:"xdr_template,omitempty" jsonschema:"xdr 模板改动，键形如 \"<templete>.<xieyiname>.<key>\" 或 \"<key>\""`
	RestartTimeout int            `json:"restart_timeout,omitempty" jsonschema:"有改动时重启 DPI 的等待秒数，缺省 600"`
}

type dpiServiceIn struct {
	BaseIn
	Component string `json:"component" jsonschema:"组件：xsa（DPI 主程序）| dpi_monitor | policyserver"`
	Action    string `json:"action" jsonschema:"动作：start | stop | restart（dpi_monitor/policyserver 只支持 start/stop）"`
}

type dpiAgentServiceIn struct {
	BaseIn
	Action string `json:"action" jsonschema:"动作：start | stop | restart"`
}

type dpiSwitchModeIn struct {
	BaseIn
	Mode          string         `json:"mode" jsonschema:"目标模式，如 com_cmcc_is；同模式同配置时自动跳过"`
	Args          []string       `json:"args,omitempty" jsonschema:"切换命令的附加参数，缺省 [idc31]"`
	ModifiedParam map[string]any `json:"modified_param,omitempty" jsonschema:"切换前修改 mod_switch.sh 的开关，如 {\"wlan_switch\": \"1\"}"`
	Force         bool           `json:"force,omitempty" jsonschema:"true = 强制切换（即使模式相同），缺省 false"`
	PciCfg        map[string]any `json:"pcicfg,omitempty" jsonschema:"PCI 配置（pci_list/raw_port/src_mac/dst_mac），变化时先写 pci.cfg 再切"`
	AliveTimeout  int            `json:"alive_timeout,omitempty" jsonschema:"等 DPI 启动的秒数，缺省 600"`
}

type dpiPolicyGetIn struct {
	BaseIn
	ResourceID string `json:"resource_id" jsonschema:"策略/配置资产名（见工具描述白名单），如 eu_plc | pcapdump | mirr | vpn_block"`
}

type dpiPolicyPutIn struct {
	BaseIn
	ResourceID string   `json:"resource_id" jsonschema:"策略/配置资产名，同 dpi_policy_get"`
	Rules      []string `json:"rules" jsonschema:"策略行（整文件覆盖；空数组 = 清空策略）"`
	MD5Check   bool     `json:"md5check,omitempty" jsonschema:"true = 内容 md5 相同时跳过写入，缺省 false"`
}

type dpiPolicyWaitIn struct {
	BaseIn
	Kind     string `json:"kind" jsonschema:"action = 等策略加载条数 | adms = 等 ADMS 任务 adms_allrule_num"`
	Action   string `json:"action,omitempty" jsonschema:"仅 kind 为 action 时用：eu_plc | pcapdump | mirr | vpn_block"`
	Expected int    `json:"expected" jsonschema:"预期条数"`
	EveryS   int    `json:"every_s,omitempty" jsonschema:"轮询间隔秒，缺省 2"`
	WaitS    int    `json:"wait_s,omitempty" jsonschema:"最长等待秒数，缺省 60"`
}

type dpiPolicyWriteIn struct {
	BaseIn
	ResourceID string `json:"resource_id" jsonschema:"非策略类配置资产名（见白名单），如 house_ipsegs | access_log | xdr_filter"`
	Content    string `json:"content" jsonschema:"文件内容（整文件）"`
	Mode       string `json:"mode,omitempty" jsonschema:"写入方式：replace（缺省，覆盖）| put_if_absent（文件已存在则不动）"`
}

type dpiPreparePackageIn struct {
	BaseIn
	FTPRef       string `json:"ftp_ref,omitempty" jsonschema:"FTP 安装包地址，需带主机：ftp://host[:port]/path 或 host:port/path；由桥下载，密码不出现在靶机上"`
	LocalPath    string `json:"local_path,omitempty" jsonschema:"桥本地已有安装包路径，给了就跳过下载"`
	PackagePath  string `json:"package_path,omitempty" jsonschema:"靶机上安装包已存在的路径，给了就跳过下载与上传"`
	ExtractDir   string `json:"extract_dir,omitempty" jsonschema:"靶机解压根目录，缺省 /home/tmp/dpi_pkg"`
	ScanExisting *bool  `json:"scan_existing,omitempty" jsonschema:"true = 已解压目录存在时跳过重解（缺省 true）"`
}

type dpiInstallIn struct {
	BaseIn
	InstallScript string         `json:"install_script" jsonschema:"靶机上 install.sh 的绝对路径（由 dpi_prepare_package 返回）"`
	BackupPath    string         `json:"backup_path,omitempty" jsonschema:"备份根目录，缺省 /home/dpibak"`
	Mode          string         `json:"mode,omitempty" jsonschema:"装完要切到的模式，如 com_cmcc_is；留空不切"`
	Args          []string       `json:"args,omitempty" jsonschema:"模式切换附加参数，缺省 [idc31]"`
	SwitchParams  map[string]any `json:"switch_params,omitempty" jsonschema:"模式切换前的开关修改"`
	PciCfg        map[string]any `json:"pcicfg,omitempty" jsonschema:"PCI 配置"`
	AliveTimeout  int            `json:"alive_timeout,omitempty" jsonschema:"等 DPI 启动秒数，缺省 600"`
}

type dpiUpgradeIn struct {
	BaseIn
	UpgradeScript    string         `json:"upgrade_script" jsonschema:"靶机上升级脚本的绝对路径（由 dpi_prepare_package 返回）"`
	TargetVersion    string         `json:"target_version" jsonschema:"目标版本号，升级后核对"`
	UseUpgradeSystem bool           `json:"use_upgrade_system,omitempty" jsonschema:"true = 交给升级系统接管（upms），缺省 false = 本地升级"`
	XsaExpect        map[string]any `json:"xsa_expect,omitempty" jsonschema:"升级后应满足的 xsa.json 配置（按点号路径核对）"`
	StartTimeout     int            `json:"start_timeout,omitempty" jsonschema:"升级脚本启动等待秒数，缺省 300"`
	CompleteTimeout  int            `json:"complete_timeout,omitempty" jsonschema:"升级完成等待秒数，缺省 1200"`
	BackupPath       string         `json:"backup_path,omitempty" jsonschema:"升级前备份根目录，缺省 /home/dpibak"`
}

type dpiBackupIn struct {
	BaseIn
	BackupRoot string `json:"backup_root,omitempty" jsonschema:"备份根目录，缺省 /home/dpibak"`
	Force      bool   `json:"force,omitempty" jsonschema:"true = 同名备份存在也重新备份（带时间戳），缺省 false"`
}

// ---- 出参 ----

type dpiInfoData struct {
	Version       string         `json:"version"`
	Mode          string         `json:"mode"`
	PCI           map[string]any `json:"pci"`
	SystemVersion string         `json:"system_version"`
}

type dpiConfigData struct {
	Kind   string         `json:"kind"`
	File   string         `json:"file"`
	Values map[string]any `json:"values"`
}

type dpiApplyConfigData struct {
	Changes   []string `json:"changes"`
	Restarted bool     `json:"restarted"`
	Alive     bool     `json:"alive"`
}

type dpiServiceData struct {
	OK        bool   `json:"ok"`
	Component string `json:"component"`
	Action    string `json:"action"`
	Running   bool   `json:"running"`
}

type dpiAgentServiceData struct {
	OK      bool `json:"ok"`
	Running bool `json:"running"`
}

type dpiSwitchData struct {
	Changed       bool     `json:"changed"`
	VersionBefore string   `json:"version_before"`
	VersionAfter  string   `json:"version_after"`
	ModeBefore    string   `json:"mode_before"`
	ModeAfter     string   `json:"mode_after"`
	Marks         []string `json:"marks"`
}

type dpiPolicyData struct {
	ResourceID string   `json:"resource_id"`
	File       string   `json:"file"`
	Rules      []string `json:"rules"`
	SHA256     string   `json:"sha256"`
	RuleCount  int      `json:"rule_count"`
}

type dpiPolicyPutData struct {
	Changed      bool   `json:"changed"`
	BeforeSHA256 string `json:"before_sha256"`
	AfterSHA256  string `json:"after_sha256"`
	RuleCount    int    `json:"rule_count"`
}

type dpiPolicyWaitData struct {
	Ready    bool    `json:"ready"`
	Actual   string  `json:"actual"`
	Expected int     `json:"expected"`
	Samples  int     `json:"samples"`
	ElapsedS float64 `json:"elapsed_s"`
	TimedOut bool    `json:"timed_out,omitempty"`
}

type dpiPolicyWriteData struct {
	Changed bool   `json:"changed"`
	SHA256  string `json:"sha256"`
	File    string `json:"file"`
}

type dpiPackageData struct {
	PackageFile   string `json:"package_file"`
	ExtractDir    string `json:"extract_dir"`
	InstallScript string `json:"install_script"`
	UpgradeScript string `json:"upgrade_script"`
}

type dpiInstallData struct {
	OK         bool     `json:"ok"`
	BackupPath string   `json:"backup_path"`
	Version    string   `json:"version"`
	Mode       string   `json:"mode"`
	Marks      []string `json:"marks"`
}

type dpiUpgradeData struct {
	OK                bool     `json:"ok"`
	Version           string   `json:"version"`
	Mode              string   `json:"mode"`
	ConfigDifferences []string `json:"config_differences"`
	Marks             []string `json:"marks"`
}

type dpiBackupData struct {
	BackupPath string `json:"backup_path"`
	Skipped    bool   `json:"skipped"`
	Version    string `json:"version"`
	Mode       string `json:"mode"`
}

// ---- 设备小命令 ----

// dpiRead 一次设备文件读取的三种结果。
//
// 必须区分"文件不存在"与"没读到"：装前核验时 /opt/dpi/ver.txt 本来就不存在
// （Python get_dpiversion 返回 None，不算错），而超时/被杀/断连才是真失败。
type dpiRead int

const (
	dpiReadOK      dpiRead = iota // 读到值
	dpiReadMissing                // 文件不存在/为空：设备未安装或未初始化
	dpiReadFailed                 // 命令超时/被杀/连接异常：无法判断
)

// dpiVersion 从 /opt/dpi/ver.txt 第一行取版本（dpi.py:573）。
func dpiVersion(c *Client) (string, dpiRead) {
	out, err := shell(c, "cat "+dpiPath+"/ver.txt | head -n 1")
	return parseDPIRead(out, err, func(s string) (string, bool) {
		if s == "" {
			return "", false
		}
		if i := strings.LastIndex(s, ":"); i >= 0 {
			s = s[i+1:]
		} else if f := strings.Fields(s); len(f) > 0 {
			s = f[len(f)-1]
		}
		return strings.TrimLeft(strings.TrimSpace(s), "V"), true
	})
}

// dpiMode 从 config/rule/dpiconfig.ok 取模式（dpi.py:553）。
func dpiMode(c *Client) (string, dpiRead) {
	out, err := shell(c, "cat "+dpiPath+"/config/rule/dpiconfig.ok")
	return parseDPIRead(out, err, func(s string) (string, bool) {
		re := regexp.MustCompile(`(\w+?_\w+?_\w+?)(?:_|$)`)
		if m := re.FindStringSubmatch(s); m != nil {
			return m[1], true
		}
		return "", false
	})
}

// parseDPIRead 把一次 cat 的结果归到三态。extract 返回 (值, 是否有值)。
func parseDPIRead(out map[string]any, err error, extract func(string) (string, bool)) (string, dpiRead) {
	if err != nil {
		return "", dpiReadFailed
	}
	if _, to := timeoutCleanup(out); to {
		return "", dpiReadFailed
	}
	raw := strings.TrimSpace(fmt.Sprint(out["stdout"]))
	if code := intOf(out["code"]); code != 0 {
		// cat 非零 + 无输出 = 文件不存在（Python 侧同样返回 None）
		if raw == "" {
			return "", dpiReadMissing
		}
		return "", dpiReadFailed
	}
	if v, ok := extract(raw); ok {
		return v, dpiReadOK
	}
	return "", dpiReadMissing
}

// dpiPCI 读 pci.cfg（dpi.py:589）。
func dpiPCI(c *Client) map[string]any {
	res := map[string]any{}
	out, err := shell(c, "cat "+dpiPath+"/mconf/modelswitch/xsajson/pci.cfg")
	if err != nil {
		return res
	}
	for _, line := range strings.Split(fmt.Sprint(out["stdout"]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "pci_list":
			res["pci_list"] = f[1:]
		case "raw_port", "src_mac", "dst_mac":
			res[f[0]] = f[1]
		}
	}
	return res
}

// dpiSystemVersion 读发行版描述（socket_linux.py:425）。
func dpiSystemVersion(c *Client) string {
	out, err := shell(c, "cat /etc/system-release 2>/dev/null || lsb_release -d")
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(fmt.Sprint(out["stdout"]))
	if i := strings.Index(s, ":"); i >= 0 && strings.Contains(s, "Description") {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

// dpiProcCount 进程名 → 匹配计数（ps -ef|grep X|grep -v grep|wc -l）。
//
// ok=false 表示**没测到**（命令被杀/超时/连接异常），不能当成"0 个进程"：
// dpiStopAll 拿它判"已停"、installDPI 据此 `rm -rf /opt/dpi`，把测不到说成
// 0 会删掉正在运行的程序目录（评审 P1-3）。
func dpiProcCount(c *Client, pattern string) (int, bool) {
	out, err := shell(c, "ps -ef|grep "+shQuote(pattern)+"|grep -v grep|wc -l")
	if err != nil {
		return 0, false
	}
	if t, _ := out["timeout"].(bool); t {
		return 0, false
	}
	if code := intOf(out["code"]); code != 0 {
		return 0, false
	}
	return int(intOf2(strings.TrimSpace(fmt.Sprint(out["stdout"])))), true
}

// waitDPIAlive 等 DPI 存活（dpi.py:72 的 md5 变化判定）。
//
// 关键：命令被 agent 到点杀掉时 stdout 是空串，若当成一次"采样值"就会
// 与基线不等 → 误判"DPI 活了"。所以只比较**正常结束**的采样，被杀/断连的
// 那轮直接跳过；基线也用第一次正常采样建立。预算取 min(aliveTimeout, 剩余预算)，
// 剩余预算耗尽时没有拿到有效变化就判失败。
//
// 返回实际使用的预算：外层总预算可能比 aliveTimeout 小，此时真实等待时间远
// 短于调用方传入的值。失败文案必须报实际值，否则"等待 600s 超时失败"却只等
// 了 3 秒，会把排查引向"设备起得慢"。
func waitDPIAlive(c *Client, timeoutS int) (alive bool, budget int) {
	statPath := shmXsa + "time_main_io.stat"
	cmd := "md5sum " + statPath + " 2>/dev/null | awk '{print $1}'"
	shell(c, "rm -f "+statPath)

	budget = timeoutS
	if rem := c.agentTimeoutS(); rem > 0 && rem < budget {
		budget = rem
	}
	deadline := time.Now().Add(time.Duration(budget) * time.Second)

	var base string
	for {
		v, ok := md5Sample(c, cmd)
		if ok {
			base = v
			break
		}
		if time.Now().After(deadline) {
			return false, budget // 连基线都采不到（全是被杀的命令）：无法证明存活
		}
		time.Sleep(time.Second)
	}

	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		v, ok := md5Sample(c, cmd)
		if !ok {
			continue // 本轮命令被杀/断连：不是一次有效观测
		}
		if v != base {
			return true, budget
		}
	}
	return false, budget
}

// md5Sample 取一次 md5；ok=false 表示命令没正常跑完（超时被杀/连接异常），
// 这种采样不能参与"值有没有变"的判断。
func md5Sample(c *Client, cmd string) (string, bool) {
	out, err := shell(c, cmd)
	if err != nil {
		return "", false
	}
	if t, _ := out["timeout"].(bool); t {
		return "", false
	}
	return strings.TrimSpace(fmt.Sprint(out["stdout"])), true
}

// dpiStopAll 停 DPI 主程序并等进程归零（dpi.py:97）。
// 只有**测到 0 个进程**才算停；测不到继续等，到点判失败。
// 预算取 min(timeoutS, 剩余预算)：外层总预算耗尽后，子命令会被 agent 逐条杀掉，
// 内层再等下去只是空转（结果同样是失败，但白占几十秒到几分钟）。
func dpiStopAll(c *Client, timeoutS int) bool {
	if _, err := shell(c, "cd "+dpiPath+" && sh dpikill.sh"); err != nil {
		return false
	}
	budget := timeoutS
	if rem := c.agentTimeoutS(); rem > 0 && rem < budget {
		budget = rem
	}
	deadline := time.Now().Add(time.Duration(budget) * time.Second)
	for time.Now().Before(deadline) {
		if n, ok := dpiProcCount(c, "/opt/dpi/xsa$"); ok && n == 0 {
			time.Sleep(2 * time.Second)
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

// dpiStartAll 启 DPI 主程序并等存活（dpi.py:115）。
func dpiStartAll(c *Client, timeoutS int) (ok bool, budget int) {
	if n, ok2 := dpiProcCount(c, "/opt/dpi/xsa$"); !ok2 || n != 0 {
		return waitDPIAlive(c, timeoutS)
	}
	if _, err := shell(c, "cd "+dpiPath+" && sh dpirun.sh"); err != nil {
		return false, timeoutS
	}
	alive, b := waitDPIAlive(c, timeoutS)
	if !alive {
		return false, b
	}
	time.Sleep(10 * time.Second)
	return true, b
}

// ---- 工具 ----

func (b *Bridge) registerDpiDeviceTools(s *mcp.Server) {
	addTyped(s, ro("dpi_get_info",
		"读 DPI 版本、当前模式、PCI 配置和系统版本（只读，四次查询）。装前装后核验用。注意：这不是 socket_server 版本，桥版本用 bridge_version。超时缺省 15 秒。"),
		func(ctx context.Context, a BaseIn) Envelope[dpiInfoData] {
			return runEnvelope[dpiInfoData](b, ctx, a, "dpi_get_info", map[string]any{}, LkNone, "", true,
				func(c *Client) (any, error) {
					// 装前核验时 ver.txt/dpiconfig.ok 本来就不存在（Python 返回 None），
					// 属于正常状态；只有"命令超时/被杀/连接异常"才算失败——
					// 否则装前核验必失败，且会被 classifyErr 误判成 timeout。
					v, rsV := dpiVersion(c)
					m, rsM := dpiMode(c)
					if rsV == dpiReadFailed || rsM == dpiReadFailed {
						return nil, &CmdError{Msg: "读取 DPI 版本或模式失败（命令超时或连接异常）"}
					}
					return dpiInfoData{Version: v, Mode: m,
						PCI: dpiPCI(c), SystemVersion: dpiSystemVersion(c)}, nil
				})
		})

	addTyped(s, ro("dpi_get_config",
		"读 DPI 配置：kind=xsa 读 xsaconf/xsa.json，kind=mod_cfg 读当前模块配置，kind=xdr_template 读 xdrconf/rule/xdr_template.json。改之前先看现值。超时缺省 15 秒。"),
		func(ctx context.Context, a dpiConfigIn) Envelope[dpiConfigData] {
			file := map[string]string{
				"xsa":          dpiPath + "/xsaconf/xsa.json",
				"xdr_template": dpiPath + "/xdrconf/rule/xdr_template.json",
			}[a.Kind]
			if file == "" && a.Kind != "mod_cfg" {
				return allFailedEnvelope[dpiConfigData](a.Targets, "kind 只能是 xsa | mod_cfg | xdr_template", ErrBusiness)
			}
			return runEnvelope[dpiConfigData](b, ctx, a.BaseIn, "dpi_get_config",
				map[string]any{"kind": a.Kind}, LkNone, "", true, func(c *Client) (any, error) {
					target := file
					if a.Kind == "mod_cfg" {
						target = dpiPath + "/" + modfileOf(c)
					}
					out, err := shell(c, "cat "+shQuote(target))
					if err != nil {
						return nil, err
					}
					if code := intOf(out["code"]); code != 0 {
						return failMap(out, fmt.Sprintf("读取 %s 失败: %s", target, out["stderr"])), nil
					}
					vals := map[string]any{}
					if strings.HasSuffix(target, ".json") {
						json.Unmarshal([]byte(fmt.Sprint(out["stdout"])), &vals)
					} else {
						for _, line := range strings.Split(fmt.Sprint(out["stdout"]), "\n") {
							line = strings.TrimSpace(line)
							if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
								continue
							}
							if i := strings.Index(line, ":"); i > 0 {
								vals[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
							}
						}
					}
					return dpiConfigData{Kind: a.Kind, File: target, Values: vals}, nil
				})
		})

	addTyped(s, destructive("dpi_apply_config",
		"改 DPI 配置：新增缺失项、跳过相同项、修改不同项；只有真的改动时才重启 DPI（restart 后等存活）。超时缺省 1230 秒，依据：停 600 + 起 600 + 余量 30。"),
		func(ctx context.Context, a dpiApplyConfigIn) Envelope[dpiApplyConfigData] {
			restartTimeout := orDefault(a.RestartTimeout, 600)
			return runEnvelope[dpiApplyConfigData](b, ctx, a.BaseIn, "dpi_apply_config",
				map[string]any{"xsa_keys": len(a.Xsa), "mod_cfg_keys": len(a.ModCfg)}, LkSystem, "", false,
				func(c *Client) (any, error) {
					changes := []string{}
					if len(a.ModCfg) > 0 {
						// 读不到模块文件名 / 读不到当前值时必须失败：否则 cur 为空 map，
						// 所有键都走"缺失 → 追加"分支，把整个配置写坏，还报成功
						// （评审 P1-2）。
						mf, ok := modfileOfOK(c)
						if !ok || mf == "" {
							return nil, fmt.Errorf("读取 syscfg.json 的 modfile 失败，无法确定模块配置文件")
						}
						cur, err := readKVFileOK(c, dpiPath+"/"+mf)
						if err != nil {
							return nil, fmt.Errorf("读取模块配置文件 %s 失败: %w", mf, err)
						}
						for k, v := range a.ModCfg {
							curV, has := cur[k]
							wantV := fmt.Sprint(v)
							switch {
							case !has:
								if _, err := shellOK(c, fmt.Sprintf("echo %s:%s >> %s",
									shQuote(k), shQuote(wantV), shQuote(dpiPath+"/"+mf))); err != nil {
									return nil, fmt.Errorf("写入 %s 失败: %w", k, err)
								}
								changes = append(changes, "mod_cfg."+k+": (missing) -> "+wantV)
							case strings.TrimSpace(curV) == strings.TrimSpace(wantV):
								// 相同不动
							default:
								if _, err := shellOK(c, fmt.Sprintf("sed -i 's/^%s:.*/%s:%s/' %s",
									k, k, wantV, shQuote(dpiPath+"/"+mf))); err != nil {
									return nil, fmt.Errorf("修改 %s 失败: %w", k, err)
								}
								changes = append(changes, "mod_cfg."+k+": "+curV+" -> "+wantV)
							}
						}
					}
					for _, spec := range []struct {
						path string
						kv   map[string]any
						tag  string
					}{
						{dpiPath + "/xsaconf/xsa.json", a.Xsa, "xsa"},
						{dpiPath + "/xdrconf/rule/xdr_template.json", a.XdrTemplate, "xdr_template"},
					} {
						if len(spec.kv) == 0 {
							continue
						}
						doc := map[string]any{}
						// 读失败/被杀时直接中止：把"读不到"当成空文档会让所有键走
						// "缺失 → 新增"，把配置文件写坏还报成功（评审 P1-2）。
						raw, err := shellOK(c, "cat "+shQuote(spec.path))
						if err != nil {
							return nil, fmt.Errorf("读取 %s 失败: %w", spec.path, err)
						}
						if err := json.Unmarshal([]byte(raw), &doc); err != nil {
							return nil, fmt.Errorf("解析 %s 失败: %w", spec.path, err)
						}
						cur := map[string]string{}
						flattenJSON("", doc, cur)
						changed := false
						for k, v := range spec.kv {
							wantV := fmt.Sprint(v)
							if strings.TrimSpace(cur[k]) == strings.TrimSpace(wantV) {
								continue
							}
							old, has := cur[k]
							if !has {
								old = "(missing)"
							}
							changes = append(changes, spec.tag+"."+k+": "+old+" -> "+wantV)
							changed = true
						}
						if changed {
							if err := setJSONPaths(c, spec.path, spec.kv); err != nil {
								return nil, err
							}
						}
					}
					if len(changes) == 0 {
						return dpiApplyConfigData{Changes: []string{}, Alive: true}, nil
					}
					if !dpiStopAll(c, restartTimeout) {
						return map[string]any{"_error": "停止 DPI 失败，未完成重启"}, nil
					}
					if ok, b := dpiStartAll(c, restartTimeout); !ok {
						return map[string]any{"_error": fmt.Sprintf("改完配置后 DPI 启动失败（实际等待 %ds，restart_timeout=%ds）", b, restartTimeout)}, nil
					}
					time.Sleep(5 * time.Second)
					return dpiApplyConfigData{Changes: changes, Restarted: true, Alive: true}, nil
				})
		})

	addTyped(s, destructive("dpi_service",
		"启停 DPI 主程序（xsa）或辅助进程（dpi_monitor / policyserver）。下发后会复查进程是否真在/真没，不靠异步返回。主程序超时缺省 1230 秒（restart 最坏 600+600+30）；辅助进程 30 秒。"),
		func(ctx context.Context, a dpiServiceIn) Envelope[dpiServiceData] {
			comp := a.Component
			act := a.Action
			if comp == "" {
				comp = "xsa"
			}
			in := a.BaseIn
			in.Timeout = timeoutFor(BaseIn{Timeout: a.Timeout}, "dpi_service")
			if comp != "xsa" {
				in.Timeout = orDefault(a.Timeout, 30)
			}
			return runEnvelope[dpiServiceData](b, ctx, in, "dpi_service",
				map[string]any{"component": comp, "action": act}, LkSystem, "", false,
				func(c *Client) (any, error) {
					switch comp {
					case "xsa":
						switch act {
						case "start":
							if ok, b := dpiStartAll(c, in.Timeout); !ok {
								return map[string]any{"_error": fmt.Sprintf("DPI 启动失败或超时（实际等待 %ds，预算 %ds）", b, in.Timeout)}, nil
							}
						case "stop":
							if !dpiStopAll(c, in.Timeout) {
								return map[string]any{"_error": "DPI 停止失败或超时"}, nil
							}
						case "restart":
							if !dpiStopAll(c, in.Timeout) {
								return map[string]any{"_error": "DPI 重启失败或超时（停止阶段）"}, nil
							}
							if ok, b := dpiStartAll(c, in.Timeout); !ok {
								return map[string]any{"_error": fmt.Sprintf("DPI 重启失败或超时（启动阶段实际等待 %ds，预算 %ds）", b, in.Timeout)}, nil
							}
						default:
							return map[string]any{"_error": "action 只能是 start | stop | restart"}, nil
						}
						// 复查必须测到才敢报 running：测不到时报错，不猜一个值出去
						n, ok := dpiProcCount(c, "/opt/dpi/xsa$")
						if !ok {
							return map[string]any{"_error": "动作已下发，但复查进程时命令未正常返回，无法确认 DPI 运行状态"}, nil
						}
						return dpiServiceData{OK: true, Component: comp, Action: act, Running: n != 0}, nil
					case "dpi_monitor", "policyserver":
						if err := toggleSideProc(c, comp, act); err != nil {
							return nil, err
						}
						n, ok := dpiProcCount(c, comp)
						if !ok {
							return map[string]any{"_error": "动作已下发，但复查进程时命令未正常返回，无法确认 " + comp + " 运行状态"}, nil
						}
						return dpiServiceData{OK: true, Component: comp, Action: act, Running: n != 0}, nil
					default:
						return map[string]any{"_error": "component 只能是 xsa | dpi_monitor | policyserver"}, nil
					}
				})
		})

	addTyped(s, destructive("dpi_agent_service",
		"启停升级系统的 agent 进程（安装/升级前会先停它）。start/stop 各自带轮询确认，stop 超时会强制 pkill。返回 {ok,running}。超时缺省 60 秒，依据：原 start/stop 各 30 秒并带轮询。"),
		func(ctx context.Context, a dpiAgentServiceIn) Envelope[dpiAgentServiceData] {
			act := orDefaultStr(a.Action, "start")
			return runEnvelope[dpiAgentServiceData](b, ctx, a.BaseIn, "dpi_agent_service",
				map[string]any{"action": act}, LkNone, "", false, func(c *Client) (any, error) {
					switch act {
					case "start", "stop", "restart":
					default:
						return map[string]any{"_error": "action 只能是 start | stop | restart"}, nil
					}
					if act == "restart" {
						if ok := toggleAgent(c, "stop", 30); !ok {
							return map[string]any{"_error": "agent 停止失败，无法重启"}, nil
						}
						time.Sleep(2 * time.Second)
						if ok := toggleAgent(c, "start", 30); !ok {
							return map[string]any{"_error": "agent 启动失败"}, nil
						}
					} else if !toggleAgent(c, act, 30) {
						return map[string]any{"_error": "agent " + act + " 失败或超时"}, nil
					}
					running, ok := agentRunning(c)
					if !ok {
						return map[string]any{"_error": "动作已下发，但复查 agent 进程时命令未正常返回，无法确认运行状态"}, nil
					}
					return dpiAgentServiceData{OK: true, Running: running}, nil
				})
		})

	addTyped(s, destructive("dpi_switch_mode",
		"切换 DPI 模式：必要时写 pci.cfg、改 mod_switch.sh 开关、执行切换脚本并等 DPI 存活；模式与配置都没变化时自动跳过。返回切换前后的版本/模式与过程标记。超时缺省 930 秒，依据：业务传 mod_switch(timeout=900) + 30。"),
		func(ctx context.Context, a dpiSwitchModeIn) Envelope[dpiSwitchData] {
			aliveTimeout := orDefault(a.AliveTimeout, 600)
			return runEnvelope[dpiSwitchData](b, ctx, a.BaseIn, "dpi_switch_mode",
				map[string]any{"mode": a.Mode, "force": a.Force}, LkSystem, "", false,
				func(c *Client) (any, error) {
					return switchMode(c, a, aliveTimeout)
				})
		})
}

func (b *Bridge) registerDpiPolicyTools(s *mcp.Server) {
	addTyped(s, ro("dpi_policy_get",
		"读指定策略/配置资产的行与 sha256（覆盖前快照）。resource_id 只能取白名单键。超时缺省 15 秒。"),
		func(ctx context.Context, a dpiPolicyGetIn) Envelope[dpiPolicyData] {
			file, ok := policyFiles[a.ResourceID]
			if !ok {
				return allFailedEnvelope[dpiPolicyData](a.Targets, "resource_id 不在白名单: "+a.ResourceID, ErrBusiness)
			}
			return runEnvelope[dpiPolicyData](b, ctx, a.BaseIn, "dpi_policy_get",
				map[string]any{"resource_id": a.ResourceID}, LkNone, "", true, func(c *Client) (any, error) {
					raw, err := readFileB64(c, file)
					if err != nil {
						return nil, err
					}
					rules := splitRuleLines(raw)
					return dpiPolicyData{ResourceID: a.ResourceID, File: file, Rules: rules,
						SHA256: sha256Hex([]byte(raw)), RuleCount: len(rules)}, nil
				})
		})

	addTyped(s, write("dpi_policy_put",
		"整体覆盖策略文件；md5check=true 且内容不变时跳过写入。rules 为空 = 清空策略。返回改前/改后 sha256 与条数。超时缺省 15 秒。"),
		func(ctx context.Context, a dpiPolicyPutIn) Envelope[dpiPolicyPutData] {
			file, ok := policyFiles[a.ResourceID]
			if !ok {
				return allFailedEnvelope[dpiPolicyPutData](a.Targets, "resource_id 不在白名单: "+a.ResourceID, ErrBusiness)
			}
			return runEnvelope[dpiPolicyPutData](b, ctx, a.BaseIn, "dpi_policy_put",
				map[string]any{"resource_id": a.ResourceID, "rules": len(a.Rules)}, LkNone, "", false,
				func(c *Client) (any, error) {
					before, _ := readFileB64(c, file)
					content := strings.Join(a.Rules, "\n")
					if len(a.Rules) > 0 {
						content += "\n"
					}
					after := sha256Hex([]byte(content))
					if a.MD5Check && before == content {
						return dpiPolicyPutData{Changed: false, BeforeSHA256: sha256Hex([]byte(before)),
							AfterSHA256: after, RuleCount: len(a.Rules)}, nil
					}
					if err := writeFileB64(c, file, content); err != nil {
						return nil, err
					}
					return dpiPolicyPutData{Changed: true, BeforeSHA256: sha256Hex([]byte(before)),
						AfterSHA256: after, RuleCount: len(a.Rules)}, nil
				})
		})

	addTyped(s, ro("dpi_policy_wait",
		"等策略或 ADMS 任务加载到预期条数。kind=action 时轮询指定 marex 文件的 policy.total；kind=adms 时轮询 adms_idc_debug.stat 的 adms_allrule_num。到点未达标返回 ready=false。超时缺省 60 秒。"),
		func(ctx context.Context, a dpiPolicyWaitIn) Envelope[dpiPolicyWaitData] {
			every := orDefault(a.EveryS, 2)
			wait := orDefault(a.WaitS, 60)
			kind := orDefaultStr(a.Kind, "action")
			if kind == "action" {
				if _, ok := marexResource[a.Action]; !ok {
					return allFailedEnvelope[dpiPolicyWaitData](a.Targets, "kind=action 时 action 必须是 eu_plc | pcapdump | mirr | vpn_block", ErrBusiness)
				}
			} else if kind != "adms" {
				return allFailedEnvelope[dpiPolicyWaitData](a.Targets, "kind 只能是 action 或 adms", ErrBusiness)
			}
			return runEnvelope[dpiPolicyWaitData](b, ctx, a.BaseIn, "dpi_policy_wait",
				map[string]any{"kind": kind, "action": a.Action, "expected": a.Expected}, LkNone, "", true,
				func(c *Client) (any, error) {
					start := time.Now()
					out := dpiPolicyWaitData{Expected: a.Expected}
					deadline := start.Add(time.Duration(wait) * time.Second)
					for {
						var actual string
						if kind == "action" {
							sd, err := readStat(c, "marex", a.Action, "")
							if err != nil {
								return nil, err
							}
							actual = rowField(sd, "policy", "total")
						} else {
							sd, err := readStat(c, "adms_idc_debug", "", "")
							if err != nil {
								return nil, err
							}
							actual, _ = lookupField(sd, "adms_allrule_num")
						}
						out.Samples++
						out.Actual = actual
						// 解析失败（actual 为空）不能与 expected=0 撞成"已就绪"（评审 P3-9）
						if strings.TrimSpace(actual) != "" && intOf2(actual) == int64(a.Expected) {
							out.Ready = true
							out.ElapsedS = time.Since(start).Seconds()
							return out, nil
						}
						if time.Now().After(deadline) {
							out.TimedOut = true
							out.ElapsedS = time.Since(start).Seconds()
							return out, nil
						}
						time.Sleep(time.Duration(every) * time.Second)
					}
				})
		})

	addTyped(s, write("dpi_policy_write",
		"写非策略类配置资产（house/pcip/oversea IP 段、common.ini、access_log、xdr_filter、bzip ipsegs）。mode=replace 覆盖，put_if_absent 文件已存在则不动。超时缺省 15 秒。"),
		func(ctx context.Context, a dpiPolicyWriteIn) Envelope[dpiPolicyWriteData] {
			file, ok := policyFiles[a.ResourceID]
			if !ok {
				return allFailedEnvelope[dpiPolicyWriteData](a.Targets, "resource_id 不在白名单: "+a.ResourceID, ErrBusiness)
			}
			mode := orDefaultStr(a.Mode, "replace")
			return runEnvelope[dpiPolicyWriteData](b, ctx, a.BaseIn, "dpi_policy_write",
				map[string]any{"resource_id": a.ResourceID, "mode": mode}, LkNone, "", false,
				func(c *Client) (any, error) {
					if mode == "put_if_absent" {
						if st, err := fileExists(c, file); err == nil && st {
							return dpiPolicyWriteData{Changed: false, File: file}, nil
						}
					}
					if err := writeFileB64(c, file, a.Content); err != nil {
						return nil, err
					}
					return dpiPolicyWriteData{Changed: true, SHA256: sha256Hex([]byte(a.Content)), File: file}, nil
				})
		})
}

func (b *Bridge) registerDpiInstallTools(s *mcp.Server) {
	addTyped(s, write("dpi_prepare_package",
		"校验/下载 DPI 安装包并按 ACT-DPI-EU（两层 tar）/ ACT-DPI-ISE|NSE|DSE（三层 unzip+tar）规则解压，返回 install.sh 与 upms_install.sh 路径。FTP 密码由桥侧持有并直接下载后上传，不出现在靶机进程列表。超时缺省 600 秒（初值，原实现无总 deadline）。"),
		func(ctx context.Context, a dpiPreparePackageIn) Envelope[dpiPackageData] {
			return runEnvelope[dpiPackageData](b, ctx, a.BaseIn, "dpi_prepare_package",
				map[string]any{"ftp_ref": a.FTPRef, "local_path": a.LocalPath, "package_path": a.PackagePath},
				LkNone, "", false, func(c *Client) (any, error) {
					return preparePackage(b, c, a)
				})
		})

	addTyped(s, destructive("dpi_install",
		"全新安装 DPI：备份旧程序、停旧程序、执行 install.sh、切到目标模式。**最多 1 台靶机**，多台请分批。超时缺省 930 秒，依据：mod_switch 900 + 30。"),
		func(ctx context.Context, a dpiInstallIn) Envelope[dpiInstallData] {
			// 必须先按 @tag 展开再判：len(a.Targets)==1 可能展开成 N 台（评审 P1-5），
			// 而这是会删 /opt/dpi 的不可逆操作。
			if resolved := b.resolve(a.Targets); len(resolved) > 1 {
				return allFailedEnvelope[dpiInstallData](resolved, "dpi_install 一次只能装 1 台，请分批", ErrBusiness)
			}
			aliveTimeout := orDefault(a.AliveTimeout, 600)
			return runEnvelope[dpiInstallData](b, ctx, a.BaseIn, "dpi_install",
				map[string]any{"install_script": a.InstallScript, "mode": a.Mode}, LkSystem, "", false,
				func(c *Client) (any, error) {
					return installDPI(c, a, aliveTimeout)
				})
		})

	addTyped(s, destructive("dpi_upgrade",
		"升级 DPI 固件（不是 socket_server，那个用 bridge_upgrade）：备份后执行本地升级，或交给升级系统接管，最后核对版本/模式/配置。**最多 1 台靶机**。超时缺省 1500 秒，依据：启动 300 + 完成 1200。"),
		func(ctx context.Context, a dpiUpgradeIn) Envelope[dpiUpgradeData] {
			if resolved := b.resolve(a.Targets); len(resolved) > 1 {
				return allFailedEnvelope[dpiUpgradeData](resolved, "dpi_upgrade 一次只能升 1 台，请分批", ErrBusiness)
			}
			startTO := orDefault(a.StartTimeout, 300)
			completeTO := orDefault(a.CompleteTimeout, 1200)
			return runEnvelope[dpiUpgradeData](b, ctx, a.BaseIn, "dpi_upgrade",
				map[string]any{"upgrade_script": a.UpgradeScript, "target_version": a.TargetVersion},
				LkSystem, "", false, func(c *Client) (any, error) {
					return upgradeDPI(c, a, startTO, completeTO)
				})
		})

	addTyped(s, write("dpi_backup",
		"按版本和模式备份 /opt/dpi 到备份根目录；同名备份已存在时跳过（force=true 带时间戳重备）。超时缺省 300 秒（初值，原实现无总超时，待规模校准）。"),
		func(ctx context.Context, a dpiBackupIn) Envelope[dpiBackupData] {
			root := orDefaultStr(a.BackupRoot, "/home/dpibak")
			return runEnvelope[dpiBackupData](b, ctx, a.BaseIn, "dpi_backup",
				map[string]any{"backup_root": root, "force": a.Force}, LkNone, "", false,
				func(c *Client) (any, error) {
					return backupDPI(c, root, a.Force)
				})
		})
}
