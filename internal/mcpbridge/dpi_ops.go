package mcpbridge

// dpi_* 工具的桥侧编排辅助：全部基于 dt1 `cmd`，不改 agent 协议。

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---- 基础读写 ----

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

// readFileB64 dt3 下载（gzip）后在桥侧解码成字符串。
func readFileB64(c *Client, path string) (string, error) {
	raw, err := c.downloadFile(path)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// writeFileB64 dt2 上传（base64 明文，agent 侧解码落盘）。
func writeFileB64(c *Client, path, content string) error {
	return c.uploadFile(path, []byte(content))
}

func splitRuleLines(content string) []string {
	out := []string{}
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func fileExists(c *Client, path string) (bool, error) { return c.Isfile(path) }

// readKVFile 读 "key: value" 配置文件为 map（模块配置等）。
// 读失败返回空 map——只用于"读不到也能继续"的展示场景；改配置请用 readKVFileOK。
func readKVFile(c *Client, path string) map[string]string {
	out, _ := readKVFileOK(c, path)
	return out
}

// readKVFileOK 同 readKVFile，但把"读不到/被杀/解析失败"如实报出来。
func readKVFileOK(c *Client, path string) (map[string]string, error) {
	out := map[string]string{}
	raw, err := shellOK(c, "cat "+shQuote(path))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if i := strings.Index(line, ":"); i > 0 {
			out[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return out, nil
}

// modfileOf 从 syscfg.json 取模块配置文件名（dpi.py:get_modfile_from_modcfg）。
func modfileOf(c *Client) string {
	v, _ := modfileOfOK(c)
	return v
}

// modfileOfOK 同 modfileOf，但读不到/解析失败时返回 ok=false。
func modfileOfOK(c *Client) (string, bool) {
	raw, err := shellOK(c, "cat "+dpiPath+"/syscfg.json")
	if err != nil {
		return "", false
	}
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil {
		return "", false
	}
	if v, ok := m["modfile"].(string); ok && v != "" {
		return v, true
	}
	return "", false
}

// flattenJSON 把嵌套 JSON 拍平成 "a.b.0.c" → 字符串值。
func flattenJSON(prefix string, v any, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flattenJSON(p, child, out)
		}
	case []any:
		for i, child := range x {
			p := fmt.Sprintf("%s.%d", prefix, i)
			flattenJSON(p, child, out)
		}
	default:
		out[prefix] = fmt.Sprint(x)
	}
}

// setJSONPaths 在靶机上按点号路径改 JSON（python 一行脚本；设备有 python3）。
func setJSONPaths(c *Client, path string, kv map[string]any) error {
	script := `
import json,sys
p=sys.argv[1]; kv=json.loads(sys.argv[2])
d=json.load(open(p))
for k,v in kv.items():
    t=d; ks=[int(x) if x.isdigit() else x for x in k.split('.')]
    for x in ks[:-1]: t=t[x]
    t[ks[-1]]=v
json.dump(d,open(p,'w'),ensure_ascii=False,indent=2)
`
	blob, _ := json.Marshal(kv)
	out, err := shell(c, "python3 -c "+shQuote(script)+" "+shQuote(path)+" "+shQuote(string(blob)))
	if err != nil {
		return err
	}
	if code := intOf(out["code"]); code != 0 {
		return cmdErr(out, "写 JSON 配置失败: "+strings.TrimSpace(fmt.Sprint(out["stderr"])))
	}
	return nil
}

// toggleSideProc 启停 dpi_monitor / policyserver，并复查进程。
func toggleSideProc(c *Client, comp, action string) error {
	switch action {
	case "start":
		if n, ok := dpiProcCount(c, comp); ok && n > 0 {
			return nil
		}
		var cmd string
		switch comp {
		case "dpi_monitor":
			// 必须 nohup + 重定向 + &：agent 的 stdout 是管道，前台子进程会一直
			// 持有写端，Cmd.Wait 直到它退出才返回——真 monitor 不退，30 秒后就被
			// 整组杀掉（评审 P2-6）。
			cmd = "nohup " + dpiPath + "/dpi_monitor -t 5 >/dev/null 2>&1 &"
		default:
			cmd = "nohup " + dpiPath + "/policyserver >/dev/null 2>&1 &"
		}
		if _, err := shell(c, cmd); err != nil {
			return err
		}
		for i := 0; i < 10; i++ {
			if n, ok := dpiProcCount(c, comp); ok && n > 0 {
				return nil
			}
			time.Sleep(time.Second)
		}
		return fmt.Errorf("%s 启动后进程仍未出现（或进程查询未正常返回）", comp)
	case "stop":
		if _, err := shell(c, "kill `ps -ef|grep "+comp+"|grep -v grep|awk '{print $2}'` 2>/dev/null"); err != nil {
			return err
		}
		for i := 0; i < 10; i++ {
			if n, ok := dpiProcCount(c, comp); ok && n == 0 {
				return nil
			}
			time.Sleep(time.Second)
		}
		return fmt.Errorf("%s 停止后进程仍在（或进程查询未正常返回）", comp)
	}
	return fmt.Errorf("action 只能是 start 或 stop")
}

// agentRunning 判 agent 进程（dpi.py:690）。测不到按"不确定"处理：
// start 侧当作没在跑（会去启动，幂等），stop 侧当作还在跑（会继续等/强杀）。
func agentRunning(c *Client) (running bool, ok bool) {
	n, ok := dpiProcCount(c, "/opt/agent/agent")
	return n > 0, ok
}

// toggleAgent 启停 agent 并轮询（dpi.py:715 / 753）。
func toggleAgent(c *Client, action string, timeoutS int) bool {
	if running, ok := agentRunning(c); ok {
		if action == "start" && running {
			return true
		}
		if action == "stop" && !running {
			return true
		}
	}
	if ok, _ := fileExists(c, "/etc/init.d/upms_agent_monitor"); !ok {
		return false
	}
	shell(c, "/etc/init.d/upms_agent_monitor "+action)
	deadline := time.Now().Add(time.Duration(timeoutS) * time.Second)
	for time.Now().Before(deadline) {
		// 只认"测到了且符合预期"，测不到继续等
		if running, ok := agentRunning(c); ok && running == (action == "start") {
			return true
		}
		time.Sleep(time.Second)
	}
	if action == "stop" {
		shell(c, "pkill -9 -f 'upms_agent_monitor'")
		time.Sleep(time.Second)
		shell(c, "pkill -9 -f '/opt/agent/agent'")
		time.Sleep(2 * time.Second)
		running, ok := agentRunning(c)
		return ok && !running // 测不到不算停
	}
	return false
}

// switchMode dpi.py:1209 mod_switch 的桥侧编排。
func switchMode(c *Client, a dpiSwitchModeIn, aliveTimeout int) (any, error) {
	out := dpiSwitchData{Marks: []string{}}
	// 切换前读不到（未安装/文件缺失）不算错，空值即可；只有命令失败才中止
	vb, rsV := dpiVersion(c)
	if rsV == dpiReadFailed {
		return out, fmt.Errorf("切换前读取 DPI 版本失败（命令超时或连接异常）")
	}
	mb, rsM := dpiMode(c)
	if rsM == dpiReadFailed {
		return out, fmt.Errorf("切换前读取 DPI 模式失败（命令超时或连接异常）")
	}
	out.VersionBefore, out.ModeBefore = vb, mb
	args := a.Args
	if len(args) == 0 {
		args = []string{"idc31"}
	}

	forceflag := false
	curMode, _ := dpiMode(c) // 读不到 → curMode 空 → 必然判"需要切换"，多做一次但不会漏切
	curPCI := dpiPCI(c)
	pcicfgChanged := len(a.PciCfg) > 0 && !jsonEqual(a.PciCfg, curPCI)
	switch {
	case curMode != a.Mode:
		forceflag = true
	case pcicfgChanged:
		forceflag = true
	}

	parts := strings.Split(a.Mode, "_")
	if len(parts) < 3 {
		return out, fmt.Errorf("mode 格式应为 aaa_bbb_ccc，实际 %q", a.Mode)
	}
	scriptDir := dpiPath + "/mconf/modelswitch"
	script := parts[1] + "_mod_switch.sh"

	if pcicfgChanged {
		if err := writePCICfg(c, a.PciCfg); err != nil {
			return out, err
		}
		dpiStopAll(c, aliveTimeout)
		shell(c, "rm -f "+dpiPath+"/syscfg.json")
	}

	// 未强制时，把"与脚本现值相同"的开关从改动集里剔除，并判断是否需要强制
	toApply := map[string]any{}
	for k, v := range a.ModifiedParam {
		if !forceflag {
			m, err := shell(c, "cd "+scriptDir+" && cat "+script+" | grep '"+k+`\s*='`+" | awk -F '=' '{print $2}'")
			if err != nil {
				return out, fmt.Errorf("读取切换脚本参数 %s 失败: %w", k, err)
			}
			if _, to := timeoutCleanup(m); to {
				return out, fmt.Errorf("读取切换脚本参数 %s 超时（预算耗尽）", k)
			}
			cur := strings.TrimSpace(fmt.Sprint(m["stdout"]))
			if cur == "" {
				return out, fmt.Errorf("未找到参数: %s", k)
			}
			if fmt.Sprint(v) != cur {
				forceflag = true
			} else {
				continue
			}
		}
		toApply[k] = v
	}
	for k, v := range toApply {
		shell(c, fmt.Sprintf("cd %s && sed -i 's/%s\\s*=.*/%s=%s/' %s", scriptDir, k, k, fmt.Sprint(v), script))
	}

	if !a.Force && !forceflag {
		out.ModeAfter = curMode
		out.VersionAfter = out.VersionBefore
		out.Marks = append(out.Marks, "无需切换dpi模式")
		return out, nil
	}

	shell(c, "truncate -s 0 /var/log/dpi.log")
	cmd := "cd " + scriptDir + " && bash " + script + " " + parts[2]
	for _, x := range args {
		cmd += " " + shQuote(x)
	}
	res, err := shell(c, cmd)
	if err != nil {
		return out, err
	}
	res["stdout"] = truncateRunes(fmt.Sprint(res["stdout"]), 4096)

	if alive, b := waitDPIAlive(c, aliveTimeout); !alive {
		return switchFail(out, fmt.Sprintf("DPI 启动等待超时失败（实际等待 %ds，alive_timeout=%ds）", b, aliveTimeout)), nil
	}
	out.Changed = true

	// 发完后核对改过的开关 / 版本 / 模式（dpi.py:1291-1325：任一不一致 result=False）
	bad := []string{}
	for k, want := range a.ModifiedParam {
		// 回读失败（命令被杀/非零）不能当成"读到了但值不对"，也不能当成"对得上"：
		// 直接判本次切换失败，避免把无法验证说成验证通过（评审 Q2）。
		m, err := shell(c, fmt.Sprintf("cd %s && cat %s | grep ^%s= | head -n 1", scriptDir, script, k))
		if err != nil {
			return switchFail(out, fmt.Sprintf("切换后回读开关 %s 失败: %v", k, err)), nil
		}
		if _, to := timeoutCleanup(m); to {
			return switchFail(out, fmt.Sprintf("切换后回读开关 %s 超时（无法确认切换结果）", k)), nil
		}
		if code := intOf(m["code"]); code != 0 {
			return switchFail(out, fmt.Sprintf("切换后回读开关 %s 失败（退出码 %d）", k, code)), nil
		}
		cur := strings.TrimSpace(fmt.Sprint(m["stdout"]))
		if !strings.Contains(cur, "="+fmt.Sprint(want)) {
			bad = append(bad, fmt.Sprintf("切换后开关 %s 期望 %v 实际 %q", k, want, cur))
		}
	}
	// 切换后读不到版本/模式 = 无法核对，必须判失败（不能因为空串让核对被跳过）
	// 切换后必须读到：读不到（含文件不存在）说明切换没生效或命令失败
	vAfter, rsV2 := dpiVersion(c)
	mAfter, rsM2 := dpiMode(c)
	if rsV2 != dpiReadOK {
		return switchFail(out, "切换后读取 DPI 版本失败，无法核对"), nil
	}
	if rsM2 != dpiReadOK {
		return switchFail(out, "切换后读取 DPI 模式失败，无法核对"), nil
	}
	out.VersionAfter, out.ModeAfter = vAfter, mAfter
	if a.Mode != "" && out.VersionBefore != "" && out.VersionAfter != out.VersionBefore {
		bad = append(bad, fmt.Sprintf("切换后预期版本不准确：期望 %s 实际 %s", out.VersionBefore, out.VersionAfter))
	}
	if a.Mode != "" && out.ModeAfter != "" && out.ModeAfter != a.Mode {
		bad = append(bad, fmt.Sprintf("切换后模式不准确：期望 %s 实际 %s", a.Mode, out.ModeAfter))
	}
	out.Marks = append(out.Marks, bad...)
	if len(bad) > 0 {
		// 切过去但核对不一致 = 没达到切换目的，不能报成功（Python mod_switch 同样 False）
		return switchFail(out, "模式切换后核对失败: "+strings.Join(bad, "；")), nil
	}
	return out, nil
}

// writePCICfg 按 dpi.py:614 config_pcicfg 写 pci.cfg。
func writePCICfg(c *Client, cfg map[string]any) error {
	path := dpiPath + "/mconf/modelswitch/xsajson/pci.cfg"
	// sed 失败（被杀/非零）必须中止：否则 pci.cfg 没改成、后面照常切模式，
	// 切换的目标配置与预期不符（评审 P2-C）。
	var werr error
	write := func(key string, val string) {
		if werr != nil {
			return
		}
		_, werr = shellOK(c, fmt.Sprintf("sed -i 's/^%s.*/%s %s/' %s", key, key, val, path))
	}
	if v, ok := cfg["pci_list"]; ok {
		list := []string{}
		switch x := v.(type) {
		case []any:
			for _, i := range x {
				list = append(list, fmt.Sprint(i))
			}
		case []string:
			list = x
		case string:
			list = strings.Fields(x)
		}
		write("pci_list", strings.Join(list, " "))
	}
	for _, k := range []string{"raw_port", "src_mac", "dst_mac"} {
		if v, ok := cfg[k]; ok {
			write(k, fmt.Sprint(v))
		}
	}
	return werr
}

func jsonEqual(a, b map[string]any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// backupDPI 按 dpi.py:634 备份 /opt/dpi。
func backupDPI(c *Client, root string, force bool) (dpiBackupData, error) {
	// 与 Python dpibak（dpi.py:646-665）一致：目录不存在/取不到模式都是**跳过**
	// 而不是失败——安装、升级里备份是尽力而为，不该因此把整条链路判死。
	if ok, _ := c.Isdir(dpiPath); !ok {
		return dpiBackupData{Skipped: true}, nil
	}
	if ok, _ := c.Isdir(root); !ok {
		if err := c.Mkdir(root); err != nil { // 同上：吞掉会毒化后续子命令
			return dpiBackupData{}, fmt.Errorf("创建备份根目录失败: %w", err)
		}
	}
	version, rsV := dpiVersion(c)
	if rsV != dpiReadOK || strings.TrimSpace(version) == "" {
		return dpiBackupData{}, fmt.Errorf("DPI 版本号不存在或读不到，请检查") // Python 这里是 raise
	}
	mode, rsM := dpiMode(c)
	if rsM != dpiReadOK || mode == "" {
		return dpiBackupData{Version: version, Skipped: true, Mode: ""}, nil
	}
	dest := strings.TrimRight(root, "/") + "/dpi_bak_" + version + "_" + mode
	if force {
		dest = dest + "_" + time.Now().Format("150405")
	}
	if !force {
		if ok, _ := c.Isdir(dest); ok {
			return dpiBackupData{BackupPath: dest, Skipped: true, Version: version, Mode: mode}, nil
		}
	}
	out, err := shell(c, "cp -r "+dpiPath+" "+shQuote(dest))
	if err != nil {
		return dpiBackupData{}, err
	}
	if code := intOf(out["code"]); code != 0 {
		return dpiBackupData{}, cmdErr(out, "备份失败: "+strings.TrimSpace(fmt.Sprint(out["stderr"])))
	}
	if ok, _ := c.Isdir(dest); !ok {
		return dpiBackupData{}, fmt.Errorf("备份目录未生成: %s", dest)
	}
	return dpiBackupData{BackupPath: dest, Version: version, Mode: mode}, nil
}

// installDPI dpi.py:1194 install + mod_switch 的桥侧编排。
func installDPI(c *Client, a dpiInstallIn, aliveTimeout int) (any, error) {
	out := dpiInstallData{Marks: []string{}}
	root := orDefaultStr(a.BackupPath, "/home/dpibak")
	if ok, _ := c.Isdir(dpiPath); ok {
		if bk, err := backupDPI(c, root, false); err == nil {
			out.BackupPath = bk.BackupPath
		} else {
			out.Marks = append(out.Marks, "备份失败（继续安装）: "+err.Error())
		}
		// 先停服务再删目录，避免安装脚本与运行中进程抢文件
		if ok := toggleAgent(c, "stop", 30); !ok {
			out.Marks = append(out.Marks, "agent 停止失败（继续）")
		}
		if !dpiStopAll(c, aliveTimeout) {
			out.Marks = append(out.Marks, "DPI 停止超时（继续）")
		}
		if _, err := shellOK(c, "rm -rf "+dpiPath); err != nil {
			return installFail(out, "删除旧 DPI 目录失败: "+err.Error()), nil
		}
	}
	dir := filepath.Dir(a.InstallScript)
	base := filepath.Base(a.InstallScript)
	if _, err := shellOK(c, "cd "+shQuote(dir)+" && bash "+shQuote(base)); err != nil {
		return failOf(err, func(r string) map[string]any { return installFail(out, r) },
			"install.sh 执行失败: "+err.Error())
	}
	if ok, _ := c.Isfile(dpiPath + "/syscfg.json"); ok {
		return installFail(out, "执行完 install.sh 后 dpi 仍存在 syscfg.json"), nil
	}
	if a.Mode != "" {
		sw, err := switchMode(c, dpiSwitchModeIn{
			BaseIn: a.BaseIn, Mode: a.Mode, Args: a.Args,
			ModifiedParam: a.SwitchParams, PciCfg: a.PciCfg, AliveTimeout: aliveTimeout,
		}, aliveTimeout)
		if err != nil {
			// 装完切不到目标模式 = 本次安装没有达到目标，不能报成功
			return installFail(out, "安装完成但模式切换失败: "+err.Error()), nil
		}
		if swd, ok := sw.(dpiSwitchData); ok {
			out.Marks = append(out.Marks, swd.Marks...)
			out.Version, out.Mode = swd.VersionAfter, swd.ModeAfter
		} else if m, ok := sw.(map[string]any); ok {
			if reason, ok2 := m["_error"].(string); ok2 {
				// 切换本身失败：安装未达到目标，带着切换诊断一起报失败
				return installFail(out, "安装完成但模式切换失败: "+reason), nil
			}
			if extra, ok2 := m["marks"].([]string); ok2 {
				out.Marks = append(out.Marks, extra...)
			}
		}
	}
	// 装完读不到版本/模式：本次安装的结果不可验证，不能报成功
	v, rsV := dpiVersion(c)
	m, rsM := dpiMode(c)
	if rsV != dpiReadOK || rsM != dpiReadOK {
		return installFail(out, "安装后读取版本/模式失败，结果不可核对"), nil
	}
	out.Version, out.Mode = v, m
	// marks 里全是"降级继续"的记录（备份失败 / agent 没停 / DPI 没停）。这些
	// 说明现场可能不干净，不能报 OK=true（评审 P1-1：信封会把 struct 一律当成功）。
	if len(out.Marks) > 0 {
		return installFail(out, "安装完成但过程有异常"), nil
	}
	out.OK = true
	return out, nil
}

// upgradeDPI 本地升级 / 升级系统接管的桥侧编排（dpi.py:836 / 958）。
func upgradeDPI(c *Client, a dpiUpgradeIn, startTO, completeTO int) (any, error) {
	out := dpiUpgradeData{Marks: []string{}}
	if a.UseUpgradeSystem {
		marks, err := upgradeViaSystem(c, a.TargetVersion, startTO, completeTO)
		// reason 里不再 join marks：upgradeFail→withMarks 还会再拼一次，
		// 原来会把同一串 marks 打两遍（评审 P1-3）。
		// err 走 failOf：带 *CmdError 时保留 cleanup，不降级成 business。
		out.Marks = nil
		if err != nil {
			return failOf(err, func(r string) map[string]any {
				out.Marks = marks
				return upgradeFail(out, r) // reason 已含前缀，别再拼一次
			}, "升级系统接管失败: "+err.Error())
		}
		out.Marks = marks
	} else {
		root := orDefaultStr(a.BackupPath, "/home/dpibak")
		if bk, err := backupDPI(c, root, false); err == nil {
			if bk.Skipped {
				out.Marks = append(out.Marks, "未备份（DPI 不存在或取不到模式）")
			} else {
				out.Marks = append(out.Marks, "已备份到 "+bk.BackupPath)
			}
		} else {
			out.Marks = append(out.Marks, "备份失败: "+err.Error())
		}
		dir := filepath.Dir(a.UpgradeScript)
		base := filepath.Base(a.UpgradeScript)
		if _, err := shellOK(c, "cd "+shQuote(dir)+" && bash "+shQuote(base)); err != nil {
			return failOf(err, func(r string) map[string]any { return upgradeFail(out, r) },
				"升级脚本执行失败: "+err.Error())
		}
		if alive, b := waitDPIAlive(c, startTO); !alive {
			return upgradeFail(out, fmt.Sprintf("升级后 DPI 未在预算内启动（实际等待 %ds，start_timeout=%ds）", b, startTO)), nil
		}
	}
	// 升完读不到版本 = 无法核对，必须失败（空串会让 TargetVersion 核对"看起来通过"）
	v, rsV := dpiVersion(c)
	if rsV != dpiReadOK {
		return upgradeFail(out, "升级后读取 DPI 版本失败，结果不可核对"), nil
	}
	m, rsM := dpiMode(c)
	if rsM != dpiReadOK {
		return upgradeFail(out, "升级后读取 DPI 模式失败，结果不可核对"), nil
	}
	out.Version, out.Mode = v, m
	if a.TargetVersion != "" && !versionMatches(out.Version, a.TargetVersion) {
		out.Marks = append(out.Marks, fmt.Sprintf("版本核对不符：期望 %s 实际 %s", a.TargetVersion, out.Version))
	}
	if len(a.XsaExpect) > 0 {
		// 读不到 xsa.json 时不能当成"空文档"：那样每个键都会判"不符"，
		// 把"读失败"报成"配置没保住"（评审 P2-4 的同类问题）。
		raw, err := shellOK(c, "cat "+dpiPath+"/xsaconf/xsa.json")
		if err != nil {
			return upgradeFail(out, "升级后读取 xsa.json 失败，无法核对配置: "+err.Error()), nil
		}
		doc := map[string]any{}
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			return upgradeFail(out, "升级后解析 xsa.json 失败: "+err.Error()), nil
		}
		flat := map[string]string{}
		flattenJSON("", doc, flat)
		for k, v := range a.XsaExpect {
			if strings.TrimSpace(flat[k]) != strings.TrimSpace(fmt.Sprint(v)) {
				out.ConfigDifferences = append(out.ConfigDifferences,
					fmt.Sprintf("%s: 期望 %v 实际 %q", k, v, flat[k]))
			}
		}
	}
	// 关键：runOne 只认 error / _error / timeout / false 四种失败信号，struct 一律
	// 当成功。OK=false 必须在这里转成 _error，否则"版本没升上去"也报 ok=1（评审 P1-1）。
	if len(out.ConfigDifferences) > 0 {
		return upgradeFail(out, "升级后 xsa 配置与期望不符: "+strings.Join(out.ConfigDifferences, "；")), nil
	}
	if len(out.Marks) > 0 {
		return upgradeFail(out, "升级后核对未通过"), nil
	}
	out.OK = true
	return out, nil
}

// upgradeViaSystem upms 升级系统接管（dpi.py:836）。
func upgradeViaSystem(c *Client, targetVersion string, startTO, completeTO int) ([]string, error) {
	marks := []string{}
	shell(c, "rm -f /tmp/*.result")
	if !toggleAgent(c, "start", 30) {
		return marks, errors.New("agent 启动失败")
	}
	// 轮询必须区分"输出为空"与"命令被杀留空"：预算耗尽后 agentTimeoutS 会返回
	// 1 秒，之后每条子命令都以 1 秒超时下发并被杀 → stdout 空。此时若沿用
	// Python 的"空 = 脚本结束"判据，就会把"升级还在跑"当成"跑完了"，接着去
	// 读不到结果文件、报成 business 失败，并顺手 pkill 掉仍在跑的 agent
	// （评审 P1-1：Python 侧没有 agent 超时，这个状态在 Go 里是常态路径）。
	upmsPids := func() (string, error) {
		out, err := shell(c, "ps -ef|grep upms_install.sh|grep -v grep")
		if err != nil {
			return "", fmt.Errorf("查询升级脚本失败: %w", err)
		}
		// 超时回执必须带 cleanup 出去：否则 runOne 只看到文本，Failure.cleanup 为空
		if cu, to := timeoutCleanup(out); to {
			return "", &CmdError{Msg: "升级状态轮询超时（预算耗尽），无法确认升级脚本状态", Cleanup: cu}
		}
		if code := intOf(out["code"]); code != 0 {
			return "", fmt.Errorf("查询升级脚本失败（退出码 %d）", code)
		}
		return strings.TrimSpace(fmt.Sprint(out["stdout"])), nil
	}

	started := false
	deadline := time.Now().Add(time.Duration(startTO) * time.Second)
	for time.Now().Before(deadline) {
		pids, err := upmsPids()
		if err != nil {
			toggleAgent(c, "stop", 30)
			return marks, err
		}
		if pids != "" {
			started = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !started {
		toggleAgent(c, "stop", 30)
		return marks, fmt.Errorf("升级脚本启动超时（%ds）", startTO)
	}
	done := false
	deadline = time.Now().Add(time.Duration(completeTO) * time.Second)
	for time.Now().Before(deadline) {
		pids, err := upmsPids()
		if err != nil {
			// 无法确认脚本是否结束：**不能** pkill agent（脚本可能还在跑）。
			// 用 %w 保留错误链，否则 *CmdError 被裹成普通 error，cleanup 丢失。
			return marks, fmt.Errorf("%w; 未停止 agent，请人工确认升级状态", err)
		}
		if pids == "" {
			done = true
			break
		}
		time.Sleep(5 * time.Second)
	}
	if !done {
		toggleAgent(c, "stop", 30)
		return marks, fmt.Errorf("升级脚本执行超时（%ds）", completeTO)
	}
	time.Sleep(2 * time.Second)
	res, err := shellOK(c, "ls -t /tmp/*.result 2>/dev/null | head -n 1")
	if err != nil {
		return marks, fmt.Errorf("查找升级结果文件失败: %w", err)
	}
	resultFile := strings.TrimSpace(res)
	if resultFile == "" {
		toggleAgent(c, "stop", 30)
		return marks, errors.New("未找到升级结果文件")
	}
	body, err := shellOK(c, "cat "+shQuote(resultFile))
	if err != nil {
		return marks, fmt.Errorf("读取升级结果文件失败: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 2 {
		toggleAgent(c, "stop", 30)
		return marks, errors.New("结果文件格式错误")
	}
	status := strings.TrimSpace(lines[0])
	msg := strings.TrimSpace(lines[1])
	toggleAgent(c, "stop", 30)
	if status != "0" {
		return marks, errors.New("升级失败: " + msg)
	}
	return marks, nil
}

// versionMatches 原项目 install.py:101-156 的版本比较口径：按 . 和 - 切段，
// 数字段按数值比，alpha/beta/rc/patch 给权重，未知标识符当 0，右侧补 0 对齐。
// 不用子串前缀——那会把 1.2 和 1.20 判成相同。
func versionMatches(actual, want string) bool {
	return compareVersions(actual, want) == 0
}

var versionLetterWeights = map[string]int{"alpha": -3, "beta": -2, "rc": -1, "patch": 1}
var reVersionSplit = regexp.MustCompile(`[.\-]`)

func parseVersionParts(v string) []int {
	out := []int{}
	for _, part := range reVersionSplit.Split(strings.TrimLeft(strings.TrimSpace(v), "vV"), -1) {
		if n, err := strconv.Atoi(part); err == nil {
			out = append(out, n)
		} else if w, ok := versionLetterWeights[part]; ok {
			out = append(out, w)
		} else {
			out = append(out, 0) // 未知标识符
		}
	}
	for len(out) < 7 {
		out = append(out, 0)
	}
	return out
}

// compareVersions -1 / 0 / 1（与 Python compare_versions 同语义）。
func compareVersions(a, b string) int {
	pa, pb := parseVersionParts(a), parseVersionParts(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ---- 安装包准备（business/install.py:630-845） ----

// dpiPackagePassword 旧版安装包（ACT-DPI-ISE/NSE/DSE）内层 zip 的发布密码。
// 这是原项目 install.py:753/783 写死的厂商发布密码，不是用户凭据；只用于解压
// 厂商包。评审建议移到受控配置，这里保留常量但集中一处，便于将来替换。
const dpiPackagePassword = "GeUpms@1995"

func dirExists(c *Client, p string) bool {
	ok, _ := c.Isdir(p)
	return ok
}

// uploadLocalFile 桥本地文件经 :9001 上传（preparePackage 用）。
func uploadLocalFile(c *Client, localPath, remote string) error {
	// 上传占的是同一次工具调用的总预算，不能写死 300 秒（评审 P2-D）
	to := c.agentTimeoutS()
	if to < 1 {
		to = 300
	}
	_, _, err := httpUpload(c.Host, 9001, localPath, remote, to)
	return err
}

// ftpGet 桥侧 FTP 下载。凭据从桥本地配置读取，不进工具参数、不进审计、不进日志。
func ftpGet(b *Bridge, url, dest string, timeoutS int) error {
	if b.Cfg.FTPUser == "" && b.Cfg.FTPPassword == "" {
		return fmt.Errorf("桥未配置 FTP 凭据（mcp.ftp_user / mcp.ftp_password），无法直连 FTP；" +
			"可先在别处下载好再用 local_path 传入")
	}
	if timeoutS < 1 {
		timeoutS = 600
	}
	return ftpDownload(url, dest, b.Cfg.FTPUser, b.Cfg.FTPPassword, timeoutS)
}

// ftpDownload 桥侧 FTP 下载（显式凭据；空用户名走 anonymous），流式落盘。
func ftpDownload(rawURL, dest, user, password string, timeoutSec int) error {
	d := &net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	conn, err := d.Dial("tcp", ftpHostPort(rawURL))
	if err != nil {
		return fmt.Errorf("FTP 连接失败: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	br := bufio.NewReader(conn)
	expect := func(code string) (string, error) {
		line, err := br.ReadString('\n')
		if err != nil {
			return line, err
		}
		if !strings.HasPrefix(line, code) {
			return line, fmt.Errorf("FTP 期望 %s，收到 %q", code, strings.TrimSpace(line))
		}
		return line, nil
	}
	sendCmd := func(cmd string) error {
		_, err := io.WriteString(conn, cmd+"\r\n")
		return err
	}
	if _, err := expect("220"); err != nil {
		return err
	}
	if user == "" {
		user = "anonymous"
	}
	if err := sendCmd("USER " + user); err != nil {
		return err
	}
	if line, err := expect("3"); err != nil {
		return err
	} else if strings.HasPrefix(line, "331") {
		if err := sendCmd("PASS " + password); err != nil {
			return err
		}
		if _, err := expect("230"); err != nil {
			return err
		}
	}
	if err := sendCmd("TYPE I"); err != nil {
		return err
	}
	if _, err := expect("200"); err != nil {
		return err
	}
	if err := sendCmd("PASV"); err != nil {
		return err
	}
	line, err := expect("227")
	if err != nil {
		return err
	}
	host, port, err := parsePasv(line)
	if err != nil {
		return err
	}
	data, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("FTP 数据连接失败: %v", err)
	}
	defer data.Close()
	if err := sendCmd("RETR " + ftpPathOf(rawURL)); err != nil {
		return err
	}
	if _, err := expect("150"); err != nil {
		if _, err2 := expect("125"); err2 != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	// 数据连接没有 deadline 时会永久挂起（控制连接的 deadline 管不到它）：
	// FTP 服务端 RETR 后僵死 → 整个 MCP 调用挂死且无清理（评审 P2-7）。
	// 用「每轮续期」而不是一个总 deadline：大包允许跑久，但不允许一直不动。
	buf := make([]byte, 1<<20)
	for {
		data.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, rerr := data.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				os.Remove(dest)
				return fmt.Errorf("FTP 下载写盘失败: %v", werr)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(dest)
			return fmt.Errorf("FTP 下载中断: %v", rerr)
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(dest)
		return err
	}
	if _, err := expect("226"); err != nil {
		return err
	}
	_ = sendCmd("QUIT")
	return nil
}

func ftpHostPort(raw string) string {
	s := strings.TrimPrefix(raw, "ftp://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if strings.Contains(s, ":") {
		return s
	}
	return s + ":21"
}

func ftpPathOf(raw string) string {
	s := strings.TrimPrefix(raw, "ftp://")
	if i := strings.Index(s, "/"); i >= 0 {
		return s[i:]
	}
	return "/"
}

func parsePasv(line string) (string, int, error) {
	i := strings.Index(line, "(")
	j := strings.Index(line, ")")
	if i < 0 || j <= i {
		return "", 0, fmt.Errorf("无法解析 PASV 响应: %q", strings.TrimSpace(line))
	}
	nums := strings.Split(line[i+1:j], ",")
	if len(nums) != 6 {
		return "", 0, fmt.Errorf("PASV 字段数异常: %q", strings.TrimSpace(line))
	}
	p1, err1 := strconv.Atoi(strings.TrimSpace(nums[4]))
	p2, err2 := strconv.Atoi(strings.TrimSpace(nums[5]))
	if err1 != nil || err2 != nil {
		return "", 0, fmt.Errorf("PASV 端口解析失败: %q", strings.TrimSpace(line))
	}
	return strings.TrimSpace(nums[0]) + "." + strings.TrimSpace(nums[1]) + "." +
		strings.TrimSpace(nums[2]) + "." + strings.TrimSpace(nums[3]), p1*256 + p2, nil
}

// preparePackage 安装包下载/上传 + 两层/三层解压（install.py:630-845）。
func preparePackage(b *Bridge, c *Client, a dpiPreparePackageIn) (dpiPackageData, error) {
	pkgPath := a.PackagePath
	var localFile string

	if pkgPath == "" {
		if a.FTPRef != "" {
			// 接受 ftp://host/path 或 host:port/path；只有路径没有主机没法连
			ref := strings.TrimSpace(a.FTPRef)
			rest := strings.TrimPrefix(ref, "ftp://")
			if !strings.Contains(strings.SplitN(rest, "/", 2)[0], ":") &&
				!strings.Contains(rest, "/") {
				return dpiPackageData{}, fmt.Errorf(
					"ftp_ref 需要主机：ftp://host[:port]/path 或 host:port/path，收到 %q", ref)
			}
			name := filepath.Base(rest)
			if name == "" || name == "." || name == "/" {
				return dpiPackageData{}, fmt.Errorf("ftp_ref 缺少安装包文件名: %q", ref)
			}
			dest := filepath.Join(b.DownloadDir, name)
			url := "ftp://" + rest
			// FTP 下载占的是同一次工具调用的总预算，不能写死 600 秒
			if err := ftpGet(b, url, dest, c.agentTimeoutS()); err != nil {
				return dpiPackageData{}, err
			}
			localFile = dest
		} else if a.LocalPath != "" {
			if _, err := os.Stat(a.LocalPath); err != nil {
				return dpiPackageData{}, fmt.Errorf("桥本地安装包不存在: %s", a.LocalPath)
			}
			localFile = a.LocalPath
		} else {
			return dpiPackageData{}, fmt.Errorf("ftp_ref / local_path / package_path 三者必须给一个")
		}
		remote := "/home/" + filepath.Base(localFile)
		// install.py:716-731：scan_existing 时先在靶机上找同名包，找到就不重复上传
		// （大包弱网下上传一次的代价很高）。
		if a.ScanExisting == nil || *a.ScanExisting {
			if found, err := shellOK(c, "find / -type f -name "+shQuote(filepath.Base(localFile))+
				" -print -quit 2>/dev/null"); err == nil {
				if p := strings.TrimSpace(found); p != "" {
					pkgPath = p
				}
			}
		}
		if pkgPath == "" {
			if err := uploadLocalFile(c, localFile, remote); err != nil {
				return dpiPackageData{}, err
			}
			pkgPath = remote
		}
	}

	name := filepath.Base(pkgPath)
	prefix, layers, layer2Method, layer2Pattern := "", 0, "", ""
	for _, p := range []string{"ACT-DPI-EU-", "ACT-DPI-ISE-", "ACT-DPI-NSE-", "ACT-DPI-DSE-"} {
		if strings.HasPrefix(name, p) {
			prefix = p
			break
		}
	}
	switch prefix {
	case "ACT-DPI-EU-":
		layers, layer2Method, layer2Pattern = 2, "tar", "ALL-BOOT-ALL-ALL-*.tar.gz"
	case "ACT-DPI-ISE-", "ACT-DPI-NSE-", "ACT-DPI-DSE-":
		layers, layer2Method, layer2Pattern = 3, "unzip", "*.tar.gz"
	default:
		return dpiPackageData{}, fmt.Errorf("无法识别的程序包前缀（仅支持 ACT-DPI-EU/ISE/NSE/DSE）: %s", name)
	}
	scan := true
	if a.ScanExisting != nil {
		scan = *a.ScanExisting
	}
	base := a.ExtractDir
	if base == "" {
		base = "/home/tmp/dpi_pkg"
	}
	// dt9 在目录已存在时会返回错误 → agent 按"规则 7"断连无响应，把后续所有
	// 子命令一起毒死。所以先查再建，且不能吞掉真错误（评审 P1-4）。
	if ok, _ := c.Isdir(base); !ok {
		if err := c.Mkdir(base); err != nil {
			return dpiPackageData{}, fmt.Errorf("创建解压根目录失败: %w", err)
		}
	}

	// 第一层：外层 *.tar.gz 其实是**加密 ZIP**（install.py:748-761 用的就是 unzip -P）。
	// 实测样本：`file` 报 Zip archive，`tar tzf` 报 encrypted file。
	outdir1 := base + "/" + strings.TrimSuffix(name, ".tar.gz")
	if !(scan && dirExists(c, outdir1)) {
		if err := c.Unzip(pkgPath, outdir1, dpiPackagePassword, true); err != nil {
			return dpiPackageData{}, fmt.Errorf("第一层解压失败: %w", err)
		}
		// dt15 在设备侧失败也会回 ok（netutils.py:234-250），必须核对产物
		n, err := countEntries(c, outdir1)
		if err != nil {
			return dpiPackageData{}, err
		}
		if n == 0 {
			return dpiPackageData{}, fmt.Errorf("第一层解压后目录为空（包损坏或密码不对）: %s", outdir1)
		}
	}

	// 第二层
	out, err := shellOK(c, "cd "+shQuote(outdir1)+" && find ./ -maxdepth 1 -name "+shQuote(layer2Pattern)+" | head -n 1")
	if err != nil {
		return dpiPackageData{}, err
	}
	l2 := strings.TrimPrefix(strings.TrimSpace(out), "./")
	if l2 == "" {
		return dpiPackageData{}, fmt.Errorf("第一层解压后未找到第二层包（%s）", layer2Pattern)
	}
	l2Path := outdir1 + "/" + l2
	outdir2 := outdir1 + "/" + strings.TrimSuffix(strings.TrimSuffix(l2, ".tar.gz"), ".zip")
	if !(scan && dirExists(c, outdir2)) {
		if layer2Method == "tar" {
			if _, err := shellOK(c, "tar -xzf "+shQuote(l2Path)+" -C "+shQuote(outdir1)); err != nil {
				return dpiPackageData{}, fmt.Errorf("第二层解压失败: %w", err)
			}
		} else {
			// Python install.py:786-792 解到 outdir1 而不是 outdir2：zip 内含同名
			// 顶层目录，解压后自然出现 outdir2。解到 outdir2 会多套一层。
			if err := c.Unzip(l2Path, outdir1, dpiPackagePassword, true); err != nil {
				return dpiPackageData{}, fmt.Errorf("第二层解压失败: %w", err)
			}
			if !dirExists(c, outdir2) {
				return dpiPackageData{}, fmt.Errorf("第二层 unzip 未产出目录: %s", outdir2)
			}
		}
	}

	upmsInstall := outdir2 + "/upms_install.sh"

	// 第三层：仅旧版（ISE/NSE/DSE）全新安装需要
	installFile := outdir2 + "/install.sh"
	if layers == 3 {
		out3, err := shellOK(c, "cd "+shQuote(outdir2)+" && find ./ -maxdepth 1 -name '*.tar.gz' | head -n 1")
		if err != nil {
			return dpiPackageData{}, err
		}
		l3 := strings.TrimPrefix(strings.TrimSpace(out3), "./")
		if l3 == "" {
			return dpiPackageData{}, fmt.Errorf("第二层解压后未找到第三层包")
		}
		outdir3 := outdir2 + "/" + strings.TrimSuffix(l3, ".tar.gz")
		if !(scan && dirExists(c, outdir3)) {
			if _, err := shellOK(c, "cd "+shQuote(outdir2)+" && tar -xzf "+shQuote(l3)); err != nil {
				return dpiPackageData{}, fmt.Errorf("第三层解压失败: %w", err)
			}
		}
		installFile = outdir3 + "/install.sh"
	}
	// 脚本必须真实存在，不能只看解压命令退出码
	if ok, _ := c.Isfile(installFile); !ok {
		return dpiPackageData{}, fmt.Errorf("安装脚本不存在: %s", installFile)
	}
	upmsOK, _ := c.Isfile(upmsInstall)

	upgrade := ""
	if upmsOK {
		upgrade = upmsInstall
	}
	return dpiPackageData{
		PackageFile:   pkgPath,
		ExtractDir:    base,
		InstallScript: installFile,
		UpgradeScript: upgrade,
	}, nil
}

// installFail / upgradeFail / switchFail 失败时的回执。runOne 走 _error 通道时
// 会丢掉 data，所以把已收集的诊断（marks / 备份路径 / 版本模式）拼进错误文案，
// 否则调用方只看到"失败"两个字，不知道装到哪一步、备份在哪。
func withMarks(reason string, marks []string) string {
	if len(marks) == 0 {
		return reason
	}
	return reason + "（过程: " + strings.Join(marks, "；") + "）"
}

// failOf 多步编排的失败出口：如果原因链里带 *CmdError（agent 到点杀了进程组），
// 必须走 error 通道把 cleanup 带出去，而不是压成字符串（评审 P2-1）。
func failOf(err error, mapFn func(string) map[string]any, reason string) (any, error) {
	var ce *CmdError
	if errors.As(err, &ce) {
		return nil, ce
	}
	return mapFn(reason), nil
}

func installFail(out dpiInstallData, reason string) map[string]any {
	msg := withMarks(reason, out.Marks)
	if out.BackupPath != "" {
		msg += "（备份: " + out.BackupPath + "）"
	}
	return map[string]any{"_error": msg}
}

func switchFail(out dpiSwitchData, reason string) map[string]any {
	msg := withMarks(reason, out.Marks)
	if out.VersionBefore != "" || out.ModeBefore != "" {
		msg += fmt.Sprintf("（切换前: %s / %s，切换后: %s / %s）",
			out.ModeBefore, out.VersionBefore, out.ModeAfter, out.VersionAfter)
	}
	return map[string]any{"_error": msg}
}

func upgradeFail(out dpiUpgradeData, reason string) map[string]any {
	return map[string]any{"_error": withMarks(reason, out.Marks)}
}

// countEntries 数目录下的条目数（含隐藏文件），用于解压后核对产物。
func countEntries(c *Client, dir string) (int, error) {
	out, err := shellOK(c, "ls -A "+shQuote(dir)+" 2>/dev/null | wc -l")
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("统计目录条目失败: %q", out)
	}
	return n, nil
}
