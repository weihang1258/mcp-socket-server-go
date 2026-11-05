package agent

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// keepVersions 本地保留的版本目录数（含当前版本）。
//
// 为什么要有：/opt/socket/versions 只增不减——每次 upgrade_run / 推送升级
// 都留一份完整二进制。真机跑到第 26 个版本时占 389MB，长期会撑满磁盘。
// 3 份足够回滚（当前 + 前两个），再往前靠中央重新下发即可。
const keepVersions = 3

// currentLinkTarget 返回 current 软链指向的版本号（"1.8.3"）；无软链/解析失败 → ""。
//
// 为什么按软链而不是按 running Version 判存活：回滚后 current 指向旧版本，而
// 启动清理的是**正在跑的新代码**，Version 与软链目标不同。2026-11-02 本机实测：
// current → 1.8.3（回滚用的 Python 版），起一个 v1.9.24 的 agent 做验收，启动清理
// 按 Version 保留最近 3 个，把 1.8.3 目录整个删掉——软链悬空，下次重启服务起不来
// （二进制是从仍在运行的进程 /proc/<pid>/exe 里捞回来的）。
func currentLinkTarget() string {
	fi, err := os.Lstat(filepath.Join(versionsDir(), "current"))
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return ""
	}
	target, err := os.Readlink(filepath.Join(versionsDir(), "current"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

// pruneOldVersions 删除除 current 与最近 keep 个之外的版本目录。
// 按版本号排序（不是按 mtime：推送升级可能补装旧版本）。
func pruneOldVersions(current string, keep int) error {
	root := versionsDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	protected := map[string]bool{current: true}
	if t := currentLinkTarget(); t != "" {
		protected[t] = true // 回滚中：current 指向的不是正在跑的版本，同样不能删
	}
	var vers []string
	for _, e := range entries {
		if !e.IsDir() || !versionRe.MatchString(e.Name()) {
			continue // 跳过 current 软链、.staging、历史残留的非版本目录
		}
		vers = append(vers, e.Name())
	}
	// 版本号比较：逐段数字比较，不是字典序（1.10.0 > 1.9.0）
	sort.Slice(vers, func(i, j int) bool { return versionLess(vers[i], vers[j]) })

	keepFrom := len(vers) - keep
	if keepFrom < 0 {
		keepFrom = 0
	}
	for i, v := range vers {
		if i >= keepFrom || protected[v] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, v)); err != nil {
			log.Printf("清理旧版本 %s 失败: %v", v, err)
			continue
		}
		log.Printf("已清理旧版本 %s（保留最近 %d 个）", v, keep)
	}
	return nil
}

// PruneAtStartup 启动时清理一次（main 在 agent 起来后异步调用）。
//
// 为什么只挂 switchTo 不够：dt20 自升级执行切链的是**升级前的旧进程**——
// 旧代码里没有 prune，切完链重启就退场了，清理永远轮不到新代码执行
// （真机验收：首次 upgrade_run 后 22 个版本纹丝不动，第二次才清到 3 个）。
// 挂在启动路径后，升级触发的自动重启即完成清理，一次 upgrade_run 就干净。
func PruneAtStartup() {
	if err := pruneOldVersions(Version, keepVersions); err != nil {
		log.Printf("启动清理旧版本失败（不影响运行）: %v", err)
	}
}

// versionLess 版本号逐段数字比较。
func versionLess(a, b string) bool {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, _ := strconv.Atoi(as[i])
		bi, _ := strconv.Atoi(bs[i])
		if ai != bi {
			return ai < bi
		}
	}
	return len(as) < len(bs)
}
