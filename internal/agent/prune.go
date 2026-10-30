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
		if i >= keepFrom || v == current {
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
