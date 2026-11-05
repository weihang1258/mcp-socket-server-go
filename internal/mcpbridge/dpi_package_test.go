package mcpbridge

// preparePackage 的风险集中在"层数/产物识别错了还继续跑"。这三条锁住早退分支，
// 不做真实解压（真实解压/FTP 属于真机验证项）。

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPreparePackageRejectsUnknownPrefix(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 7:
			w.text(`{"res":true}`) // 包已存在
		case 8:
			w.text(`{"res":true}`) // 解压根目录已存在
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if strings.Contains(p["args"], "find /") {
				cmdReply(w, 0, "/home/FOO-1.0.tar.gz\n", "")
				return
			}
			cmdReply(w, 0, "", "")
		}
	})
	c, _ := dialClient(t, m)
	_, err := preparePackage(newTestBridge(t), c, dpiPreparePackageIn{
		BaseIn:       BaseIn{Targets: []string{m.Addr}},
		PackagePath:  "/home/FOO-1.0.tar.gz",
		ScanExisting: boolPtr(false),
	})
	if err == nil || !strings.Contains(err.Error(), "无法识别的程序包前缀") {
		t.Fatalf("未知前缀必须早退: %v", err)
	}
}

func TestPreparePackageFailsWhenLayer2Missing(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 8:
			w.text(`{"res":true}`) // 第一层目录已存在 → 跳过解压
		case 15: // dt15 恒回 ok
			w.text("ok")
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if strings.Contains(p["args"], "ALL-BOOT-ALL-ALL-") {
				cmdReply(w, 0, "", "") // 第二层包找不到
				return
			}
			cmdReply(w, 0, "", "")
		}
	})
	c, _ := dialClient(t, m)
	_, err := preparePackage(newTestBridge(t), c, dpiPreparePackageIn{
		BaseIn:      BaseIn{Targets: []string{m.Addr}},
		PackagePath: "/home/ACT-DPI-EU-20260101.tar.gz",
	})
	if err == nil || !strings.Contains(err.Error(), "第二层包") {
		t.Fatalf("找不到第二层必须报错: %v", err)
	}
}

func TestPreparePackageFailsWhenInstallScriptMissing(t *testing.T) {
	m := newMockServer(t, func(dt int32, payload []byte, w *mockConnIO) {
		switch dt {
		case 14:
			w.text(`"1.9.27"`)
		case 7:
			w.text(`{"res":false}`) // install.sh 不存在
		case 8:
			w.text(`{"res":true}`) // 各层目录已存在 → 跳过解压
		case 15:
			w.text("ok")
		case 1:
			var p map[string]string
			json.Unmarshal(payload, &p)
			if strings.Contains(p["args"], "ALL-BOOT-ALL-ALL-") {
				cmdReply(w, 0, "ALL-BOOT-ALL-ALL-1.tar.gz\n", "")
				return
			}
			cmdReply(w, 0, "", "")
		}
	})
	c, _ := dialClient(t, m)
	_, err := preparePackage(newTestBridge(t), c, dpiPreparePackageIn{
		BaseIn:      BaseIn{Targets: []string{m.Addr}},
		PackagePath: "/home/ACT-DPI-EU-20260101.tar.gz",
	})
	if err == nil || !strings.Contains(err.Error(), "安装脚本不存在") {
		t.Fatalf("install.sh 缺失必须报错: %v", err)
	}
}
