package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
)

// logf 等价 log.Printf，集中一处便于以后统一格式。
func logf(format string, args ...any) { log.Printf(format, args...) }

// Python 原版日志保真（protocol.py / handlers.py）：验收脚本卡住时现场靠
// /var/log/socket_server.log 判断请求到没到、走到哪一帧。Go 版早期只在出错
// 时打日志，成功路径全程静默——2026-11-02 客户端验收 #22 指出「日志都没有
// 看到收到这个请求」。此文件按 Python 原文案逐条补齐。

// pyReprPayload payload 的 Python repr（dict → 单引号/True/False/空格）。
// 解析失败退回原始字符串（Python json.loads 失败会抛异常，那时日志本来就只有
// 「错误：...」，这里不退化为 panic）。
func pyReprPayload(payload []byte) string {
	var v any
	if err := json.Unmarshal(payload, &v); err != nil {
		return string(payload)
	}
	return pyRepr(v)
}

func pyRepr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return "'" + strings.ReplaceAll(x, "'", `\'`) + "'"
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = pyRepr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		parts := make([]string, 0, len(x))
		for k, e := range x {
			parts = append(parts, "'"+k+"': "+pyRepr(e))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprint(x)
	}
}

// logRecv 帧接收日志（protocol.py:43/45/51/54）。
func logRecv(dataLen int32, chunkLen int, total int) {
	logf("指定接收有效字节数：%d", dataLen)
	logf("本条接收长度%d", chunkLen)
	logf("接收总长度%d", total)
}

// logResponse 业务响应日志（protocol.py:122）：response(N)：<前100字节 hex>。
func logResponse(resp []byte) {
	head := resp
	if len(head) > 100 {
		head = head[:100]
	}
	logf("response(%d)：%x", len(resp), head)
}

// logHandler 统一入口日志（handlers.py 各分支首行）。
func logHandler(name string, dt int32, payload []byte) {
	logf("%s，类型：%d，参数：%s", name, dt, pyReprPayload(payload))
}

// logHandlerResult 结果日志（handlers.py 各分支 response 之后一行）。
func logHandlerResult(v any) { logf("%s", pyRepr(v)) }
