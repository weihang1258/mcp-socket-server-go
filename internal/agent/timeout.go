package agent

// 超时"真停"（方案 §6）：wire 可选字段 timeout_s，agent 到点杀整个进程组，
// 并在回执里带 timeout/killed/verified，桥据此把失败归到 error_type=timeout。
// timeout_s=0（或不传）= 不限时，行为与旧版完全一致（Python 原客户端兼容）。

import (
	"errors"
	"os/exec"
	"sync/atomic"
	"time"
)

// 等待粒度抽成原子量，单测里可缩短（-race 安全：杀进程在别的 goroutine 里读）。
var (
	secondNs          atomic.Int64
	timeMillisecondNs atomic.Int64
)

func init() {
	secondNs.Store(int64(time.Second))
	timeMillisecondNs.Store(int64(time.Millisecond))
}

func second() time.Duration          { return time.Duration(secondNs.Load()) }
func timeMillisecond() time.Duration { return time.Duration(timeMillisecondNs.Load()) }
func timeSleep(d time.Duration)      { time.Sleep(d) }

// timeoutResult 到点杀进程后返回的结构化结果。
type timeoutResult struct {
	TimedOut bool
	Killed   bool
	Verified bool // 杀完复查进程组已空
	PGID     int
}

// exitCodeOf 把 Wait 的错误翻成进程退出码（信号死亡 → -signum，与 Python 一致）。
func exitCodeOf(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return processExitCode(ee), nil
	}
	return -1, err
}

// runWithTimeout 执行 c（已配好 Stdout/Stderr），timeoutS>0 时到点整组杀。
// 返回 (退出码, 超时信息)。err 非 nil 仅表示启动/等待异常。
func runWithTimeout(c *exec.Cmd, timeoutS int) (int, *timeoutResult, error) {
	if timeoutS <= 0 {
		err := c.Run()
		code, rerr := exitCodeOf(err)
		if rerr != nil {
			return -1, nil, rerr
		}
		return code, nil, nil
	}
	setProcGroup(c)
	if err := c.Start(); err != nil {
		return -1, nil, err
	}
	pgid := c.Process.Pid
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	timer := time.NewTimer(time.Duration(timeoutS) * second())
	defer timer.Stop()
	select {
	case err := <-done:
		code, rerr := exitCodeOf(err)
		if rerr != nil {
			return -1, nil, rerr
		}
		return code, nil, nil
	case <-timer.C:
		// 组内进程可能在 SIGTERM 后自行退出；Wait 与杀灭并行，最多等 3 秒。
		// 注意：3 秒兜底返回时 Wait **还没回**，os/exec 的 copy goroutine 可能仍在写
		// Stdout/Stderr；调用方此时读 buffer 就是数据竞争（setsid 脱离组的后代、
		// NFS 卡写都会触发，评审 P2-5）。所以这里把"Wait 是否已回"告诉调用方，
		// 由它决定能不能安全读 buffer，以及 verified 能不能说成立。
		go killProcGroup(pgid)
		waited := false
		select {
		case <-done:
			waited = true
		case <-time.After(3 * time.Second):
		}
		// 进程组空了不代表脱离组的后代也空了：只有 Wait 已回（管道写端全灭）
		// 且组内无存活进程，才能说"现场已确认清理"。
		res := &timeoutResult{TimedOut: true, Killed: true, PGID: pgid,
			Verified: waited && !procGroupAlive(pgid)}
		return -1, res, nil
	}
}
