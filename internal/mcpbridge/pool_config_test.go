package mcpbridge

import "testing"

// A6 回归：ConfigureLimits 生效
func TestConfigureLimits(t *testing.T) {
	defer ConfigureLimits(5, 600, 10, 50) // 测试后恢复缺省
	ConfigureLimits(20, 1200, 30, 100)
	if poolMaxConnPerTarget != 20 || poolIdleTimeoutSec != 1200 || poolBorrowTimeoutSec != 30 {
		t.Fatalf("池参数未生效: %d %d %d", poolMaxConnPerTarget, poolIdleTimeoutSec, poolBorrowTimeoutSec)
	}
	if maxGlobalConcurrency != 100 {
		t.Fatalf("并发上限未生效: %d", maxGlobalConcurrency)
	}
	if schedGlobal != nil && cap(schedGlobal.sem) != 100 {
		t.Fatalf("sem 容量未重建: %d", cap(schedGlobal.sem))
	}
	// 0 值不覆盖
	ConfigureLimits(0, 0, 0, 0)
	if poolMaxConnPerTarget != 20 {
		t.Fatalf("0 值意外覆盖")
	}
}

// A6 回归：Init 传 Pool 后调度器生效
func TestInitWiresPool(t *testing.T) {
	dir := t.TempDir()
	b := Init(BridgeConfig{DBPath: dir + "/t.db", AuditDays: 1,
		Pool: PoolLimits{MaxConnPerTarget: 8, MaxGlobalConcurrency: 33}})
	defer b.Audit.conn.Close()
	if poolMaxConnPerTarget != 8 {
		t.Fatalf("Init 未接线: %d", poolMaxConnPerTarget)
	}
	if cap(schedGlobal.sem) != 33 {
		t.Fatalf("sem 未按配置重建: %d", cap(schedGlobal.sem))
	}
	if b.Sched != schedGlobal {
		t.Fatal("b.Sched 与 schedGlobal 脱钩")
	}
	defer ConfigureLimits(5, 600, 10, 50)
}
