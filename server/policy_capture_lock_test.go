package server

import "testing"

// 合规执行层启用后，流量录制就是判定依赖的基础设施（L3 范围/语义/预算都在代理里做），
// 关掉它等于关掉刹车。这条硬约束必须在工程层，而不是文档里写一句"请不要关闭"。
func TestManagerRefusesDisablingCaptureUnderPolicy(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("database unavailable (%v) — skipping", err)
	}
	defer m.Close()
	if m.pg == nil {
		t.Skip("postgres unavailable — skipping")
	}
	if err := m.SetTrafficEnabled(true); err != nil {
		t.Fatalf("开启录制失败: %v", err)
	}
	installTestPolicy(t) // 同时注册 cleanup：用例结束恢复未启用状态
	if err := m.SetTrafficEnabled(false); err == nil {
		t.Fatal("规范执行层启用后必须拒绝关闭流量录制（否则 L3 判定可被绕过）")
	}
	if !m.TrafficEnabled() {
		t.Fatal("拒绝关闭后录制仍应保持开启，不能出现\"报错但已关掉\"")
	}
}
