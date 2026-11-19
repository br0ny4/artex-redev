package policy

import "testing"

func TestBudgetReserve(t *testing.T) {
	b := NewBudget(BudgetConfig{VulnSamples: 5, TotalRequestsPerTask: 3})
	k := BudgetKey{Engagement: "e", Task: "t", Host: "h"}

	for i := 1; i <= 5; i++ {
		ok, used, lim := b.Reserve(k, "vuln_samples", 1)
		if !ok {
			t.Fatalf("第 %d 次应成功（规范 5.3 允许 5 组）", i)
		}
		if used != float64(i) || lim != 5 {
			t.Fatalf("used=%v lim=%v want %d/5", used, lim, i)
		}
	}
	if ok, _, _ := b.Reserve(k, "vuln_samples", 1); ok {
		t.Fatal("第 6 组必须硬停止（规范 5.3）")
	}

	// 总量熔断
	k2 := BudgetKey{Engagement: "e", Task: "t2", Host: "h"}
	for i := 0; i < 3; i++ {
		if ok, _, _ := b.Reserve(k2, "total_requests_per_task", 1); !ok {
			t.Fatalf("第 %d 次应成功", i+1)
		}
	}
	if ok, _, _ := b.Reserve(k2, "total_requests_per_task", 1); ok {
		t.Fatal("超过 total_requests_per_task 必须熔断")
	}
}

func TestBudgetOverridesOnlyStricter(t *testing.T) {
	b := NewBudget(BudgetConfig{ResponseBodyMaxMB: 10, VulnSamples: 5})
	ignored := b.ApplyOverrides(map[string]any{
		"response_body_max_mb": 5,  // 更严 → 生效
		"vuln_samples":         50, // 更松 → 忽略
	})
	if len(ignored) != 1 || ignored[0] != "vuln_samples" {
		t.Fatalf("应只忽略更松的覆盖，得到 ignored=%v", ignored)
	}
	if b.Limit("response_body_max_mb") != 5 {
		t.Fatalf("更严的覆盖未生效: %v", b.Limit("response_body_max_mb"))
	}
	if b.Limit("vuln_samples") != 5 {
		t.Fatalf("更松的覆盖不应生效: %v", b.Limit("vuln_samples"))
	}
}

func TestBudgetUnlimited(t *testing.T) {
	b := NewBudget(BudgetConfig{})
	for i := 0; i < 100; i++ {
		if ok, _, _ := b.Reserve(BudgetKey{Task: "t"}, "nope", 1); !ok {
			t.Fatal("未配置上限的计数器应不限")
		}
	}
}
