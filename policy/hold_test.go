package policy

import (
	"context"
	"testing"
)

// 规范 7.3：需要确认时**全量停止**，未获明确答复前不恢复。
func TestGlobalHoldStopsEverything(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))
	ctx := context.Background()

	// 触发挂起：范围归属不明
	d := e.DecideRequest(ctx, "t", req("GET", "unknown.example.net", "/"))
	if d.Action != ActionHold || d.Rule != "SCOPE_UNCERTAIN" {
		t.Fatalf("应挂起，得到 %v(%s)", d.Action, d.Rule)
	}
	h, ok := e.ActiveHold()
	if !ok || h.ID == 0 || h.Question == "" {
		t.Fatalf("挂起状态不完整: %+v ok=%v", h, ok)
	}

	// 挂起期间：范围内的正常请求也不放行（不是只挡触发那一条）
	if d := e.DecideRequest(ctx, "t", req("GET", "app.example.com", "/api/list")); d.Rule != "STOP_ALL" {
		t.Fatalf("挂起期间应 STOP_ALL，得到 %v(%s)", d.Action, d.Rule)
	}
	// 命令出口同样停
	if d := e.CheckCommand("t", "curl http://app.example.com", CommandOptions{}); d.Rule != "STOP_ALL" {
		t.Fatalf("命令出口也应 STOP_ALL，得到 %v(%s)", d.Action, d.Rule)
	}

	// 错误 id 不能解除（防止旧答复解掉新挂起）
	if e.ReleaseGlobalHold(h.ID + 1) {
		t.Fatal("错误 id 不应能解除挂起")
	}
	// 正确 id 解除后恢复
	if !e.ReleaseGlobalHold(h.ID) {
		t.Fatal("正确 id 应能解除")
	}
	if d := e.DecideRequest(ctx, "t", req("GET", "app.example.com", "/api/list")); d.Action != ActionAllow {
		t.Fatalf("解除后应恢复，得到 %v(%s)", d.Action, d.Reason)
	}
}

func TestRaiseHoldIdempotent(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))
	h1, created1 := e.RaiseHold("R1", "原因一", "问题一")
	if !created1 {
		t.Fatal("首次应创建")
	}
	h2, created2 := e.RaiseHold("R2", "原因二", "问题二")
	if created2 {
		t.Fatal("重复挂起应幂等，不该覆盖原因")
	}
	if h2.ID != h1.ID || h2.Reason != h1.Reason {
		t.Fatalf("幂等返回不一致: %+v vs %+v", h1, h2)
	}
}

// 挂起只发一次审计事件，避免 agent 重试把审计表刷满。
func TestHoldEmitsAuditOnce(t *testing.T) {
	var events []Event
	SetAuditor(func(ev Event) { events = append(events, ev) })
	defer SetAuditor(nil)

	e := newTestEngine(t, testEngagement(t))
	ctx := context.Background()
	e.DecideRequest(ctx, "t", req("GET", "unknown.example.net", "/"))         // 触发挂起
	e.DecideRequest(ctx, "t", req("GET", "unknown.example.net", "/"))         // 已挂起 → STOP_ALL
	e.CheckCommand("t", "nuclei -u http://app.example.com", CommandOptions{}) // 已挂起 → STOP_ALL

	holdEvents := 0
	for _, ev := range events {
		if ev.Source == "L5-hold" {
			holdEvents++
			if ev.HoldID == 0 || ev.Question == "" {
				t.Fatalf("挂起事件缺字段: %+v", ev)
			}
		}
	}
	if holdEvents != 1 {
		t.Fatalf("挂起事件应只发一次，实际 %d 次", holdEvents)
	}
	// STOP_ALL 不应再产生新事件
	if len(events) != 1 {
		t.Fatalf("挂起期间不应产生额外事件，实际 %d 条", len(events))
	}
}

func TestBudgetExhaustionRaisesHold(t *testing.T) {
	cfg := mustConfig(t)
	cfg.Budget.TotalRequestsPerTask = 1
	e, err := New(cfg, nil, testEngagement(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if d := e.DecideRequest(ctx, "t", req("GET", "app.example.com", "/a")); d.Action != ActionAllow {
		t.Fatalf("第一条应放行，得到 %v", d.Action)
	}
	d := e.DecideRequest(ctx, "t", req("GET", "app.example.com", "/b"))
	if d.Rule != "BUDGET_EXHAUSTED" {
		t.Fatalf("超预算应挂起，得到 %v(%s)", d.Action, d.Rule)
	}
	if h, ok := e.ActiveHold(); !ok || h.Rule != "BUDGET_EXHAUSTED" {
		t.Fatalf("应存在预算挂起: %+v ok=%v", h, ok)
	}
}
