package db

import (
	"testing"
	"time"
)

// 判定链：prev_hash 参与摘要，任何一条被改都会让后续全部失配。
func TestDecisionHashChain(t *testing.T) {
	d := PolicyDecision{
		TS:     time.Unix(1700000000, 0).UTC(),
		TaskID: "task-1",
		Source: "L3-request",
		Host:   "app.example.com",
		Method: "DELETE",
		Path:   "/api/user/1",
		Class:  "A",
		Action: "deny",
		Rule:   "R1_destructive",
		Reason: "删除类接口禁止测试",
		Budget: map[string]float64{"total_requests_per_task": 3},
	}
	h1 := decisionHash("", d)
	h2 := decisionHash(h1, d)
	if h1 == "" || h2 == "" {
		t.Fatal("摘要不应为空")
	}
	if h1 == h2 {
		t.Fatal("prev_hash 必须参与摘要（链式）")
	}
	// 稳定：同样的输入必须得到同样的摘要
	if decisionHash("", d) != h1 {
		t.Fatal("摘要不稳定，无法用于证据链校验")
	}
	// 篡改任一字段 → 摘要变化
	tampered := d
	tampered.Rule = "R_allow_everything"
	if decisionHash("", tampered) == h1 {
		t.Fatal("字段被篡改后摘要未变化")
	}
	tampered = d
	tampered.Budget = map[string]float64{"total_requests_per_task": 4}
	if decisionHash("", tampered) == h1 {
		t.Fatal("预算快照被篡改后摘要未变化")
	}
}
