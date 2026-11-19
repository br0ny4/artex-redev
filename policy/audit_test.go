package policy

import (
	"context"
	"strings"
	"testing"
)

// 判定必须落审计：拒绝/挂起都要有事件，放行不刷日志（否则审计表会被正常流量淹掉）。
func TestAuditorReceivesDenials(t *testing.T) {
	var got []Event
	SetAuditor(func(e Event) { got = append(got, e) })
	defer SetAuditor(nil)

	e := newTestEngine(t, testEngagement(t))
	ctx := context.Background()

	// 拒绝 → 一条 L3-request 事件
	e.DecideRequest(ctx, "task-9", req("DELETE", "app.example.com", "/api/user/1"))
	// 放行 → 不产生事件
	e.DecideRequest(ctx, "task-9", req("GET", "app.example.com", "/api/list"))
	// 命令拒绝 → 一条 L1-command 事件
	e.CheckCommand("task-9", "nmap app.example.com", CommandOptions{})

	if len(got) != 2 {
		t.Fatalf("应产生 2 条事件，实际 %d：%+v", len(got), got)
	}
	if got[0].Source != "L3-request" || got[0].Action != string(ActionDeny) || got[0].Rule == "" {
		t.Fatalf("请求事件字段不全：%+v", got[0])
	}
	if got[0].EngagementID != "ENG-TEST" {
		t.Fatalf("事件应带 engagement id：%+v", got[0])
	}
	if got[1].Source != "L1-command" || got[1].Path == "" {
		t.Fatalf("命令事件字段不全：%+v", got[1])
	}
}

func TestAuditorNilSafe(t *testing.T) {
	SetAuditor(nil)
	// 未安装出口时判定照常工作，且不 panic
	e := newTestEngine(t, testEngagement(t))
	if d := e.DecideRequest(context.Background(), "t", req("DELETE", "app.example.com", "/api/user/1")); d.Action != ActionDeny {
		t.Fatalf("无 auditor 时判定应照常：%v", d.Action)
	}
}

func TestCommandAuditTruncates(t *testing.T) {
	var got []Event
	SetAuditor(func(e Event) { got = append(got, e) })
	defer SetAuditor(nil)
	e := newTestEngine(t, testEngagement(t))

	long := "nuclei -u http://app.example.com/?q=" + strings.Repeat("A", 500)
	e.CheckCommand("t", long, CommandOptions{})
	if len(got) != 1 {
		t.Fatalf("应有 1 条事件，实际 %d", len(got))
	}
	if len(got[0].Path) > 240 {
		t.Fatalf("命令审计未截断（%d 字节），可能把 payload 里的凭据写进日志", len(got[0].Path))
	}
}
