package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/br0ny4/artex-redev/policy"
	"github.com/Autumn-27/norma/hook"
)

func testEngine(t *testing.T, mode string) *policy.Engine {
	t.Helper()
	cfg, err := policy.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Enforcement.Mode = mode
	eng := &policy.Engagement{
		ID:     "ENG-TEST",
		Client: "test",
		Scope:  policy.EngScope{Domains: []string{"example.com", "*.example.com"}},
	}
	e, err := policy.New(cfg, nil, eng, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func bashEvent(cmd string) hook.Event {
	b, _ := json.Marshal(map[string]any{"command": cmd})
	return hook.Event{Type: hook.PreToolUse, ToolName: "Bash", Input: b}
}

func TestPolicyBlocksOutOfScopeCommand(t *testing.T) {
	g := NewWithInterceptorAndPolicy(nil, testEngine(t, "hard"))
	res := g.preToolUse(context.Background(), bashEvent("curl -s http://evil.test/x"))
	if res.Decision != "block" {
		t.Fatalf("越界命令应被拦截，得到 decision=%q msg=%q", res.Decision, res.Message)
	}
	if !strings.Contains(res.Message, "ARTEX 平台管控") {
		t.Fatalf("拦截消息应说明是平台策略而非目标防御：%q", res.Message)
	}

	res = g.preToolUse(context.Background(), bashEvent("curl -s http://app.example.com/api"))
	if res.Decision == "block" {
		t.Fatalf("范围内命令不应被拦截：%q", res.Message)
	}
}

func TestPolicyBlocksScanner(t *testing.T) {
	g := NewWithInterceptorAndPolicy(nil, testEngine(t, "hard"))
	res := g.preToolUse(context.Background(), bashEvent("nuclei -u http://app.example.com"))
	if res.Decision != "block" {
		t.Fatal("扫描器未审批应被拦截（规范第三章 3）")
	}
}

func TestPolicyWarnModeDoesNotBlock(t *testing.T) {
	g := NewWithInterceptorAndPolicy(nil, testEngine(t, "warn"))
	res := g.preToolUse(context.Background(), bashEvent("nmap app.example.com"))
	if res.Decision == "block" {
		t.Fatal("warn 模式不应阻断，只记录")
	}
	found := false
	for _, a := range g.Audit() {
		if a.Action == "warn" && strings.Contains(a.Reason, "policy:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warn 模式应留下审计记录，实际 %+v", g.Audit())
	}
}

func TestNoEngineKeepsUpstreamBehavior(t *testing.T) {
	policy.Install(nil) // 确保全局默认引擎为空
	g := New()
	res := g.preToolUse(context.Background(), bashEvent("nuclei -u http://evil.test"))
	if res.Decision == "block" {
		t.Fatal("未安装引擎时必须保持上游原行为（不拦截）")
	}
}

func TestGlobalDefaultEngineUsed(t *testing.T) {
	eng := testEngine(t, "hard")
	old := policy.Install(eng)
	defer policy.Install(old)

	g := New() // 不显式传引擎
	res := g.preToolUse(context.Background(), bashEvent("bash -c 'id'"))
	if res.Decision != "block" {
		t.Fatal("全局安装的引擎应生效（内联解释器拦截）")
	}
}
