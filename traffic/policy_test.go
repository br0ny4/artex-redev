package traffic

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/br0ny4/artex-redev/policy"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

func testPolicyEngine(t *testing.T, mode string) *policy.Engine {
	t.Helper()
	cfg, err := policy.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Enforcement.Mode = mode
	now := time.Now()
	eng := &policy.Engagement{
		ID:     "ENG-L3",
		Client: "test",
		Window: policy.Window{
			StartsAt: now.Add(-time.Hour).Format(time.RFC3339),
			EndsAt:   now.Add(time.Hour).Format(time.RFC3339),
		},
		Scope: policy.EngScope{Domains: []string{"example.com", "*.example.com"}},
	}
	e, err := policy.New(cfg, nil, eng, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func flowFor(method, rawURL string, body []byte) *mproxy.Flow {
	u, _ := url.Parse(rawURL)
	return &mproxy.Flow{Request: &mproxy.Request{Method: method, URL: u, Body: body}}
}

func TestDecideRequestPolicyAllowsInScope(t *testing.T) {
	eng := testPolicyEngine(t, "hard")
	dec, block := decideRequestPolicy(eng, flowFor("GET", "http://app.example.com/api/user/list", nil))
	if block {
		t.Fatalf("范围内读请求不应阻断：%s", dec.Reason)
	}
}

func TestDecideRequestPolicyBlocksOutOfScope(t *testing.T) {
	eng := testPolicyEngine(t, "hard")
	dec, block := decideRequestPolicy(eng, flowFor("GET", "http://evil.test/x", nil))
	if !block {
		t.Fatal("范围外请求必须阻断")
	}
	if dec.Action != policy.ActionHold && dec.Action != policy.ActionDeny {
		t.Fatalf("判定动作异常：%s", dec.Action)
	}
}

func TestDecideRequestPolicyBlocksDestructive(t *testing.T) {
	eng := testPolicyEngine(t, "hard")
	// 上游 CHANGELOG 明确漏过的那类：GET 也能触发删除
	_, block := decideRequestPolicy(eng, flowFor("GET", "http://app.example.com/api/user/delete?id=1", nil))
	if !block {
		t.Fatal("删除类请求必须阻断（规范红线 1）")
	}
	_, block = decideRequestPolicy(eng, flowFor("DELETE", "http://app.example.com/api/user/1", nil))
	if !block {
		t.Fatal("DELETE 必须阻断")
	}
}

func TestDecideRequestPolicyWarnMode(t *testing.T) {
	eng := testPolicyEngine(t, "warn")
	_, block := decideRequestPolicy(eng, flowFor("GET", "http://evil.test/x", nil))
	if block {
		t.Fatal("warn 模式只记录不阻断")
	}
}

func TestPolicyBlockMessageFraming(t *testing.T) {
	msg := policyBlockMessage(policy.Decision{Rule: "R1_scope", Reason: "未列入授权清单"})
	if !strings.Contains(msg, "平台管控") {
		t.Fatalf("拦截消息必须说明是平台策略而非目标防御：%s", msg)
	}
	if !strings.Contains(msg, "未发送到目标") {
		t.Fatalf("拦截消息应明确请求没有发出去：%s", msg)
	}
}

func TestRequestView(t *testing.T) {
	f := flowFor("POST", "https://app.example.com/api/x?a=1", []byte(`{"b":2}`))
	v := requestView(f.Request)
	if v.Host != "app.example.com" || v.Path != "/api/x" || v.Method != "POST" {
		t.Fatalf("view=%+v", v)
	}
	if v.Query.Get("a") != "1" {
		t.Fatalf("query 未解析：%v", v.Query)
	}
	if string(v.Body) != `{"b":2}` {
		t.Fatalf("body 未带上：%q", v.Body)
	}
}
