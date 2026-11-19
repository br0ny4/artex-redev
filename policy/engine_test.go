package policy

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestEngine(t *testing.T, eng *Engagement) *Engine {
	t.Helper()
	cfg := mustConfig(t)
	e, err := New(cfg, nil, eng, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func req(method, host, path string) Request {
	return Request{Method: method, Host: host, Path: path}
}

func TestDecideRequestAllow(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))
	d := e.DecideRequest(context.Background(), "task-1", req("GET", "app.example.com", "/api/user/list"))
	if d.Action != ActionAllow {
		t.Fatalf("正常读请求应放行，得到 %v(%s)", d.Action, d.Reason)
	}
}

func TestDecideRequestNoContext(t *testing.T) {
	e := newTestEngine(t, nil)
	d := e.DecideRequest(context.Background(), "task-1", req("GET", "app.example.com", "/api/user/list"))
	if d.Action != ActionDeny || d.Rule != "R0_no_context" {
		t.Fatalf("缺部署上下文必须拒绝发包，得到 %v(%s)", d.Action, d.Reason)
	}
}

func TestDecideRequestOutOfWindow(t *testing.T) {
	eng := testEngagement(t)
	eng.Window.StartsAt = time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
	eng.Window.EndsAt = time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	e := newTestEngine(t, eng)
	d := e.DecideRequest(context.Background(), "task-1", req("GET", "app.example.com", "/api/user/list"))
	if d.Action != ActionDeny || d.Rule != "R0_out_of_window" {
		t.Fatalf("超出授权时间窗必须拒绝，得到 %v(%s)", d.Action, d.Reason)
	}
}

func TestDecideRequestScope(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))
	// 未列入清单 → 归属不明 → 挂起问询（规范 7.3）
	if d := e.DecideRequest(context.Background(), "t", req("GET", "other.com", "/")); d.Action != ActionHold {
		t.Fatalf("未列入清单应挂起问询，得到 %v(%s)", d.Action, d.Reason)
	}
	// 内网 → 直接拒绝（横向预算 0）
	if d := e.DecideRequest(context.Background(), "t", req("GET", "10.0.0.5", "/")); d.Action != ActionDeny || d.Rule != "R4_internal_lateral" {
		t.Fatalf("内网目标必须拒绝，得到 %v(%s)", d.Action, d.Reason)
	}
}

func TestDecideRequestRedlines(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))
	ctx := context.Background()

	if d := e.DecideRequest(ctx, "t", req("DELETE", "app.example.com", "/api/user/1")); d.Action != ActionDeny || d.Rule != "R1_destructive" {
		t.Fatalf("删除类必须拒绝，得到 %v(%s)", d.Action, d.Reason)
	}
	if d := e.DecideRequest(ctx, "t", req("GET", "app.example.com", "/api/user/delete")); d.Action != ActionDeny {
		t.Fatalf("GET 删除接口必须拒绝，得到 %v(%s)", d.Action, d.Reason)
	}
	// C 类：未标注测试账号 → 拒绝
	if d := e.DecideRequest(ctx, "t", req("POST", "app.example.com", "/api/user/update")); d.Action != ActionDeny || d.Rule != "R5_not_test_account" {
		t.Fatalf("C 类非测试账号必须拒绝，得到 %v(%s)", d.Action, d.Reason)
	}
	// C 类：测试账号 → 放行
	r := req("POST", "app.example.com", "/api/user/update")
	r.AsTestAccount = true
	if d := e.DecideRequest(ctx, "t", r); d.Action != ActionAllow {
		t.Fatalf("C 类测试账号应放行，得到 %v(%s)", d.Action, d.Reason)
	}
	// D 类高危（退款）即便测试账号也拒绝（红线 9）
	r2 := req("POST", "app.example.com", "/api/order/refund")
	r2.AsTestAccount = true
	if d := e.DecideRequest(ctx, "t", r2); d.Action != ActionDeny || d.Rule != "R9_money" {
		t.Fatalf("资金类必须拒绝，得到 %v(%s)", d.Action, d.Rule)
	}
	// 凭据复用（红线 10）
	r3 := req("GET", "app.example.com", "/api/user/me")
	r3.HasHarvestedCredential = true
	if d := e.DecideRequest(ctx, "t", r3); d.Action != ActionDeny || d.Rule != "R10_cred_reuse" {
		t.Fatalf("复用窃取凭据必须拒绝，得到 %v(%s)", d.Action, d.Rule)
	}
	// 语义判不清 → 挂起问询
	if d := e.DecideRequest(ctx, "t", req("POST", "app.example.com", "/api/user/profile")); d.Action != ActionHold {
		t.Fatalf("语义判不清应挂起，得到 %v(%s)", d.Action, d.Reason)
	}
}

func TestDecideRequestBudgetFuse(t *testing.T) {
	cfg := mustConfig(t)
	cfg.Budget.TotalRequestsPerTask = 2
	e, err := New(cfg, nil, testEngagement(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if d := e.DecideRequest(ctx, "t", req("GET", "app.example.com", "/api/list")); d.Action != ActionAllow {
			t.Fatalf("第 %d 次应放行，得到 %v", i+1, d.Action)
		}
	}
	if d := e.DecideRequest(ctx, "t", req("GET", "app.example.com", "/api/list")); d.Action != ActionHold || d.Rule != "BUDGET_EXHAUSTED" {
		t.Fatalf("超预算应熔断，得到 %v(%s)", d.Action, d.Reason)
	}
}

func TestInspectResponse(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))

	// 敏感信息命中即停（规范 5.4）
	v := e.InspectResponse(ResponseInfo{ContentType: "application/json",
		Body: []byte(`{"key":"-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}`)})
	if !v.Hold || v.Rule != "R5_sensitive_hit" {
		t.Fatalf("私钥特征应即停，得到 %+v", v)
	}

	// 源码泄露
	v = e.InspectResponse(ResponseInfo{ContentType: "text/plain",
		Body: []byte("<?php\n$db = new PDO('mysql:host=127.0.0.1','root','pw');\n")})
	if !v.Hold {
		t.Fatalf("源码特征应即停，得到 %+v", v)
	}

	// 超过响应体上限 → 视为拖取
	big := make([]byte, int(10.5*1024*1024))
	for i := range big {
		big[i] = 'a'
	}
	v = e.InspectResponse(ResponseInfo{ContentType: "text/plain", Body: big})
	if !v.Hold || v.Rule != "R2_bulk_export" {
		t.Fatalf("超限响应应即停，得到 %+v", v)
	}

	// 正常响应放行，且能读出记录数（规范 5.1 用计数代替取数）
	v = e.InspectResponse(ResponseInfo{ContentType: "application/json",
		Body: []byte(`{"total":1024,"data":[{"id":1},{"id":2}]}`)})
	if v.Hold {
		t.Fatalf("正常响应不应挂起：%+v", v)
	}
	if v.Rows != 1024 {
		t.Fatalf("应优先读 total 字段，得到 rows=%d", v.Rows)
	}
}

func TestCheckCommandScope(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))
	if d := e.CheckCommand("t", "curl -s http://evil.test/x", CommandOptions{}); d.Action != ActionDeny || d.Rule != "R1_scope" {
		t.Fatalf("命令目标越界必须拒绝，得到 %v(%s)", d.Action, d.Reason)
	}
	if d := e.CheckCommand("t", "curl -s http://app.example.com/api", CommandOptions{}); d.Action != ActionAllow {
		t.Fatalf("范围内目标应放行，得到 %v(%s)", d.Action, d.Reason)
	}
}

func TestCheckCommandScanerApproval(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))
	d := e.CheckCommand("t", "nmap -sV app.example.com", CommandOptions{})
	if d.Action != ActionDeny || !strings.Contains(d.Reason, "扫描器") {
		t.Fatalf("扫描器默认禁用，得到 %v(%s)", d.Action, d.Reason)
	}
}

func TestHoldLifecycle(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))
	e.SetHold("t", "预算耗尽")
	if held, reason := e.Held("t"); !held || reason != "预算耗尽" {
		t.Fatalf("挂起状态未生效: %v %q", held, reason)
	}
	e.ReleaseHold("t")
	if held, _ := e.Held("t"); held {
		t.Fatal("释放后不应仍处于挂起")
	}
}

func TestQueryParsingInClassify(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))
	r := req("GET", "app.example.com", "/api/user/delete")
	q, _ := url.ParseQuery("id=1&action=purge")
	r.Query = q
	if d := e.DecideRequest(context.Background(), "t", r); d.Action != ActionDeny {
		t.Fatalf("参数开关 purge 应被判定为破坏性，得到 %v", d.Action)
	}
}

// 回归：前端 JS 是公开资产，不是"服务器源码泄露"，不能因此挂起任务——
// 否则任何一次正常的 web 测试都会被自己的静态资源打断。
func TestInspectResponseIgnoresFrontendJS(t *testing.T) {
	e := newTestEngine(t, testEngagement(t))
	js := []byte(`import React from "react";
export const App = () => null;
module.exports = {a: 1};
`)
	v := e.InspectResponse(ResponseInfo{ContentType: "application/javascript", Body: js})
	if v.Hold {
		t.Fatalf("前端 JS 不应触发即停：%+v", v)
	}

	// 普通业务 JSON 里的 password 字段（值不像密钥）也不应即停
	body := []byte(`{"username":"alice","password":"placeholder","role":"user"}`)
	v = e.InspectResponse(ResponseInfo{ContentType: "application/json", Body: body})
	if v.Hold {
		t.Fatalf("普通业务字段不应触发即停：%+v", v)
	}
}
