package vulngate

import (
	"strings"
	"testing"
)

func TestParseReplayRequestRawHTTP(t *testing.T) {
	in := "POST /api/user/list HTTP/1.1\r\nHost: in-scope.example.com\r\nContent-Type: application/json\r\nCookie: sid=1\r\n\r\n{\"page\":1}"
	r, err := ParseReplayRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "POST" || r.Scheme != "https" || r.Host != "in-scope.example.com" || r.Path != "/api/user/list" {
		t.Fatalf("解析错误：%+v", r)
	}
	if string(r.Body) != `{"page":1}` {
		t.Fatalf("body 应保留：%q", r.Body)
	}
	if _, ok := r.Headers["Host"]; ok {
		t.Fatal("Host 应转成 URL 的 host，不该重复进头")
	}
	if r.Headers["Cookie"] != "sid=1" {
		t.Fatalf("应保留 Cookie：%+v", r.Headers)
	}
}

func TestParseReplayRequestURLForm(t *testing.T) {
	r, err := ParseReplayRequest("https://in-scope.example.com/x?y=1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "GET" || r.Path != "/x?y=1" || r.Host != "in-scope.example.com" {
		t.Fatalf("URL 形态解析错误：%+v", r)
	}
}

func TestParseReplayRequestSchemeOverrideAndAbsoluteTarget(t *testing.T) {
	r, err := ParseReplayRequest("GET /plain HTTP/1.1\nHost: in-scope.example.com\nX-ArtEx-Scheme: http\n")
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "http" {
		t.Fatalf("X-ArtEx-Scheme 应覆盖默认 https：%+v", r)
	}
	if _, ok := r.Headers["X-ArtEx-Scheme"]; ok {
		t.Fatal("X-ArtEx-Scheme 是控制头，不该转发给目标")
	}

	r, err = ParseReplayRequest("GET https://in-scope.example.com/abs HTTP/1.1\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if r.Host != "in-scope.example.com" || r.Path != "/abs" {
		t.Fatalf("绝对形式请求行解析错误：%+v", r)
	}
}

func TestParseReplayRequestErrors(t *testing.T) {
	for name, in := range map[string]string{
		"空":          "   ",
		"请求行缺路径":     "GET\n",
		"相对路径无 Host": "GET /api HTTP/1.1\n",
		"不支持协议":      "ftp://in-scope.example.com/x",
	} {
		if _, err := ParseReplayRequest(in); err == nil {
			t.Fatalf("%s：应报错", name)
		}
	}
}

func TestMatchExpectation(t *testing.T) {
	p := Poc{ExpectStatus: 200, ExpectBodyContains: []string{"admin", "secret"}}
	ok, mism := MatchExpectation(p, ReplayResult{Status: 200, Body: "welcome ADMIN here, secret=1"})
	if !ok || len(mism) != 0 {
		t.Fatalf("应判定一致：%v", mism)
	}

	ok, mism = MatchExpectation(p, ReplayResult{Status: 403, Body: "denied"})
	if ok || len(mism) == 0 {
		t.Fatal("状态码不符应不一致")
	}
	if !containsStr(mism, "状态码不符") || !containsStr(mism, "响应体不含") {
		t.Fatalf("应同时报状态码与响应体不一致：%v", mism)
	}

	ok, mism = MatchExpectation(Poc{}, ReplayResult{Status: 200, Body: "x"})
	if ok || !containsStr(mism, "expect_status") {
		t.Fatalf("没有机器可判预期时不能判为通过：%v", mism)
	}

	ok, mism = MatchExpectation(p, ReplayResult{Status: 200, Body: "welcome admin here, secret=1", Denied: "R1_scope"})
	if ok || !containsStr(mism, "规范执行层") {
		t.Fatalf("被拦下的请求不能算复现：%v", mism)
	}
}

func containsStr(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
