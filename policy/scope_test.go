package policy

import (
	"context"
	"net"
	"testing"
)

func TestScopeCheckHost(t *testing.T) {
	cfg := mustConfig(t)
	eng := testEngagement(t)
	eng.Scope.Exclude = []string{"pay.example.com"}
	s, err := NewScope(cfg.Scope, eng, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want ScopeVerdict
	}{
		{"example.com", ScopeAllow},
		{"app.example.com", ScopeAllow},
		{"a.b.example.com", ScopeAllow},
		{"pay.example.com", ScopeDeny}, // 客户显式排除，优先于 allow
		{"other.com", ScopeAmbiguous},  // 未列入清单 → 按范围外（需问询）
		{"10.1.2.3", ScopeInternal},
		{"192.168.1.1", ScopeInternal},
		{"127.0.0.1", ScopeInternal},
		{"169.254.169.254", ScopeMetadata},
		{"", ScopeDeny},
		{"EXAMPLE.COM:443", ScopeAllow}, // 端口/大小写归一
	}
	for _, tc := range cases {
		if got, reason := s.CheckHost(tc.host); got != tc.want {
			t.Errorf("CheckHost(%q)=%v(%s) want %v", tc.host, got, reason, tc.want)
		}
	}
}

func TestScopeWithoutEngagementDeniesAll(t *testing.T) {
	cfg := mustConfig(t)
	s, err := NewScope(cfg.Scope, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.CheckHost("example.com"); got == ScopeAllow {
		t.Fatal("没有授权上下文时不能放行任何目标")
	}
}

func TestScopeResolvedThirdParty(t *testing.T) {
	cfg := mustConfig(t)
	eng := testEngagement(t)
	s, _ := NewScope(cfg.Scope, eng, nil)
	// 子域在清单内，但 CNAME 指向 CloudFront（第三方托管）→ 按范围外
	v, reason := s.CheckResolved("static.example.com",
		[]string{"d111.cloudfront.net."}, []net.IP{net.ParseIP("203.0.113.10")})
	if v != ScopeAmbiguous {
		t.Fatalf("CNAME 指向第三方托管应判 ambiguous，得到 %v(%s)", v, reason)
	}
	// 解析到内网地址 → 内网（横向预算 0）
	v, _ = s.CheckResolved("app.example.com", nil, []net.IP{net.ParseIP("10.0.0.5")})
	if v != ScopeInternal {
		t.Fatalf("解析到内网应判 internal，得到 %v", v)
	}
	// 正常解析
	v, _ = s.CheckResolved("app.example.com", nil, []net.IP{net.ParseIP("203.0.113.10")})
	if v != ScopeAllow {
		t.Fatalf("正常公网解析应放行，得到 %v", v)
	}
}

func TestEgressAllowlist(t *testing.T) {
	cfg := mustConfig(t)
	eng := testEngagement(t)
	s, _ := NewScope(cfg.Scope, eng, nil)
	if !s.EgressAllowed("abc.dnslog.cn") {
		t.Error("带外验证域名 dnslog.cn 应允许（规范 6.3/6.7）")
	}
	if !s.EgressAllowed("example.com") {
		t.Error("授权目标应允许")
	}
	if s.EgressAllowed("evil.example.net") {
		t.Error("非授权、非带外域名必须拒绝（红线 8）")
	}
}

func TestResolveAndCheckWithoutResolver(t *testing.T) {
	cfg := mustConfig(t)
	eng := testEngagement(t)
	s, _ := NewScope(cfg.Scope, eng, nil)
	if v, _ := s.ResolveAndCheck(context.Background(), "app.example.com"); v != ScopeAllow {
		t.Fatalf("无 resolver 时应退化为 CheckHost，得到 %v", v)
	}
}
