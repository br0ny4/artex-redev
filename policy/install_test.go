package policy

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// 代理出口上每个请求都要判范围，DNS 必须有缓存；同时缓存让"判定用 IP"
// 与"实际连接 IP"保持一致（压掉 rebinding 时间窗）。
func TestNetResolverCaches(t *testing.T) {
	r := NewNetResolver(time.Minute)
	var ipCalls, cnameCalls atomic.Int32
	r.lookupIP = func(context.Context, string) ([]net.IP, error) {
		ipCalls.Add(1)
		return []net.IP{net.ParseIP("203.0.113.9")}, nil
	}
	r.lookupCNAME = func(context.Context, string) (string, error) {
		cnameCalls.Add(1)
		return "edge.example.com.", nil
	}

	for i := 0; i < 5; i++ {
		cn, ips, err := r.LookupAll(context.Background(), "app.example.com")
		if err != nil || len(ips) != 1 || cn == "" {
			t.Fatalf("第 %d 次解析结果异常: cn=%q ips=%v err=%v", i+1, cn, ips, err)
		}
	}
	if ipCalls.Load() != 1 || cnameCalls.Load() != 1 {
		t.Fatalf("应只解析一次，实际 ip=%d cname=%d", ipCalls.Load(), cnameCalls.Load())
	}
}

func TestNetResolverFailureCachedShortly(t *testing.T) {
	r := NewNetResolver(time.Minute)
	var calls atomic.Int32
	r.lookupIP = func(context.Context, string) ([]net.IP, error) {
		calls.Add(1)
		return nil, &net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true}
	}
	r.lookupCNAME = func(context.Context, string) (string, error) {
		return "", &net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true}
	}
	if _, _, err := r.LookupAll(context.Background(), "nope.invalid"); err == nil {
		t.Fatal("解析失败应返回错误")
	}
	// 失败也缓存，避免被不存在的域名打爆 DNS
	if _, _, err := r.LookupAll(context.Background(), "nope.invalid"); err == nil {
		t.Fatal("第二次也应返回缓存的失败")
	}
	if calls.Load() != 1 {
		t.Fatalf("失败结果应缓存，实际解析 %d 次", calls.Load())
	}
}

func TestScopeUsesMultiResolver(t *testing.T) {
	cfg := mustConfig(t)
	eng := testEngagement(t)
	r := NewNetResolver(time.Minute)
	r.lookupCNAME = func(context.Context, string) (string, error) { return "d1.cloudfront.net.", nil }
	r.lookupIP = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.9")}, nil
	}
	s, err := NewScope(cfg.Scope, eng, r)
	if err != nil {
		t.Fatal(err)
	}
	// 清单内的子域，但 CNAME 指向第三方托管 → 按范围外，需问询
	v, reason := s.ResolveAndCheck(context.Background(), "static.example.com")
	if v != ScopeAmbiguous {
		t.Fatalf("第三方托管应判 ambiguous，得到 %v(%s)", v, reason)
	}
}

func TestInstallFromFileRejectsIncompleteContext(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ctx.yaml"
	// 缺 scope / test_accounts / report / artifacts
	body := "engagement:\n  client: acme\n  authorization_doc_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"
	if err := writeFile(path, body); err != nil {
		t.Fatal(err)
	}
	old := Install(nil)
	defer Install(old)
	if _, err := InstallFromFile(path); err == nil {
		t.Fatal("上下文缺项时必须拒绝安装（规范 9.2）")
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// TestLoadEngagementAcceptsShippedTemplate 守住"文档模板必须能被引擎直接读取"。
//
// 这条曾经是真的坏过：模板用 engagement: 包一层、scope 在顶层，而 LoadEngagement
// 只认扁平写法——照模板填的授权文件永远装不上引擎，策略静默失效。模板与解析器
// 分属不同文件，没有用例就会再次漂移。
func TestLoadEngagementAcceptsShippedTemplate(t *testing.T) {
	raw, err := os.ReadFile("web-pentest/deployment-context.example.yaml")
	if err != nil {
		t.Fatalf("读取随仓库发布的模板: %v", err)
	}
	e, err := LoadEngagement(raw)
	if err != nil {
		t.Fatalf("模板必须能被直接加载（否则策略静默失效）: %v", err)
	}
	if len(e.Scope.Domains) == 0 {
		t.Fatal("顶层 scope 应合并进 Engagement.Scope")
	}
	if len(e.Accounts) == 0 {
		t.Fatal("顶层 test_accounts 应合并进 Engagement.Accounts")
	}
	if e.Report.Channel == "" || e.Artifacts.Dir == "" {
		t.Fatalf("顶层 report/artifacts 未合并: report=%q artifacts=%q", e.Report.Channel, e.Artifacts.Dir)
	}
	if e.ID == "" || e.Client == "" {
		t.Fatalf("engagement: 段未解析: id=%q client=%q", e.ID, e.Client)
	}
}
