package traffic

// L3 出口的端到端验收：起真实录制代理 → 客户端把请求交给代理 → 断言请求**没有
// 发到目标**、而是被判定层挡下（403 + X-ArtEx-Policy），且这次尝试进了流量索引。
//
// 为什么值得单独做：policy 包的单测只能证明"判定函数返回 deny"，证明不了
// "代理真的没发包"。用不存在的 .invalid 域名做目标，如果代理把请求转发出去会得到
// 502/网络错误；只有 403 才说明它在发包前就拦下了。

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/br0ny4/artex-redev/policy"
)

func installE2EPolicy(t *testing.T) {
	t.Helper()
	now := time.Now()
	ctx := fmt.Sprintf(`
engagement:
  id: E2E-L3-001
  client: 示例客户
  title: L3 出口验收
  authorization_doc: ./docs/authorization/e2e.pdf
  authorization_doc_sha256: "%s"
  window:
    starts_at: %q
    ends_at: %q
    timezone: Asia/Shanghai
scope:
  domains: [in-scope.example.com]
test_accounts:
  - id: ta-001
    username: pentest_a_001
    role: 普通用户
allowed_tools:
  always: [curl]
report:
  channel: https://report.example.com/E2E-L3-001
artifacts:
  dir: ./artifacts/E2E-L3-001
compliance:
  spec_version: "2.5"
  handshake: "[RULES_LOADED v2.5]"
  operator_acknowledged: true
`,
		strings.Repeat("0", 64),
		now.Add(-24*time.Hour).Format(time.RFC3339),
		now.Add(24*time.Hour).Format(time.RFC3339))
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	if err := os.WriteFile(path, []byte(ctx), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := policy.InstallFromFile(path)
	if err != nil {
		t.Fatalf("安装执行层: %v", err)
	}
	if eng == nil || !eng.Enforcing() {
		t.Fatal("执行层安装后应处于强制模式")
	}
	t.Cleanup(func() { policy.Install(nil) })
}

// freeAddr 取一个当前空闲的回环端口（关闭后交给代理监听，存在极小竞争窗口）。
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// waitProxyUp 等到代理端口可连（Start 成功后监听才建立）。
func waitProxyUp(t *testing.T, addr string) error {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("代理 %s 5s 内未就绪", addr)
}

func proxyClient(t *testing.T, tr *Traffic) *http.Client {
	t.Helper()
	pu, err := url.Parse(tr.ProxyAddr()) // ProxyAddr 已带 http:// 前缀
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pu),
			// 代理用自签 CA 时客户端需要信任；这里走明文 HTTP，不涉及 TLS。
		},
	}
}

func TestL3ProxyBlocksOutOfScopeBeforeSending(t *testing.T) {
	installE2EPolicy(t)
	// mitmproxy 不回报实际监听端口（addr 为 :0 时会一直显示 :0），所以先占一个空闲端口。
	tr, err := Open(t.TempDir(), freeAddr(t))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	// 代理的 Start 是阻塞的服务循环（线上由 manager 放进 goroutine），测试这里同样起
	// 一个 goroutine，并等端口真正可连再发请求，避免"请求打早了"变成随机失败。
	go func() {
		if err := tr.Start(); err != nil {
			t.Logf("proxy start 返回：%v", err)
		}
	}()
	if err := waitProxyUp(t, strings.TrimPrefix(tr.ProxyAddr(), "http://")); err != nil {
		t.Fatal(err)
	}

	resp, err := proxyClient(t, tr).Get("http://unlisted-host.invalid/api/user/list")
	if err != nil {
		t.Fatalf("代理请求失败（说明请求被转发出去了，而不是在出口被挡）：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want 403：范围外请求必须在代理出口被挡下", resp.StatusCode)
	}
	rule := resp.Header.Get("X-ArtEx-Policy")
	if rule == "" {
		t.Fatal("缺少 X-ArtEx-Policy：运维与审计需要知道是哪条判定挡的")
	}
	buf := make([]byte, 2048)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "平台管控") {
		t.Fatalf("阻断说明不对：%s", string(buf[:n]))
	}
	// 阻断尝试要进流量索引：既当证据，也方便排查误拦。
	if n, err := tr.Count(); err != nil || n == 0 {
		t.Fatalf("阻断尝试未落流量索引：count=%d err=%v", n, err)
	}
}
