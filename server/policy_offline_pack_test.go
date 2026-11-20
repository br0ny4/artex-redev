package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/br0ny4/artex-redev/policy"
)

// installTestPolicyPack 在 Manager 之前安装指定域包的授权上下文，用来验证
// "启动期"行为（在线域没有录制代理必须拒绝启动；离线域允许）。
func installTestPolicyPack(t *testing.T, pack string, isOnline bool) {
	t.Helper()
	now := time.Now()
	scope := fmt.Sprintf("  local_paths: [%q]", t.TempDir())
	if isOnline {
		scope = "  domains: [example.com]"
	}
	accounts := "test_accounts: []\n"
	if isOnline {
		accounts = fmt.Sprintf(`test_accounts:
  - id: ta-1
    username: pentest_a
    bound_contact:
      phone: "+8613800000000"
`)
	}
	ctx := fmt.Sprintf(`engagement:
  id: ENG-PACK
  client: pack-client
  title: pack-startup
  pack: %s
  authorization_doc_sha256: %s
  window:
    starts_at: "%s"
    ends_at: "%s"
scope:
%s
%sreport:
  channel: https://src.example.com/report/ENG-PACK
artifacts:
  dir: %s
compliance:
  spec_version: "2.5"
`,
		pack,
		policy.SHA256Hex([]byte("authorization-doc")),
		now.Add(-time.Hour).Format(time.RFC3339),
		now.Add(time.Hour).Format(time.RFC3339),
		scope, accounts, t.TempDir(),
	)
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	if err := os.WriteFile(path, []byte(ctx), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.InstallFromFile(path); err != nil {
		t.Fatalf("安装 %s 授权上下文失败: %v", pack, err)
	}
	t.Cleanup(func() { policy.Install(nil) })
}

// 离线域包（binary-re 等）分析的是本地产物、不产生目标侧 HTTP 流量：
// 没有录制代理也必须能启动，否则"合规"会反过来挡住样本/源码分析。
func TestManagerStartsWithOfflinePackWithoutProxy(t *testing.T) {
	installTestPolicyPack(t, "binary-re", false)
	// 同一套 PG 可能被前面的在线域用例置过 traffic_capture=true；先恢复成初始态，
	// 才能验证"离线域不会强制开启"（而不是碰巧沿用上一次设置）。
	if m0, err := NewManager(t.TempDir(), ""); err == nil {
		_ = m0.pg.SetBool(settingTrafficCapture, false)
		m0.Close()
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatalf("离线域包在无录制代理时应能启动: %v", err)
	}
	defer m.Close()
	if m.TrafficEnabled() {
		t.Fatal("离线域包启动时不应强制开启录制")
	}
	if err := m.SetTrafficEnabled(false); err != nil {
		t.Fatalf("离线域包应允许关闭录制: %v", err)
	}
}

// 在线域包仍然是 fail-closed：没有录制代理就拒绝启动（L3 判定在代理里）。
func TestManagerRefusesStartForOnlinePackWithoutProxy(t *testing.T) {
	installTestPolicyPack(t, "web-pentest", true)
	if _, err := NewManager(t.TempDir(), ""); err == nil {
		t.Fatal("在线域包没有录制代理时必须拒绝启动")
	}
}
