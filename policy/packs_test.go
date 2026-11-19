package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 域包是"同一套执行层契约、不同域策略"的载体。这里守住三件事：
// 包能被发现、包里的关键差异真的进了判定、不认识的包不会被静默回退。
func TestAvailablePacks(t *testing.T) {
	got := AvailablePacks()
	joined := strings.Join(got, ",")
	for _, want := range []string{"web-pentest", "binary-re", "source-audit", "malware-triage"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("域包列表缺少 %s：%v", want, got)
		}
	}
}

func TestPackConfigBinaryRE(t *testing.T) {
	cfg, err := PackConfig("binary-re")
	if err != nil {
		t.Fatalf("加载 binary-re: %v", err)
	}
	if cfg.Pack != "binary-re" {
		t.Fatalf("Pack=%q want binary-re", cfg.Pack)
	}
	if cfg.Spec.ID != "offline-binary-analysis" {
		t.Fatalf("spec.id=%q，离线域不该复用在线域的 spec id", cfg.Spec.ID)
	}
	// 离线域的出网白名单必须包含情报源，否则"查哈希"这一步直接不可用。
	join := strings.Join(cfg.Scope.EgressAllowlistExtra, ",")
	if !strings.Contains(join, "virustotal.com") {
		t.Fatalf("出网白名单缺少情报源：%v", cfg.Scope.EgressAllowlistExtra)
	}
	// 能在宿主机跑样本的模拟器默认禁用。
	if !strings.Contains(strings.Join(cfg.Tools.DefaultDenyBinaries, ","), "wine") {
		t.Fatalf("未禁用宿主机模拟器：%v", cfg.Tools.DefaultDenyBinaries)
	}
	// 默认包不受影响。
	def, err := DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}
	if def.Pack != DefaultPack || def.Spec.ID != "src-authorized-asset-test" {
		t.Fatalf("默认包被污染：pack=%q id=%q", def.Pack, def.Spec.ID)
	}
}

// 源码审计域的差异点：没有网络目标（范围是 local_paths）、默认零出网、代码外发需授权。
func TestPackConfigSourceAudit(t *testing.T) {
	cfg, err := PackConfig("source-audit")
	if err != nil {
		t.Fatalf("加载 source-audit: %v", err)
	}
	if cfg.Spec.ID != "offline-source-audit" {
		t.Fatalf("spec.id=%q", cfg.Spec.ID)
	}
	if len(cfg.Scope.EgressAllowlistExtra) != 0 {
		t.Fatalf("源码审计默认不该有情报回源：%v", cfg.Scope.EgressAllowlistExtra)
	}
	// 能把源码送出去的命令默认禁用。
	deny := strings.Join(cfg.Tools.DefaultDenyBinaries, ",")
	for _, want := range []string{"ssh", "scp", "curl", "wget"} {
		if !strings.Contains(deny, want) {
			t.Fatalf("未禁用外传类命令 %s：%v", want, cfg.Tools.DefaultDenyBinaries)
		}
	}
}

// 端到端：源码审计模板用 local_paths 作授权范围（没有域名），能装上且判定生效。
func TestInstallSourceAuditPack(t *testing.T) {
	raw, err := os.ReadFile("source-audit/deployment-context.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	text := strings.ReplaceAll(string(raw), "2026-11-20T00:00:00+08:00",
		now.Add(-24*time.Hour).Format("2006-01-02T15:04:05-07:00"))
	text = strings.ReplaceAll(text, "2026-11-27T23:59:59+08:00",
		now.Add(24*time.Hour).Format("2006-01-02T15:04:05-07:00"))
	ctxPath := filepath.Join(t.TempDir(), "context.yaml")
	if err := os.WriteFile(ctxPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := InstallFromFile(ctxPath)
	if err != nil {
		t.Fatalf("按源码审计模板安装: %v", err)
	}
	defer Install(nil)
	if eng.Pack() != "source-audit" {
		t.Fatalf("pack=%q want source-audit", eng.Pack())
	}
	if len(eng.Engagement().Scope.LocalPaths) == 0 {
		t.Fatal("local_paths 没进引擎范围，审计就无从谈授权")
	}
	if d := eng.DecideRequest(context.Background(), "t", req("GET", "unknown.example.net", "/")); d.Action == ActionAllow {
		t.Fatalf("源码审计域不该允许出网，得到 %v(%s)", d.Action, d.Reason)
	}
}

// 分诊包与 binary_re 的分工要在配置里体现：分诊一律不执行样本、预算更紧。
func TestPackConfigMalwareTriage(t *testing.T) {
	cfg, err := PackConfig("malware-triage")
	if err != nil {
		t.Fatalf("加载 malware-triage: %v", err)
	}
	if cfg.Spec.ID != "offline-malware-triage" {
		t.Fatalf("spec.id=%q", cfg.Spec.ID)
	}
	if cfg.Budget.TotalRequestsPerTask >= 200 {
		t.Fatalf("分诊预算应比深挖更紧，得到 %v", cfg.Budget.TotalRequestsPerTask)
	}
	if !strings.Contains(strings.Join(cfg.Tools.DefaultDenyBinaries, ","), "gdb") {
		t.Fatalf("分诊不该允许调试器：%v", cfg.Tools.DefaultDenyBinaries)
	}
	// 分诊的 R13 是"一律不执行"，而不是 binary_re 的"沙箱外执行"（红线不进 Config 模型，
	// 这里直接核对 yaml 原文，避免"文档说一套、判定跑另一套"）。
	raw, err := os.ReadFile("malware-triage/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "execute_sample_at_all") {
		t.Fatal("R13 应为 execute_sample_at_all：分诊阶段不得执行样本")
	}
}

func TestPackConfigUnknown(t *testing.T) {
	if _, err := PackConfig("no-such-pack"); err == nil {
		t.Fatal("未知域包必须报错，静默回退会让人以为在用另一套策略")
	}
	if _, err := PackLexicon("no-such-pack"); err == nil {
		t.Fatal("未知域包的词表也必须报错")
	}
}

// 端到端：按离线域模板装引擎，判定语义应跟着包走（只放行情报源，其它出网拒绝）。
func TestInstallFromFileSelectsPack(t *testing.T) {
	// 模板里的授权窗口是示例日期，用例把窗口改到"现在前后"，否则判定会因不在窗内而拒绝，
	// 测出来的就不是域包选择而是时间窗。
	raw, err := os.ReadFile("binary-re/deployment-context.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	text := strings.ReplaceAll(string(raw), "2026-11-20T00:00:00+08:00",
		now.Add(-24*time.Hour).Format("2006-01-02T15:04:05-07:00"))
	text = strings.ReplaceAll(text, "2026-11-27T23:59:59+08:00",
		now.Add(24*time.Hour).Format("2006-01-02T15:04:05-07:00"))
	ctxPath := filepath.Join(t.TempDir(), "context.yaml")
	if err := os.WriteFile(ctxPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := InstallFromFile(ctxPath)
	if err != nil {
		t.Fatalf("按离线域模板安装: %v", err)
	}
	defer Install(nil)
	if eng.Pack() != "binary-re" {
		t.Fatalf("pack=%q want binary-re", eng.Pack())
	}
	ctx := context.Background()
	if d := eng.DecideRequest(ctx, "t", req("GET", "www.virustotal.com", "/api/v3/files/x")); d.Action != ActionAllow {
		t.Fatalf("情报源只读查询应放行，得到 %v(%s)", d.Action, d.Reason)
	}
	// 模板没声明的地址：离线域一样按越界拒绝（红线 R1）。
	if d := eng.DecideRequest(ctx, "t", req("GET", "unknown.example.net", "/")); d.Action == ActionAllow {
		t.Fatalf("未声明地址不应放行，得到 %v(%s)", d.Action, d.Reason)
	}
}
