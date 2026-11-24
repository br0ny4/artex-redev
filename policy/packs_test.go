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
	for _, want := range []string{"web-pentest", "binary-re", "source-audit", "malware-triage", "bounty-recon"} {
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

// 录制代理是运行时资源，不同域包的依赖不同：在线域的 L3 判定发生在代理里，
// 离线域只分析本地产物。这条测试守住"默认在线域必须强制录制"，同时保证离线域
// 不会被迫挂一个用不上的 MITM 代理（否则样本/源码分析先得配代理证书）。
func TestPackRuntimeCaptureRequirement(t *testing.T) {
	cases := map[string]bool{
		"web-pentest":    true,
		"binary-re":      false,
		"source-audit":   false,
		"malware-triage": false,
	}
	for pack, want := range cases {
		cfg, err := PackConfig(pack)
		if err != nil {
			t.Fatalf("加载 %s: %v", pack, err)
		}
		if cfg.Runtime.RequiresTrafficCapture == nil {
			t.Fatalf("%s 必须显式声明 runtime.requires_traffic_capture（漏写会按在线域最严处理：%v）", pack, want)
		}
		if got := *cfg.Runtime.RequiresTrafficCapture; got != want {
			t.Fatalf("%s 的 requires_traffic_capture=%v，want %v", pack, got, want)
		}
		eng, err := New(cfg, nil, nil, NewNetResolver(time.Minute))
		if err != nil {
			t.Fatalf("构造 %s 引擎: %v", pack, err)
		}
		if got := eng.RequiresTrafficCapture(); got != want {
			t.Fatalf("%s 的 Engine.RequiresTrafficCapture()=%v，want %v", pack, got, want)
		}
	}
}

// 未声明的域包必须按最严处理：漏写 runtime 不该把强制录制放松。
func TestEngineDefaultsToRequiringCapture(t *testing.T) {
	cfg := &Config{}
	cfg.Pack = "synthetic"
	eng, err := New(cfg, nil, nil, NewNetResolver(time.Minute))
	if err != nil {
		t.Fatalf("构造引擎: %v", err)
	}
	if !eng.RequiresTrafficCapture() {
		t.Fatal("未声明 runtime.requires_traffic_capture 时应按在线域处理（要求录制代理）")
	}
	var nilEng *Engine
	if nilEng.RequiresTrafficCapture() {
		t.Fatal("未启用引擎时不应要求录制代理")
	}
}

// 在线侦察域与在线测试域共用执行层，但"只看不动"要能在配置里看出来：
// 无测试账号、禁扫描器、情报源只读出网、预算向读倾斜。
func TestPackConfigBountyRecon(t *testing.T) {
	cfg, err := PackConfig("bounty-recon")
	if err != nil {
		t.Fatalf("加载 bounty-recon: %v", err)
	}
	if cfg.Spec.ID != "online-bounty-recon" {
		t.Fatalf("spec.id=%q", cfg.Spec.ID)
	}
	if cfg.Requirements.TestAccounts {
		t.Fatal("侦察域不应要求测试账号：它不做写操作")
	}
	if cfg.Runtime.RequiresTrafficCapture == nil {
		t.Fatal("runtime.requires_traffic_capture 必须显式声明")
	}
	if !*cfg.Runtime.RequiresTrafficCapture {
		t.Fatal("侦察域是在线域：必须有录制代理")
	}
	if cfg.Budget.VulnSamples != 0 || cfg.Budget.SendActions != 0 {
		t.Fatalf("侦察域不该有漏洞验证/外发预算：samples=%v send=%v", cfg.Budget.VulnSamples, cfg.Budget.SendActions)
	}
	joined := strings.Join(cfg.Scope.EgressAllowlistExtra, ",")
	if !strings.Contains(joined, "crt.sh") {
		t.Fatalf("情报源白名单缺失：%v", cfg.Scope.EgressAllowlistExtra)
	}
	if len(cfg.Scope.OutOfBandAllowSuffixes) != 0 {
		t.Fatalf("侦察不触发带外回调，带外域名应为空：%v", cfg.Scope.OutOfBandAllowSuffixes)
	}
	if strings.Contains(strings.Join(cfg.Tools.DefaultDenyBinaries, ","), "zmap") == false {
		t.Fatalf("主动测绘工具应默认禁用：%v", cfg.Tools.DefaultDenyBinaries)
	}
}

// 出网白名单主机是"非测试目标"：只放行只读方法，写动作直接拒。
func TestBountyReconIntelEgressReadOnly(t *testing.T) {
	cfg, err := PackConfig("bounty-recon")
	if err != nil {
		t.Fatal(err)
	}
	lx, err := PackLexicon("bounty-recon")
	if err != nil {
		t.Fatal(err)
	}
	eng := testEngagement(t)
	eng.Accounts = nil // 侦察域没有测试账号
	eng.Scope = EngScope{Domains: []string{"example.com"}}
	e, err := New(cfg, lx, eng, NewNetResolver(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if d := e.DecideRequest(context.Background(), "t", req("GET", "crt.sh", "/?q=%25.example.com")); d.Action != ActionAllow {
		t.Fatalf("情报源只读查询应放行，得到 %v(%s)", d.Action, d.Reason)
	}
	if d := e.DecideRequest(context.Background(), "t", req("POST", "crt.sh", "/api/submit")); d.Action != ActionDeny {
		t.Fatalf("情报源不得写入，得到 %v(%s)", d.Action, d.Reason)
	}
	if d := e.DecideRequest(context.Background(), "t", req("GET", "evil.example.net", "/")); d.Action == ActionAllow {
		t.Fatalf("非白名单外网主机不该放行，得到 %v(%s)", d.Action, d.Reason)
	}
}

// 端到端：按侦察域模板装引擎——通配 scope、无测试账号也能装，pack 切换生效。
func TestInstallBountyReconPack(t *testing.T) {
	raw, err := os.ReadFile("bounty-recon/deployment-context.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	text := strings.ReplaceAll(string(raw), "2026-11-20T00:00:00+08:00",
		now.Add(-24*time.Hour).Format("2006-01-02T15:04:05-07:00"))
	text = strings.ReplaceAll(text, "2026-12-20T23:59:59+08:00",
		now.Add(24*time.Hour).Format("2006-01-02T15:04:05-07:00"))
	ctxPath := filepath.Join(t.TempDir(), "context.yaml")
	if err := os.WriteFile(ctxPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := InstallFromFile(ctxPath)
	if err != nil {
		t.Fatalf("按侦察域模板安装: %v", err)
	}
	defer Install(nil)
	if eng.Pack() != "bounty-recon" {
		t.Fatalf("pack=%q want bounty-recon", eng.Pack())
	}
	if !eng.RequiresTrafficCapture() {
		t.Fatal("侦察域是在线域：L3 判定必须有代理")
	}
	if d := eng.DecideRequest(context.Background(), "t", req("GET", "crt.sh", "/")); d.Action != ActionAllow {
		t.Fatalf("模板装好后情报源应可用，得到 %v(%s)", d.Action, d.Reason)
	}
}
