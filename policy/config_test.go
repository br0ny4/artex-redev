package policy

import (
	"errors"
	"testing"
	"time"
)

func mustConfig(t *testing.T) *Config {
	t.Helper()
	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}
	return cfg
}

func mustLexicon(t *testing.T) *Lexicon {
	t.Helper()
	lx, err := NewLexicon(nil)
	if err != nil {
		t.Fatalf("NewLexicon: %v", err)
	}
	return lx
}

// testEngagement 构造一个合法的部署上下文：范围 example.com、时间窗覆盖现在。
func testEngagement(t *testing.T) *Engagement {
	t.Helper()
	now := time.Now()
	e := &Engagement{
		ID:      "ENG-TEST",
		Client:  "test-client",
		AuthSHA: SHA256Hex([]byte("authorization-doc")),
		Window: Window{
			StartsAt: now.Add(-1 * time.Hour).Format(time.RFC3339),
			EndsAt:   now.Add(1 * time.Hour).Format(time.RFC3339),
		},
		Scope: EngScope{Domains: []string{"example.com", "*.example.com"}},
		Accounts: []Account{
			{ID: "ta-1", Username: "pentest_a", BoundContact: BoundContact{Phone: "+8613800000000"}},
		},
		Report:    EngReport{Channel: "https://src.example.com/report"},
		Artifacts: Artifacts{Dir: "./artifacts/ENG-TEST"},
		Compliance: EngCompliance{
			SpecVersion: "2.5",
		},
	}
	return e
}

func TestDefaultConfigParses(t *testing.T) {
	cfg := mustConfig(t)
	if cfg.Spec.Version != "2.5" {
		t.Fatalf("spec.version=%q want 2.5", cfg.Spec.Version)
	}
	if cfg.Spec.Handshake != "[RULES_LOADED v2.5]" {
		t.Fatalf("handshake=%q", cfg.Spec.Handshake)
	}
	if cfg.Budget.VulnSamples != 5 {
		t.Fatalf("vuln_samples=%v want 5", cfg.Budget.VulnSamples)
	}
	if cfg.Budget.InternalLateralHosts != 0 {
		t.Fatalf("internal_lateral_hosts=%v want 0", cfg.Budget.InternalLateralHosts)
	}
	if cfg.Budget.ResponseBodyMaxMB != 10 {
		t.Fatalf("response_body_max_mb=%v want 10", cfg.Budget.ResponseBodyMaxMB)
	}
	if len(cfg.Scope.InternalCIDRsDeny) == 0 {
		t.Fatal("internal_cidrs_deny 为空")
	}
	if cfg.Enforcement.Mode == "" {
		t.Fatal("enforcement.mode 为空")
	}
}

func TestLexiconIndex(t *testing.T) {
	lx := mustLexicon(t)
	for _, tc := range []struct{ word, want string }{
		{"delete", "A"}, {"remove", "A"}, {"purge", "A"}, {"truncate", "A"},
		{"overwrite", "B"}, {"reset", "B"}, {"migrate", "B"},
		{"update", "C"}, {"rename", "C"},
		{"cancel", "D"}, {"approve", "D"},
		{"create", "E"}, {"upload", "E"},
		{"get", "F"}, {"list", "F"},
	} {
		got, tok, _ := lx.matchWord(tc.word)
		if got != tc.want {
			t.Errorf("matchWord(%q)=%q(token=%q) want %q", tc.word, got, tok, tc.want)
		}
	}
	// 误报防护：delivery / settings / presets 不能命中 del/set/reset
	for _, w := range []string{"delivery", "settings", "presets", "updatex"} {
		if cls, tok, _ := lx.matchWord(w); cls == "A" || cls == "B" {
			t.Errorf("matchWord(%q) 误命中 %q(token=%q)", w, cls, tok)
		}
	}
}

func TestEngagementValidate(t *testing.T) {
	e := testEngagement(t)
	if err := e.Validate(); err != nil {
		t.Fatalf("合法上下文校验失败: %v", err)
	}
	// 缺范围 → 上下文不完整
	bad := testEngagement(t)
	bad.Scope = EngScope{}
	err := bad.Validate()
	if !errors.Is(err, ErrContextIncomplete) {
		t.Fatalf("缺范围应为 ErrContextIncomplete，得到 %v", err)
	}
	// 缺测试账号
	bad2 := testEngagement(t)
	bad2.Accounts = nil
	if err := bad2.Validate(); !errors.Is(err, ErrContextIncomplete) {
		t.Fatalf("缺测试账号应为 ErrContextIncomplete，得到 %v", err)
	}
	// 授权书哈希格式
	bad3 := testEngagement(t)
	bad3.AuthSHA = "not-a-hash"
	if err := bad3.Validate(); !errors.Is(err, ErrContextIncomplete) {
		t.Fatalf("授权书哈希非法应为 ErrContextIncomplete，得到 %v", err)
	}
}

func TestSpecVersionMismatchRejected(t *testing.T) {
	cfg := mustConfig(t)
	eng := testEngagement(t)
	eng.Compliance.SpecVersion = "2.4"
	if _, err := New(cfg, nil, eng, nil); !errors.Is(err, ErrSpecMismatch) {
		t.Fatalf("版本不一致应拒绝构造，得到 %v", err)
	}
}

func TestHandshake(t *testing.T) {
	cfg := mustConfig(t)
	eng := testEngagement(t)
	e, err := New(cfg, nil, eng, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !e.VerifyHandshake("[RULES_LOADED v2.5] 已加载，开始测试") {
		t.Fatal("合法握手串应通过")
	}
	if e.VerifyHandshake("好的，我来开始渗透测试") {
		t.Fatal("缺少握手串必须判失败（规范 9.1）")
	}
}
