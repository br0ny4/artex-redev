package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 是 policy.yaml 的解析结果。只建模判定实际用到的字段；yaml 解码默认忽略
// 未知字段，因此 policy.yaml 里仍保留给人看的说明性键（注释）。
type Config struct {
	Spec        Spec              `yaml:"spec"`
	Enforcement Enforcement       `yaml:"enforcement"`
	Scope       ScopeConfig       `yaml:"scope"`
	Classes     map[string]string `yaml:"classes"`
	Semantics   SemanticsConfig   `yaml:"semantics"`
	Budget      BudgetConfig      `yaml:"budget"`
	Tools       ToolsConfig       `yaml:"tools"`
	Response    ResponseConfig    `yaml:"response"`
	Stop        StopConfig        `yaml:"stop"`
	Report      ReportConfig      `yaml:"report"`
	Compliance  ComplianceConfig  `yaml:"compliance"`

	// Requirements 声明该域包对部署上下文的必填项。在线测试域要求测试账号兜住
	// C/D/E 类操作；离线分析域不碰目标账号体系，强填只会逼使用者造假账号。
	Requirements EngagementRequirements `yaml:"engagement_requirements"`

	// Pack 是策略来源的域包名（web-pentest / binary-re ...），由 PackConfig 填入，
	// 不参与 yaml 解码；用于状态展示与审计标注"这批判定用的是哪套域策略"。
	Pack string `yaml:"-"`
}

// EngagementRequirements 是"部署上下文填什么才算完整"的域包声明。
// 未写字段按在线域（最严）处理：漏声明不该把校验放松。
type EngagementRequirements struct {
	TestAccounts bool `yaml:"test_accounts"`
}

type Spec struct {
	ID        string `yaml:"id"`
	Version   string `yaml:"version"`
	Handshake string `yaml:"handshake"`
	FailMode  string `yaml:"fail_mode"` // closed | open
}

type Enforcement struct {
	Mode        string      `yaml:"mode"` // hard | warn
	Layers      []string    `yaml:"layers"`
	OnViolation OnViolation `yaml:"on_violation"`
}

type OnViolation struct {
	Action   string `yaml:"action"`
	HoldTask bool   `yaml:"hold_task"`
	Notify   string `yaml:"notify"`
}

type ScopeConfig struct {
	RequireDeploymentContext bool           `yaml:"require_deployment_context"`
	DenyByDefault            bool           `yaml:"deny_by_default"`
	AmbiguousAsOutOfScope    bool           `yaml:"ambiguous_as_out_of_scope"`
	ThirdPartyDetect         ThirdParty     `yaml:"third_party_detect"`
	InternalCIDRsDeny        []string       `yaml:"internal_cidrs_deny"`
	MetadataDeny             []string       `yaml:"metadata_deny"`
	OutOfBandAllowSuffixes   []string       `yaml:"out_of_band_allow_suffixes"`
	EgressAllowlistExtra     []string       `yaml:"egress_allowlist_extra"`
	BudgetExpansion          map[string]any `yaml:"budget_expansion"`
}

type ThirdParty struct {
	CNAMESuffix     []string `yaml:"cname_suffix"`
	ASNLookup       bool     `yaml:"asn_lookup"`
	RequireExplicit bool     `yaml:"require_explicit"`
}

type SemanticsConfig struct {
	MatchSurface           []string    `yaml:"match_surface"`
	ApplyOrder             []string    `yaml:"apply_order"`
	ObfuscationIsViolation bool        `yaml:"obfuscation_is_violation"`
	LLMFallback            LLMFallback `yaml:"llm_fallback"`
}

// LLMFallback 只用于给操作员解释"为什么判不清"，默认不参与放行（判定见 doc 04 §11）。
type LLMFallback struct {
	Enabled                bool   `yaml:"enabled"`
	DefaultOnLowConfidence string `yaml:"default_on_low_confidence"`
	LogDecision            bool   `yaml:"log_decision"`
}

type BudgetConfig struct {
	SQLProof             string  `yaml:"sql_proof"`
	VulnSamples          float64 `yaml:"vuln_samples"`
	InternalLateralHosts float64 `yaml:"internal_lateral_hosts"`
	SendActions          float64 `yaml:"send_actions"`
	PIIActiveFetch       float64 `yaml:"pii_active_fetch"`
	ResponseBodyMaxMB    float64 `yaml:"response_body_max_mb"`
	TestAccounts         float64 `yaml:"test_accounts"`
	RateRPSPerHost       float64 `yaml:"rate_rps_per_host"`
	ConcurrencyPerHost   float64 `yaml:"concurrency_per_host"`
	RetryMax             float64 `yaml:"retry_max"`
	TotalRequestsPerTask float64 `yaml:"total_requests_per_task"`
	ScannerBurstMax      float64 `yaml:"scanner_burst_max"`
	Window               string  `yaml:"window"`
	StopAtExpiry         bool    `yaml:"stop_at_expiry"`
}

type ToolsConfig struct {
	DefaultDenyBinaries    []string       `yaml:"default_deny_binaries"`
	Approval               map[string]any `yaml:"approval"`
	NoSelfTuning           []string       `yaml:"no_self_tuning"`
	NoProbeFirst           bool           `yaml:"no_probe_first"`
	ScriptRequiresCounters bool           `yaml:"script_requires_counters"`
	Attribution            string         `yaml:"attribution"`
}

type ResponseConfig struct {
	MaxBodyMB            float64     `yaml:"max_body_mb"`
	StopOnSecretPatterns bool        `yaml:"stop_on_secret_patterns"`
	SecretPatternsRef    string      `yaml:"secret_patterns_ref"`
	RowCounting          RowCounting `yaml:"row_counting"`
	PIIDetector          PIIDetector `yaml:"pii_detector"`
}

type RowCounting struct {
	PreferTotalFields bool `yaml:"prefer_total_fields"`
	SampleRowsMax     int  `yaml:"sample_rows_max"`
}

type PIIDetector struct {
	Enabled        bool `yaml:"enabled"`
	MinHitsToCount int  `yaml:"min_hits_to_count"`
}

type StopConfig struct {
	ImmediateOn          []string       `yaml:"immediate_on"`
	StopAll              bool           `yaml:"stop_all"`
	KeepContextForReport bool           `yaml:"keep_context_for_report"`
	ResumeRequires       string         `yaml:"resume_requires"`
	AmbiguousAnswer      string         `yaml:"ambiguous_answer"`
	AnomalyDetect        map[string]any `yaml:"anomaly_detect"`
}

type ReportConfig struct {
	RequiredFields      []string `yaml:"required_fields"`
	Redact              []string `yaml:"redact"`
	OneFindingOneReport bool     `yaml:"one_finding_one_report"`
	Rating              string   `yaml:"rating"`
	ArtifactsDir        string   `yaml:"artifacts_dir"`
	PurgeAfterReport    bool     `yaml:"purge_after_report"`
}

type ComplianceConfig struct {
	HandshakeRequired             bool   `yaml:"handshake_required"`
	DeploymentContextRequired     bool   `yaml:"deployment_context_required"`
	PassiveOnlyWhenContextMissing bool   `yaml:"passive_only_when_context_missing"`
	SpecVersionPinned             string `yaml:"spec_version_pinned"`
	StrictInterpretation          bool   `yaml:"strict_interpretation"`
}

// ---------------------------------------------------------------------
// 部署上下文（规范 9.2）—— engagement 的机器可读块
// ---------------------------------------------------------------------

// Engagement 是一次授权测试的完整上下文。缺任一必填项 → ErrContextIncomplete，
// 任务只能做被动分析（规范 9.2）。
// Engagement 的 json tag 只为 /api/policy/status 的展示服务；授权文件仍然只读 yaml。
type Engagement struct {
	ID         string         `yaml:"id" json:"id"`
	Client     string         `yaml:"client" json:"client"`
	Title      string         `yaml:"title" json:"title"`
	AuthDoc    string         `yaml:"authorization_doc" json:"authorization_doc"`
	AuthSHA    string         `yaml:"authorization_doc_sha256" json:"authorization_doc_sha256"`
	Window     Window         `yaml:"window" json:"window"`
	Contacts   Contacts       `yaml:"contacts" json:"contacts"`
	Scope      EngScope       `yaml:"scope" json:"scope"`
	Accounts   []Account      `yaml:"test_accounts" json:"test_accounts"`
	Tools      EngTools       `yaml:"allowed_tools" json:"allowed_tools"`
	Report     EngReport      `yaml:"report" json:"report"`
	Artifacts  Artifacts      `yaml:"artifacts" json:"artifacts"`
	Overrides  map[string]any `yaml:"budget_overrides" json:"budget_overrides"`
	Compliance EngCompliance  `yaml:"compliance" json:"compliance"`

	// Pack 显式声明本次作业使用的域包；为空时用默认包（web-pentest）。
	// 离线域（binary-re）与在线域的红线不同，混用会让判定语义错位，所以必须能标出来。
	Pack string `yaml:"pack" json:"pack,omitempty"`
}

type Window struct {
	StartsAt string `yaml:"starts_at" json:"starts_at"`
	EndsAt   string `yaml:"ends_at" json:"ends_at"`
	Timezone string `yaml:"timezone" json:"timezone"`
}

type Contacts struct {
	Operator      string `yaml:"operator"`
	ClientPOC     string `yaml:"client_poc"`
	ReportChannel string `yaml:"report_channel"`
}

type EngScope struct {
	Domains []string `yaml:"domains" json:"domains"`
	IPs     []string `yaml:"ips" json:"ips"`
	CIDRs   []string `yaml:"cidrs" json:"cidrs"`
	Apps    []string `yaml:"apps" json:"apps"`
	APIs    []string `yaml:"apis" json:"apis"`
	Notes   string   `yaml:"notes" json:"notes"`
	Exclude []string `yaml:"exclude" json:"exclude"`
	Egress  []string `yaml:"allowed_egress" json:"allowed_egress"`
}

type Account struct {
	ID           string       `yaml:"id"`
	Username     string       `yaml:"username"`
	Role         string       `yaml:"role"`
	BoundContact BoundContact `yaml:"bound_contact"`
}

type BoundContact struct {
	Phone string `yaml:"phone"`
	Email string `yaml:"email"`
}

type EngTools struct {
	Always []string `yaml:"always"`
	PerUse []string `yaml:"per_use"`
	Denied []string `yaml:"denied"`
}

type EngReport struct {
	Channel            string   `yaml:"channel"`
	Format             string   `yaml:"format"`
	AttachmentsAllowed []string `yaml:"attachments_allowed"`
}

type Artifacts struct {
	Dir              string `yaml:"dir"`
	MaxTotalMB       int    `yaml:"max_total_mb"`
	PurgeAfterReport bool   `yaml:"purge_after_report"`
	PurgeGraceDays   int    `yaml:"purge_grace_days"`
}

type EngCompliance struct {
	SpecVersion          string `yaml:"spec_version"`
	Handshake            string `yaml:"handshake"`
	OperatorAcknowledged bool   `yaml:"operator_acknowledged"`
}

// ErrContextIncomplete 表示部署上下文缺项：只允许被动分析，不得发包。
var ErrContextIncomplete = errors.New("部署上下文不完整：只允许被动分析，不得发包（规范 9.2）")

var reHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LoadEngagement 解析 deployment-context YAML 并做必填校验。
// LoadEngagement 解析部署上下文。
//
// 支持两种写法，因为规范文档给的模板与"引擎直接读"的形态不一样：
//  1. 规范模板（deployment-context.example.yaml）：engagement 包住身份信息，
//     scope / test_accounts / allowed_tools / report / artifacts / compliance 在顶层；
//  2. 扁平写法：所有字段直接挂在顶层（便于脚本生成）。
//
// 之前这里只认扁平写法，导致照着模板填的部署上下文永远装不上引擎——策略静默失效，
// 而使用者以为已经在保护范围内。两端必须能直接对上，模板改引擎不改是不可接受的。
func LoadEngagement(raw []byte) (*Engagement, error) {
	var doc struct {
		Engagement      *Engagement    `yaml:"engagement"`
		Scope           *EngScope      `yaml:"scope"`
		TestAccounts    []Account      `yaml:"test_accounts"`
		AllowedTools    *EngTools      `yaml:"allowed_tools"`
		Report          *EngReport     `yaml:"report"`
		Artifacts       *Artifacts     `yaml:"artifacts"`
		BudgetOverrides map[string]any `yaml:"budget_overrides"`
		Compliance      *EngCompliance `yaml:"compliance"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析部署上下文: %w", err)
	}
	var e Engagement
	if doc.Engagement != nil {
		e = *doc.Engagement
		if doc.Scope != nil {
			e.Scope = *doc.Scope
		}
		if len(doc.TestAccounts) > 0 {
			e.Accounts = doc.TestAccounts
		}
		if doc.AllowedTools != nil {
			e.Tools = *doc.AllowedTools
		}
		if doc.Report != nil {
			e.Report = *doc.Report
		}
		if doc.Artifacts != nil {
			e.Artifacts = *doc.Artifacts
		}
		if len(doc.BudgetOverrides) > 0 {
			e.Overrides = doc.BudgetOverrides
		}
		if doc.Compliance != nil {
			e.Compliance = *doc.Compliance
		}
	} else {
		// 扁平写法（旧行为）。
		if err := yaml.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("解析部署上下文: %w", err)
		}
	}
	// 按部署上下文声明的域包取必填项；未知包名在这里就报错（而不是启动后静默用默认包）。
	packCfg, err := PackConfig(e.Pack)
	if err != nil {
		return nil, err
	}
	if err := e.validate(packCfg.Requirements); err != nil {
		return nil, err
	}
	return &e, nil
}

// Validate 检查规范 9.2 的必填项。缺项返回 ErrContextIncomplete（不是致命错误：
// 任务降级为被动分析）。
func (e *Engagement) Validate() error {
	return e.validate(EngagementRequirements{TestAccounts: true})
}

// validate 按域包声明的必填项校验。
func (e *Engagement) validate(req EngagementRequirements) error {
	var missing []string
	if strings.TrimSpace(e.Client) == "" {
		missing = append(missing, "engagement.client")
	}
	if !reHex64.MatchString(strings.ToLower(strings.TrimSpace(e.AuthSHA))) {
		missing = append(missing, "engagement.authorization_doc_sha256（须为 64 位 hex）")
	}
	if _, err := e.Start(); err != nil {
		missing = append(missing, "engagement.window.starts_at")
	}
	if _, err := e.End(); err != nil {
		missing = append(missing, "engagement.window.ends_at")
	}
	if len(e.Scope.Domains)+len(e.Scope.IPs)+len(e.Scope.CIDRs)+len(e.Scope.Apps)+len(e.Scope.APIs) == 0 {
		missing = append(missing, "scope（至少一项 domain/ip/cidr/app/api）")
	}
	if len(e.Accounts) == 0 && req.TestAccounts {
		missing = append(missing, "test_accounts（C/D/E 类操作需要）")
	}
	if strings.TrimSpace(e.Report.Channel) == "" {
		missing = append(missing, "report.channel")
	}
	if strings.TrimSpace(e.Artifacts.Dir) == "" {
		missing = append(missing, "artifacts.dir")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w：缺少 %s", ErrContextIncomplete, strings.Join(missing, ", "))
	}
	return nil
}

// Start / End 解析授权时间窗（RFC3339）。
func (e *Engagement) Start() (time.Time, error) { return time.Parse(time.RFC3339, e.Window.StartsAt) }
func (e *Engagement) End() (time.Time, error)   { return time.Parse(time.RFC3339, e.Window.EndsAt) }

// InWindow 判断 now 是否在授权时间窗内（规范 1.x / 3.x）。
func (e *Engagement) InWindow(now time.Time) bool {
	st, err1 := e.Start()
	en, err2 := e.End()
	if err1 != nil || err2 != nil {
		return false
	}
	return !now.Before(st) && !now.After(en)
}

// SHA256Hex 计算规范正文摘要，用于「提示词与判定同源」的自检与报告附录。
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
