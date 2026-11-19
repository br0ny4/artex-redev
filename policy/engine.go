package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Action 是判定结果的动作。
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionHold  Action = "hold" // 任务级挂起，等待操作员答复（规范 7.3）
)

// Decision 是一次判定的完整结果，可原样落审计表。
type Decision struct {
	Action   Action
	Rule     string
	Reason   string
	Class    string
	Matched  ClassVerdict // 语义分类细节（判定入库用）
	Evidence []string
}

func allow() Decision { return Decision{Action: ActionAllow} }

// Engine 把配置、词表、范围、预算、特征组合成判定入口。
type Engine struct {
	cfg            *Config
	lex            *Lexicon
	cls            *Classifier
	scope          *Scope
	budget         *Budget
	secretPatterns []secretPattern
	eng            *Engagement
	mode           string // hard | warn

	mu    sync.Mutex
	holds map[string]string // taskKey → 挂起原因（任务级，供测试/未来按任务挂起）

	holdMu sync.Mutex
	hold   *HoldInfo // 全局挂起（Stop-All，规范 7.3）
}

// ErrSpecMismatch 表示 policy.yaml 与部署上下文声明的规范版本不一致。
var ErrSpecMismatch = errors.New("规范版本不一致")

// New 构造引擎。eng 可为 nil（离线域或未配置授权上下文 → 只允许被动分析）。
func New(cfg *Config, lex *Lexicon, eng *Engagement, resolver Resolver) (*Engine, error) {
	if cfg == nil {
		var err error
		if cfg, err = DefaultConfig(); err != nil {
			return nil, err
		}
	}
	if lex == nil {
		var err error
		if lex, err = NewLexicon(nil); err != nil {
			return nil, err
		}
	}
	if eng != nil {
		v := strings.TrimSpace(eng.Compliance.SpecVersion)
		if v != "" && cfg.Spec.Version != "" && v != cfg.Spec.Version {
			return nil, fmt.Errorf("%w：部署上下文声明 %s，平台策略为 %s（规范九章 4）", ErrSpecMismatch, v, cfg.Spec.Version)
		}
	}
	scope, err := NewScope(cfg.Scope, eng, resolver)
	if err != nil {
		return nil, err
	}
	patterns, err := LoadSecretPatterns(SecretPatternsRaw())
	if err != nil {
		return nil, err
	}
	mode := cfg.Enforcement.Mode
	if mode == "" {
		mode = "hard"
	}
	e := &Engine{
		cfg: cfg, lex: lex, cls: NewClassifier(lex, cfg.Semantics),
		scope: scope, budget: NewBudget(cfg.Budget), secretPatterns: patterns,
		eng: eng, mode: mode, holds: map[string]string{},
	}
	e.budget.ApplyOverrides(engOverrides(eng))
	return e, nil
}

func engOverrides(eng *Engagement) map[string]any {
	if eng == nil {
		return nil
	}
	return eng.Overrides
}

// Mode 返回强制模式：hard=拦截，warn=只记录。
func (e *Engine) Mode() string { return e.mode }

// Enforcing 是否为强制模式。
func (e *Engine) Enforcing() bool { return e.mode != "warn" }

// Engagement 返回当前授权上下文（可能为 nil）。
func (e *Engine) Engagement() *Engagement { return e.eng }

// SpecVersion 返回平台锁定执行的规范版本（policy.yaml:spec.version）。
func (e *Engine) SpecVersion() string { return e.cfg.Spec.Version }

// HandshakeToken 返回规范要求的握手串。
func (e *Engine) HandshakeToken() string { return e.cfg.Spec.Handshake }

// Budget 暴露计数器，供调用方做"响应体预算"之类的补充记账。
func (e *Engine) Budget() *Budget { return e.budget }

// Scope 暴露范围判定器。
func (e *Engine) Scope() *Scope { return e.scope }

// Classify 直接暴露语义分类（供报表/调试）。
func (e *Engine) Classify(r Request) ClassVerdict { return e.cls.Classify(r) }

// taskKey 生成计数器作用域。
func (e *Engine) taskKey(task, host string) BudgetKey {
	id := ""
	if e.eng != nil {
		id = e.eng.ID
	}
	return BudgetKey{Engagement: id, Task: task, Host: host}
}

// DecideRequest 是请求出口（L3）的判定入口，顺序即规范章序：
// 时间窗 → 凭据复用 → 范围 → 语义分级 → 预算。任何一步失败即返回 deny/hold。
func (e *Engine) DecideRequest(ctx context.Context, task string, r Request) Decision {
	d := e.decideRequest(ctx, task, r)
	// 只有 deny 在这里记流水账：hold 由 L5 统一记（见 raiseHoldDecision），
	// STOP_ALL 期间不重复记，避免 agent 重试把审计表刷满。
	if d.Action == ActionDeny {
		e.emit(Event{
			TaskID: task, Source: "L3-request", Host: r.Host, Method: r.Method, Path: r.Path,
			Class: d.Class, Action: string(d.Action), Rule: d.Rule, Reason: d.Reason,
			Budget: e.budget.Snapshot(e.taskKey(task, normalizeHost(r.Host))),
		})
	}
	return d
}

func (e *Engine) decideRequest(ctx context.Context, task string, r Request) Decision {
	// -1. 已全局挂起：Stop-All，任何新请求都不放行（规范 7.3）。
	if d := e.stopAllDecision(); d.Action != "" {
		return d
	}

	// 0. 没有部署上下文：规范 9.2 —— 只允许被动分析，不得发包。
	if e.eng == nil {
		return Decision{Action: ActionDeny, Rule: "R0_no_context",
			Reason: "缺少部署上下文（授权范围/测试账号/报告出口等），只允许被动分析，不得发包（规范 9.2）"}
	}

	// 1. 授权时间窗
	if !e.eng.InWindow(time.Now()) {
		return Decision{Action: ActionDeny, Rule: "R0_out_of_window",
			Reason: fmt.Sprintf("当前不在授权时间窗 %s ~ %s 内", e.eng.Window.StartsAt, e.eng.Window.EndsAt)}
	}

	// 2. 凭据复用（红线 10）
	if r.HasHarvestedCredential {
		return Decision{Action: ActionDeny, Rule: "R10_cred_reuse",
			Reason: "禁止使用测试获取的凭据发起任何登录/身份验证请求（规范红线 10、5.5）"}
	}

	// 3. 范围：DNS 解析后再判（内网/元数据/第三方托管）
	v, reason := e.scope.ResolveAndCheck(ctx, r.Host)
	switch v {
	case ScopeAllow:
		// ok
	case ScopeInternal, ScopeMetadata:
		return Decision{Action: ActionDeny, Rule: "R4_internal_lateral", Reason: reason}
	case ScopeAmbiguous:
		return e.raiseHoldDecision("SCOPE_UNCERTAIN", reason,
			"目标归属不明（未列入授权清单/第三方托管/CDN 回源）。是否确认在授权范围内？确认后恢复测试，否则请客户补充授权。", "")
	default:
		return Decision{Action: ActionDeny, Rule: "R1_scope", Reason: reason}
	}

	// 4. 语义分级（第四章）
	sv := e.cls.Classify(r)
	switch sv.Class {
	case ClassA:
		return Decision{Action: ActionDeny, Rule: "R1_destructive", Class: sv.Class, Matched: sv, Reason: "删除/清空/销毁、覆盖/重置/迁移/合并类接口禁止测试（规范红线 1、第四章 A/B）"}
	case ClassB:
		return Decision{Action: ActionDeny, Rule: "R1_destructive", Class: sv.Class, Matched: sv, Reason: "覆盖/重置/迁移/合并类接口禁止测试（规范红线 1、第四章 B）"}
	case ClassDeny:
		return Decision{Action: ActionDeny, Rule: "R_method_forbidden", Class: sv.Class, Reason: "该 HTTP 方法本身不允许（规范第四章）"}
	case ClassC, ClassD, ClassE:
		if !r.AsTestAccount {
			return Decision{Action: ActionDeny, Rule: "R5_not_test_account", Class: sv.Class, Matched: sv,
				Reason: "C/D/E 类操作只能作用于自建测试账号的数据（规范 4.2）"}
		}
		if sv.HighRisk {
			return Decision{Action: ActionDeny, Rule: "R9_money", Class: sv.Class, Matched: sv,
				Reason: "资金/权益/公域发布类动作直接红线（规范红线 9、4.2 D）"}
		}
	case ClassUnknown:
		return e.raiseHoldDecision("SEMANTICS_UNCERTAIN",
			"接口语义判不清（按禁止处理）："+r.Method+" "+r.Path,
			"该接口的业务语义无法归类（可能是新的删除/覆盖写法）。请确认它属于哪一类（A 删除/B 覆盖/C 修改/D 状态/E 新增/F 读取）。", sv.Class)
	}

	// 5. 预算：总量熔断
	bk := e.taskKey(task, normalizeHost(r.Host))
	if ok, used, lim := e.budget.Reserve(bk, "total_requests_per_task", 1); !ok {
		return e.raiseHoldDecision("BUDGET_EXHAUSTED",
			fmt.Sprintf("任务请求总量已达上限 %.0f（已用 %.0f），熔断（规范第三章 1、5.3）", lim, used),
			"预算已耗尽。请确认是否放宽本次 engagement 的请求总量上限，或结束本轮测试。", "")
	}
	return allow()
}

// CheckCommand 是命令出口（L1）的判定入口。返回 deny 时调用方应阻断工具调用。
// 注意：本地沙箱里的破坏性命令不在这里拦（那是操作者自己的机器，由上游 intercept
// 规则处理）；这里拦的是"目标侧 RCE 只读"、"扫描器未审批"、"内联解释器"、
// "读敏感文件" 与 "命令里的目标越界"。
func (e *Engine) CheckCommand(task, cmd string, opt CommandOptions) Decision {
	d := e.checkCommand(task, cmd, opt)
	if d.Action == ActionDeny {
		e.emit(Event{
			TaskID: task, Source: "L1-command", Action: string(d.Action),
			Rule: d.Rule, Reason: d.Reason, Path: truncateCmd(cmd),
		})
	}
	return d
}

// truncateCmd 只保留命令前 200 字节进审计：既够定位，又避免把整段 payload（可能含
// 凭据）写进日志。
func truncateCmd(cmd string) string {
	const max = 200
	if len(cmd) <= max {
		return cmd
	}
	return cmd[:max] + "…"
}

func (e *Engine) checkCommand(task, cmd string, opt CommandOptions) Decision {
	if d := e.stopAllDecision(); d.Action != "" {
		return d
	}
	denyBinaries := map[string]bool{}
	for _, b := range e.cfg.Tools.DefaultDenyBinaries {
		denyBinaries[strings.ToLower(strings.TrimSpace(b))] = true
	}
	v := AnalyzeCommand(cmd, e.lex, denyBinaries, opt)
	if v.Deny {
		return Decision{Action: ActionDeny, Rule: v.Rule, Reason: v.Reason}
	}
	// 命令里出现的网络目标必须都在授权范围内（红线 1.2 / 4）
	if e.eng != nil {
		for _, t := range v.Targets {
			if sv, reason := e.scope.CheckHost(t); sv != ScopeAllow {
				if sv == ScopeAmbiguous && !e.Enforcing() {
					continue
				}
				return Decision{Action: ActionDeny, Rule: "R1_scope",
					Reason: "命令目标 " + t + " 不在授权范围内（" + reason + "）"}
			}
		}
	}
	return allow()
}

// SetHold / Held 实现任务级挂起（规范 7.3：停止是全量的）。
func (e *Engine) SetHold(task, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.holds[task] = reason
}

// Held 返回任务是否处于挂起状态。
func (e *Engine) Held(task string) (bool, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.holds[task]
	return ok, r
}

// ReleaseHold 只在操作员给出明确答复后调用。
func (e *Engine) ReleaseHold(task string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.holds, task)
}

// VerifyHandshake 校验首个模型响应是否以 [RULES_LOADED vX] 开头（规范 9.1）。
// 不匹配即视为未加载规范，调用方应禁用全部工具。
func (e *Engine) VerifyHandshake(firstMessage string) bool {
	want := strings.TrimSpace(e.cfg.Spec.Handshake)
	if want == "" {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(firstMessage), want)
}
