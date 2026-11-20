// Package vulngate 是 0day 发现的**准入门**：判定一条 finding 是否有资格被当作
// 结论提交（导出报告 / 发给客户 / 提到 SRC）。
//
// 为什么单独成包、且不依赖 LLM：这两个门解决的是"结论可不可信"，靠模型在提示词里
// 自我声明"我做了反例验证/我查过没撞车"等于没有约束——它完全可以在没跑任何验证的
// 情况下把这两句话写进报告。所以门只认**结构化、逐条可核对**的记录：
//
//	门一（反例验证）：每条候选漏洞至少 5 条**反例**（阴性对照）——换个不该触发的
//	  输入/环境/不影响条件，漏洞必须不出现。5 条不能是同一个手法的 5 个副本，必须
//	  覆盖不同误报路径（不同变体、不同权限、不同路径），否则等于只测了一次。
//
//	门二（撞车比对）：提交前用全网可检索的信息比对，至少 3 次查询、覆盖 2 类以上
//	  信息源（CVE 库 / 厂商公告 / 代码托管 / 漏洞库检索）。任何一次查询命中"同一
//	  漏洞"即判定撞车，直接阻断——重复的 0day 是负资产（浪费客户时间、损害报告
//	  可信度、还可能被当成抄袭）。
//
//	门三（触发验证）：**无 PoC 不算 finding**。必须有一条可复制粘贴的触发输入、
//	  观察到的结果、以及至少 2 次连续复现（一次可能是巧合/缓存/偶发状态）。
//
// 本包只做纯判定（无 IO、无 DB），便于单测与复用：handler 负责落库，评估只回答
// "这批记录够不够格"。
package vulngate

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	// MinCounterexamples 是门一的下限。低于 5 条视为"只测了一次"，不足以排除误报。
	MinCounterexamples = 5
	// MinNoveltyQueries 是门二的下限（不同查询去重后）。
	MinNoveltyQueries = 3
	// MinSourceClasses 是门二要求覆盖的信息源类别下限。
	MinSourceClasses = 2
	// MinReproductions 是门三要求的连续复现次数下限。一次成功可能是巧合：缓存、
	// 上游偶发、时序、上一次请求的残留状态都能伪造出"漏洞"。
	MinReproductions = 2
)

// Counterexample 是一条反例（阴性对照）：用"不该触发漏洞"的条件去验证，确认漏洞
// 确实没有出现，从而排除该误报路径。
type Counterexample struct {
	ID       int64  `json:"id,omitempty"`
	Ordinal  int    `json:"ordinal"`
	Claim    string `json:"claim"`    // 这条反例要排除的误报路径（越具体越好）
	Method   string `json:"method"`   // 验证手法：变体输入/降级条件/对照环境
	Expected string `json:"expected"` // 反例成立时应观察到的正常行为
	Observed string `json:"observed"` // 实际观察到的结果（与 Expected 对照）
	Passed   bool   `json:"passed"`   // 反例成立（漏洞未出现）→ true
	Evidence string `json:"evidence"` // 流量 id / 命令输出摘要等可核对凭据
	// TrafficIDs 是凭据里引用的真实流量 id。判定逻辑不校验它（离线域没有流量），
	// 但录入接口会核对存在性——"编一个 id"过不了服务端。
	TrafficIDs []string `json:"traffic_ids,omitempty"`
}

// NoveltyCheck 是一次撞车比对查询。
type NoveltyCheck struct {
	ID          int64    `json:"id,omitempty"`
	Query       string   `json:"query"`
	SourceClass string   `json:"source_class"` // cve|vendor|github|advisory|search|other
	Hits        []string `json:"hits"`         // 命中的标题/链接（便于人工复核）
	SameVuln    bool     `json:"same_vuln"`    // 命中已被公开的同一致命漏洞 → 撞车
	// Origin 标记这条检索记录是谁产生的：manual（人/agent 手工登记）或 platform
	// （平台代执行，真的请求了公开漏洞库并落下了返回条目）。人工记录声明"我查过"，
	// 平台记录证明"查过、结果是这样"。
	Origin string `json:"origin,omitempty"`
	// ReviewedBy / ReviewedAt / ReviewNote 是复核留痕：平台代检只证明"查到了这些
	// 条目"，是否属于"同一个漏洞"必须由人看过命中条目后判定——机器猜错两个方向都
	// 危险（把无关 CVE 当撞车=放弃真 0day；把同一漏洞当无关=重复提交）。
	// 未复核的平台代检记录不计入门二（见 Assess），复核结论落库可审计。
	ReviewedBy string     `json:"reviewed_by,omitempty"`
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
	ReviewNote string     `json:"review_note,omitempty"`
}

// Poc 是门三要求的触发验证记录：可复制粘贴的输入 + 观察到的结果 + 复现次数。
//
// ExpectStatus / ExpectBodyContains 是**机器可判的预期**：只有填了它们，平台才能
// 代执行重放并自动判定"这次到底复现没有"。手写的 Expected 是给人看的，不能拿来自
// 动判定——那是又一次"模型自己说通过"。
type Poc struct {
	Kind               string   `json:"kind"`                           // http|command|file|sample 等触发方式
	Input              string   `json:"input"`                          // 复现步骤：完整请求/命令/文件路径（要能直接照做）
	Expected           string   `json:"expected"`                       // 预期（漏洞存在的表现，给人看）
	Observed           string   `json:"observed"`                       // 实际观察到的结果
	Reproduced         int      `json:"reproduced"`                     // 连续复现成功次数
	Evidence           string   `json:"evidence"`                       // 流量 id / 命令输出摘要
	ExpectStatus       int      `json:"expect_status,omitempty"`        // 重放判定用：期望的响应状态码
	ExpectBodyContains []string `json:"expect_body_contains,omitempty"` // 重放判定用：响应体必须包含的片段
}

// Assessment 是一条 finding 当前积累的全部门记录。
type Assessment struct {
	Counterexamples []Counterexample
	Novelty         []NoveltyCheck
	Poc             *Poc
	// PocReplays / PocReplayMatched 是平台代执行重放的次数（总次数 / 与预期一致的次数）。
	// 它们不参与"挡不挡"的判定，但决定 Verdict 里那条 note：结论到底是机器跑出来的，
	// 还是人写上去的。
	PocReplays       int
	PocReplayMatched int
}

// Verdict 是门的结论。State 只有两种：passed / blocked。
type Verdict struct {
	State                 string   `json:"state"`
	Reasons               []string `json:"reasons"`
	PassedCounterexamples int      `json:"passed_counterexamples"`
	FailedCounterexamples int      `json:"failed_counterexamples"`
	DistinctVectors       int      `json:"distinct_vectors"`
	NoveltyQueries        int      `json:"novelty_queries"`
	SourceClasses         int      `json:"source_classes"`
	PocReproductions      int      `json:"poc_reproductions"`
	PocReplays            int      `json:"poc_replays"`
	PocReplayMatched      int      `json:"poc_replay_matched"`
	NoveltyPlatform       int      `json:"novelty_platform"`
	// NoveltyUnreviewed 是"平台代检有命中但还没有人复核"的记录数；>0 时门二阻断。
	NoveltyUnreviewed int `json:"novelty_unreviewed"`
	// Notes 是不阻断放行、但操作员必须看到的提示（例如"触发验证未经平台重放"）。
	Notes []string `json:"notes,omitempty"`
}

// Passed 报告是否放行。
func (v Verdict) Passed() bool { return v.State == StatePassed }

const (
	StatePassed  = "passed"
	StateBlocked = "blocked"
)

// Assess 按两道门评估。reasons 逐条说明为什么被挡，且**不区分顺序**地列出所有问题，
// 让人一次就能补齐，而不是被挡一次补一条。
func Assess(a Assessment) Verdict {
	v := Verdict{State: StatePassed}
	vectors := map[string]bool{}
	for _, c := range a.Counterexamples {
		if c.Passed {
			v.PassedCounterexamples++
		} else {
			v.FailedCounterexamples++
		}
		if key := vectorKey(c); key != "" {
			vectors[key] = true
		}
		switch {
		case strings.TrimSpace(c.Claim) == "":
			v.blockf("第 %d 条反例缺少 claim（要排除哪条误报路径）", c.Ordinal)
		case strings.TrimSpace(c.Method) == "":
			v.blockf("第 %d 条反例缺少 method（怎么验证的）", c.Ordinal)
		case strings.TrimSpace(c.Expected) == "":
			v.blockf("第 %d 条反例缺少 expected（正常情况下应观察到什么）", c.Ordinal)
		case strings.TrimSpace(c.Observed) == "":
			v.blockf("第 %d 条反例缺少 observed（实际观察到什么）", c.Ordinal)
		case strings.TrimSpace(c.Evidence) == "":
			v.blockf("第 %d 条反例缺少 evidence（可核对凭据：流量 id / 命令输出）", c.Ordinal)
		}
	}
	v.DistinctVectors = len(vectors)
	if v.PassedCounterexamples < MinCounterexamples {
		v.blockf("反例验证不足：需至少 %d 条通过的反例，当前 %d 条", MinCounterexamples, v.PassedCounterexamples)
	}
	if v.FailedCounterexamples > 0 {
		v.blockf("有 %d 条反例未通过（漏洞在反例条件下仍出现）：要么降级为误报，要么补充证据说明差异", v.FailedCounterexamples)
	}
	if v.DistinctVectors < MinCounterexamples {
		v.blockf("反例重复：不同误报路径只有 %d 条，需要 %d 条以上的不同变体/条件", v.DistinctVectors, MinCounterexamples)
	}

	queries := map[string]bool{}
	classes := map[string]bool{}
	platformProbes := 0
	unreviewed := 0
	for _, n := range a.Novelty {
		if norm(n.Origin) == "platform" {
			platformProbes++
			// 有命中的平台代检必须人看过：机器给的是"候选公开漏洞列表"，
			// 不是"没撞车"的结论。
			if len(n.Hits) > 0 && strings.TrimSpace(n.ReviewedBy) == "" {
				unreviewed++
			}
		}
		if q := norm(n.Query); q != "" {
			queries[q] = true
		}
		if sc := norm(n.SourceClass); sc != "" {
			classes[sc] = true
		}
		if n.SameVuln {
			// 带上命中条目：操作员要能直接去看那条公开漏洞，而不是只被告知"撞了"。
			if len(n.Hits) > 0 {
				v.blockf("撞车：查询 %q 已命中公开的同一致命漏洞（%s），重复提交是负资产",
					n.Query, strings.Join(n.Hits, " / "))
			} else {
				v.blockf("撞车：查询 %q 已命中公开的同一致命漏洞，重复提交是负资产", n.Query)
			}
		}
		if norm(n.Query) == "" {
			v.blockf("撞车比对存在空查询：每次检索要记录实际使用的关键词")
		}
	}
	v.NoveltyQueries = len(queries)
	v.SourceClasses = len(classes)
	v.NoveltyPlatform = platformProbes
	v.NoveltyUnreviewed = unreviewed
	if unreviewed > 0 {
		v.blockf("平台代检记录尚未复核（%d 条）：机器只负责\"查到什么\"，是否同一个漏洞要人看过命中条目并留下复核人与依据——在「准入」页逐条标记\"无同一漏洞\"或\"撞车\"", unreviewed)
	}
	if v.NoveltyQueries < MinNoveltyQueries {
		v.blockf("撞车比对不足：需至少 %d 次不同检索，当前 %d 次", MinNoveltyQueries, v.NoveltyQueries)
	}
	if v.SourceClasses < MinSourceClasses {
		v.blockf("撞车比对覆盖面不足：需覆盖至少 %d 类信息源（CVE 库/厂商公告/代码托管/漏洞库检索），当前 %d 类", MinSourceClasses, v.SourceClasses)
	}
	// 平台代执行检索会把真实返回条目落库；只靠人工登记的"我查过"没法核实。
	// 不阻断（离线域/内网检索不到公网），但必须让操作员看到这条证据的成色。
	if v.NoveltyQueries > 0 {
		if platformProbes == 0 {
			v.note("撞车比对目前只有人工/agent 登记的记录，未经平台代执行检索；建议在「准入」页用「平台代检」跑一次（NVD / CISA KEV），由平台真实请求并落下命中条目")
		} else if unreviewed == 0 {
			v.note("撞车比对已由平台代执行 %d 次检索，命中条目均已人工复核（复核人/时间/依据已落库）", platformProbes)
		} else {
			v.note("撞车比对已由平台代执行 %d 次检索，其中 %d 条命中待人工复核", platformProbes, unreviewed)
		}
	}

	// 门三：触发验证（无 PoC 不算 finding）。
	if a.Poc == nil {
		v.blockf("触发验证缺失：没有 PoC 不算 finding——需记录触发方式、可复制粘贴的输入、实际观察结果与至少 %d 次连续复现", MinReproductions)
	} else {
		v.PocReproductions = a.Poc.Reproduced
		switch {
		case strings.TrimSpace(a.Poc.Kind) == "":
			v.blockf("触发验证缺少 kind（触发方式：http/command/file/sample）")
		case strings.TrimSpace(a.Poc.Input) == "":
			v.blockf("触发验证缺少 input（别人要能照着你写的步骤复现）")
		case strings.TrimSpace(a.Poc.Observed) == "":
			v.blockf("触发验证缺少 observed（实际观察到什么才算命中）")
		case strings.TrimSpace(a.Poc.Evidence) == "":
			v.blockf("触发验证缺少 evidence（流量 id / 命令输出摘要）")
		}
		if a.Poc.Reproduced < MinReproductions {
			v.blockf("复现次数不足：需连续成功 %d 次，当前 %d 次（一次成功可能是缓存/偶发状态）", MinReproductions, a.Poc.Reproduced)
		}
		v.PocReplays = a.PocReplays
		v.PocReplayMatched = a.PocReplayMatched
		if a.Poc.Reproduced >= MinReproductions {
			// 复现次数够了，但"谁跑出来的"决定这条证据的可信度：平台代执行重放会
			// 经过 L3 判定并落真实流量，人工录入则只是一个数字。不阻断，但必须让
			// 操作员看到区别——报告里"已复现"三个字的含金量不该靠猜。
			if a.PocReplayMatched > 0 {
				v.note("平台重放已验证：%d 次重放与预期一致（共 %d 次尝试）", a.PocReplayMatched, a.PocReplays)
			} else {
				v.note("触发验证目前只有人工/agent 录入的证据，未经平台重放；建议在「准入」页点一次「重放」，由平台真实发包并回填流量证据")
			}
			if a.PocReplays > a.PocReplayMatched {
				v.note("有 %d 次平台重放与预期不符，请确认是环境波动还是 PoC 本身不稳定", a.PocReplays-a.PocReplayMatched)
			}
		}
	}

	if len(v.Reasons) == 0 {
		v.State = StatePassed
		v.Reasons = nil
	} else {
		v.State = StateBlocked
	}
	return v
}

func (v *Verdict) blockf(format string, args ...any) {
	v.Reasons = append(v.Reasons, fmt.Sprintf(format, args...))
}

// note 记录一条不阻断的提示（操作员需要知道、但不该因此挡住导出）。
func (v *Verdict) note(format string, args ...any) {
	v.Notes = append(v.Notes, fmt.Sprintf(format, args...))
}

// vectorKey 归一化一条反例的"手法 + 误报路径"，用来识别 5 个副本伪装成 5 条反例。
func vectorKey(c Counterexample) string {
	k := norm(c.Method) + "|" + norm(c.Claim)
	if norm(c.Method) == "" || norm(c.Claim) == "" {
		return ""
	}
	return k
}

// norm 做保守归一化：小写、去空白与常见标点，避免"变了大小写就算不同"。
func norm(s string) string {
	var b strings.Builder
	prevSpace := false
	for _, r := range strings.ToLower(s) {
		if unicode.IsSpace(r) || unicode.IsPunct(r) {
			if !prevSpace {
				b.WriteRune(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}

// SourceClasses 返回规范化的信息源类别集合（供 handler 校验白名单）。
func SourceClasses(checks []NoveltyCheck) []string {
	set := map[string]bool{}
	for _, c := range checks {
		if sc := norm(c.SourceClass); sc != "" {
			set[sc] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
