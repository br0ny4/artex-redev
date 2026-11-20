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
// 本包只做纯判定（无 IO、无 DB），便于单测与复用：handler 负责落库，评估只回答
// "这批记录够不够格"。
package vulngate

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

const (
	// MinCounterexamples 是门一的下限。低于 5 条视为"只测了一次"，不足以排除误报。
	MinCounterexamples = 5
	// MinNoveltyQueries 是门二的下限（不同查询去重后）。
	MinNoveltyQueries = 3
	// MinSourceClasses 是门二要求覆盖的信息源类别下限。
	MinSourceClasses = 2
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
}

// NoveltyCheck 是一次撞车比对查询。
type NoveltyCheck struct {
	ID          int64    `json:"id,omitempty"`
	Query       string   `json:"query"`
	SourceClass string   `json:"source_class"` // cve|vendor|github|advisory|search|other
	Hits        []string `json:"hits"`         // 命中的标题/链接（便于人工复核）
	SameVuln    bool     `json:"same_vuln"`    // 命中已被公开的同一致命漏洞 → 撞车
}

// Assessment 是一条 finding 当前积累的全部门记录。
type Assessment struct {
	Counterexamples []Counterexample
	Novelty         []NoveltyCheck
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
	for _, n := range a.Novelty {
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
	if v.NoveltyQueries < MinNoveltyQueries {
		v.blockf("撞车比对不足：需至少 %d 次不同检索，当前 %d 次", MinNoveltyQueries, v.NoveltyQueries)
	}
	if v.SourceClasses < MinSourceClasses {
		v.blockf("撞车比对覆盖面不足：需覆盖至少 %d 类信息源（CVE 库/厂商公告/代码托管/漏洞库检索），当前 %d 类", MinSourceClasses, v.SourceClasses)
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
