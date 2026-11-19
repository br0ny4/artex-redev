package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Lexicon 是第四章语义词表的解析结果。词表按【业务后果】归类，而非穷举；
// 词表外的动词按后果归入最近类别，归不进 → unknown → 按禁止处理。
type Lexicon struct {
	Normalize struct {
		Lowercase  bool     `yaml:"lowercase"`
		StripSep   string   `yaml:"strip_separators"`
		SplitCamel bool     `yaml:"split_camel"`
		DecodeURL  bool     `yaml:"decode_url_encoding"`
		ParseBody  []string `yaml:"parse_body"`
	} `yaml:"normalize"`

	RestMethodClass map[string]string `yaml:"rest_method_class"`

	A map[string]any `yaml:"A"`
	B map[string]any `yaml:"B"`
	C map[string]any `yaml:"C"`
	D map[string]any `yaml:"D"`
	E map[string]any `yaml:"E"`
	F map[string]any `yaml:"F"`

	ParamSwitches struct {
		MethodOverride    []string `yaml:"method_override"`
		ActionKeys        []string `yaml:"action_keys"`
		DestructiveValues []string `yaml:"destructive_values"`
		OverwriteValues   []string `yaml:"overwrite_values"`
		BatchPatterns     []string `yaml:"batch_patterns"`
	} `yaml:"param_switches"`

	RCEExecAllowlist []string `yaml:"rce_exec_allowlist"`
	RCEExecDenylist  []string `yaml:"rce_exec_denylist"`

	// 由 BuildIndex 派生，不参与 YAML 解码。
	classOf     map[string]string // 归一化 token → class
	highRisk    map[string]bool   // D 类高危子类（资金/权益/公域）→ 红线 R9
	actionKeys  map[string]bool
	destructive map[string]bool
	overwrite   map[string]bool
	rceAllow    map[string]bool
	rceDeny     map[string]bool
	methodCls   map[string]string
}

// classRank 越小越严重。unknown 视为最严重之外的"禁止"。
var classRank = map[string]int{"A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5, "unknown": 6}

// Rank 返回类别严重度序号（用于"取最严重"）。
func Rank(class string) int {
	if r, ok := classRank[class]; ok {
		return r
	}
	return classRank["unknown"]
}

// NewLexicon 解析词表并建立索引。
func NewLexicon(lx *Lexicon) (*Lexicon, error) {
	if lx == nil {
		var err error
		if lx, err = DefaultLexicon(); err != nil {
			return nil, err
		}
	}
	lx.classOf = map[string]string{}
	lx.highRisk = map[string]bool{}
	for _, entry := range []struct {
		class string
		m     map[string]any
	}{{"A", lx.A}, {"B", lx.B}, {"C", lx.C}, {"D", lx.D}, {"E", lx.E}, {"F", lx.F}} {
		verbs, high := collectVerbs(entry.m)
		for _, v := range verbs {
			n := normToken(v)
			if n == "" {
				continue
			}
			if cur, ok := lx.classOf[n]; !ok || Rank(entry.class) < Rank(cur) {
				lx.classOf[n] = entry.class
			}
		}
		if entry.class == "D" {
			// D 类高危子类（资金/权益/公域）既是 D 类动作，也直接触发红线 R9。
			for _, v := range high {
				n := normToken(v)
				if n == "" {
					continue
				}
				if cur, ok := lx.classOf[n]; !ok || Rank(entry.class) < Rank(cur) {
					lx.classOf[n] = entry.class
				}
				lx.highRisk[n] = true
			}
		}
	}
	lx.actionKeys = tokens(lx.ParamSwitches.ActionKeys)
	lx.destructive = tokens(lx.ParamSwitches.DestructiveValues)
	lx.overwrite = tokens(lx.ParamSwitches.OverwriteValues)
	lx.rceAllow = tokens(lx.RCEExecAllowlist)
	lx.rceDeny = tokens(lx.RCEExecDenylist)
	lx.methodCls = map[string]string{}
	for k, v := range lx.RestMethodClass {
		lx.methodCls[strings.ToUpper(k)] = v
	}
	return lx, nil
}

// collectVerbs 递归收集词表里的动词；跳过 conditions（那是条件声明，不是动词），
// D 类的 high_risk_redline 单独返回（它表示"直接红线"而不是受限动作）。
func collectVerbs(m map[string]any) (verbs []string, highRisk []string) {
	if m == nil {
		return nil, nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 稳定顺序，便于测试复现
	for _, k := range keys {
		if k == "conditions" {
			continue
		}
		if k == "high_risk_redline" {
			highRisk = append(highRisk, toStringSlice(m[k])...)
			continue
		}
		switch v := m[k].(type) {
		case []any:
			verbs = append(verbs, toStringSlice(v)...)
		case []string:
			verbs = append(verbs, v...)
		case string:
			verbs = append(verbs, v)
		case map[string]any:
			sub, high := collectVerbs(v)
			verbs = append(verbs, sub...)
			highRisk = append(highRisk, high...)
		}
	}
	return verbs, highRisk
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		return []string{t}
	}
	return nil
}

func tokens(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[normToken(s)] = true
	}
	return m
}

// normToken 归一化：小写、去分隔符。delete_user / del-user / DELUSER → deleteuser。
func normToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	repl := strings.NewReplacer("_", "", "-", "", ".", "", " ", "", "\t", "")
	return repl.Replace(s)
}

// splitWords 把一个字符串切成词：先按非字母数字切，再拆 camelCase。
// userDelete → [user delete]；delete_user → [delete user]。
func splitWords(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	runes := []rune(s)
	for i, r := range runes {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r > 127:
			// camelCase 边界：小写/数字后接大写 → 切
			if i > 0 && r >= 'A' && r <= 'Z' {
				prev := runes[i-1]
				if prev >= 'a' && prev <= 'z' || prev >= '0' && prev <= '9' {
					flush()
				}
			}
			cur.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return out
}

// matchWord 判断一个词属于哪个类别。规则（避免误报）：
//   - 归一化后整词精确命中；
//   - 长度 ≥4 的 token 允许前缀/后缀命中（userDelete → delete 后缀）；
//   - 长度 ≤3 的 token（del/rm/set）只允许整词命中，避免 /delivery 命中 /del。
func (lx *Lexicon) matchWord(word string) (class, token string, highRisk bool) {
	w := normToken(word)
	if w == "" {
		return "", "", false
	}
	if c, ok := lx.classOf[w]; ok {
		return c, w, lx.highRisk[w]
	}
	best := ""
	bestTok := ""
	for tok, c := range lx.classOf {
		if len(tok) < 4 || len(tok) >= len(w) {
			continue
		}
		if !strings.HasPrefix(w, tok) && !strings.HasSuffix(w, tok) {
			continue
		}
		if best == "" || Rank(c) < Rank(best) {
			best, bestTok = c, tok
		}
	}
	if best != "" {
		return best, bestTok, false
	}
	return "", "", false
}

// CheckBatch 判断词是否为批量形态（*All / batch* / *ByIds）。命中 A 类动词时升级为 A。
func (lx *Lexicon) CheckBatch(word string) (bool, string) {
	w := normToken(word)
	for _, p := range lx.ParamSwitches.BatchPatterns {
		p = normToken(p)
		switch {
		case strings.HasPrefix(p, "*") && strings.HasSuffix(p, "*"):
			mid := strings.Trim(p, "*")
			if strings.Contains(w, mid) {
				return true, p
			}
		case strings.HasPrefix(p, "*"):
			if strings.HasSuffix(w, strings.TrimPrefix(p, "*")) {
				return true, p
			}
		case strings.HasSuffix(p, "*"):
			if strings.HasPrefix(w, strings.TrimSuffix(p, "*")) {
				return true, p
			}
		}
	}
	return false, ""
}

// dumpClass 用于调试/测试：返回类别 → 归一化 token 列表。
func (lx *Lexicon) dumpClass(class string) []string {
	var out []string
	for tok, c := range lx.classOf {
		if c == class {
			out = append(out, tok)
		}
	}
	sort.Strings(out)
	return out
}

func (lx *Lexicon) String() string {
	return fmt.Sprintf("lexicon(tokens=%d)", len(lx.classOf))
}
