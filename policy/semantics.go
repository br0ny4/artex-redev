package policy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// 请求类别（规范第四章）。ClassDeny 用于 TRACE 之类"方法本身就不允许"的情况。
const (
	ClassA       = "A" // 删除/清空/销毁 —— 禁止
	ClassB       = "B" // 覆盖/重置/迁移/合并 —— 禁止
	ClassC       = "C" // 通用修改 —— 受限
	ClassD       = "D" // 状态流转 —— 受限（高危子类直接红线）
	ClassE       = "E" // 新增/创建 —— 条件
	ClassF       = "F" // 读取/查询 —— 正常
	ClassUnknown = "unknown"
	ClassDeny    = "deny"
)

// Request 是一次待判定的出站请求。字段只取判定需要的部分。
type Request struct {
	Method string
	Host   string
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte

	// 以下由调用方标注，用于红线判定：
	AsTestAccount          bool // 是否使用清单内的自建测试账号
	HasHarvestedCredential bool // 请求是否携带窃取到的凭据（红线 10）
}

// ClassVerdict 是语义分级结果。
type ClassVerdict struct {
	Class    string
	Rule     string
	Matched  string
	HighRisk bool // D 类高危子类（资金/权益/公域）→ 红线 R9
	Evidence []string
}

// Classifier 实现第四章"接口语义分级"。判断对象是业务语义，不是名字。
type Classifier struct {
	lex *Lexicon
	cfg SemanticsConfig
}

// NewClassifier 构造分类器。
func NewClassifier(lex *Lexicon, cfg SemanticsConfig) *Classifier {
	return &Classifier{lex: lex, cfg: cfg}
}

// Classify 按 rest_method → 显式动词 → 参数开关 → 批量形态 的顺序判定。
// 判不清返回 ClassUnknown（调用方按禁止处理，规范 4.1）。
func (c *Classifier) Classify(r Request) ClassVerdict {
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	words, ev := c.collectWords(r)

	// 0. 方法伪装：_method / X-HTTP-Method-Override 覆盖真实方法
	if override := c.methodOverride(r); override != "" {
		method = strings.ToUpper(override)
		words = append(words, override)
		ev = append(ev, "method-override="+override)
	}

	// 1. REST 方法默认语义
	if cls, ok := c.lex.methodCls[method]; ok {
		switch cls {
		case ClassA, ClassB, ClassDeny:
			return ClassVerdict{Class: cls, Rule: "rest_method:" + method, Matched: method, Evidence: ev}
		}
	}

	// 2. 参数开关：action=purge / type=hard_delete / force=true / is_cover=1
	if v := c.paramSwitch(r); v != "" {
		return ClassVerdict{Class: v, Rule: "param_switch", Matched: v, Evidence: ev}
	}

	// 3. 动词扫描：取最严重（A 最严重）的命中
	best := ClassVerdict{Class: "", Rule: "no_match"}
	for _, w := range words {
		cls, tok, high := c.lex.matchWord(w)
		if cls == "" {
			continue
		}
		if best.Class == "" || Rank(cls) < Rank(best.Class) {
			best = ClassVerdict{Class: cls, Rule: "verb:" + tok, Matched: w, HighRisk: high, Evidence: ev}
		}
		if high {
			best.HighRisk = true
		}
	}
	if best.Class != "" {
		// 3b. 批量形态：clearAll / batchRemove 等 → 升级为 A（不因批量/按 ID 降低级别）
		if best.Class != ClassA {
			for _, w := range words {
				if ok, pat := c.lex.CheckBatch(w); ok {
					if base, _, _ := c.lex.matchWord(w); base == ClassA {
						best = ClassVerdict{Class: ClassA, Rule: "batch:" + pat, Matched: w, Evidence: ev}
						break
					}
				}
			}
		}
		return best
	}

	// 4. 方法兜底：读方法 → F；其余 → unknown（按禁止处理）
	if cls, ok := c.lex.methodCls[method]; ok && cls == ClassF {
		return ClassVerdict{Class: ClassF, Rule: "rest_method:" + method, Matched: method, Evidence: ev}
	}
	return ClassVerdict{Class: ClassUnknown, Rule: "unclassified", Evidence: ev}
}

// methodOverride 读取方法伪装参数（4.1）。
func (c *Classifier) methodOverride(r Request) string {
	for _, k := range c.lex.ParamSwitches.MethodOverride {
		nk := normToken(k)
		if r.Query != nil {
			for qk, vs := range r.Query {
				if normToken(qk) == nk && len(vs) > 0 {
					return vs[0]
				}
			}
		}
		if r.Header != nil && r.Header.Get(k) != "" {
			return r.Header.Get(k)
		}
	}
	// body 里的 _method 也认
	if len(r.Body) > 0 {
		var m map[string]any
		if json.Unmarshal(r.Body, &m) == nil {
			for k, v := range m {
				if normToken(k) == "method" {
					if s, ok := v.(string); ok {
						return s
					}
				}
			}
		}
	}
	return ""
}

// paramSwitch 识别"动词换皮成参数值/开关"的写法（规范 4.1）：
//   - action=purge / type=hard_delete / op=rm  → A
//   - force=true / is_cover=1 / overwrite=1    → B
//
// 键与值都做归一化比较，且 1/true/yes/on 视为真。
func (c *Classifier) paramSwitch(r Request) string {
	check := func(key string, val any) string {
		nk := normToken(key)
		vs, truthy := valueString(val)
		nv := normToken(vs)
		if c.lex.actionKeys[nk] || nk == "method" {
			if c.lex.destructive[nv] {
				return ClassA
			}
			if c.lex.overwrite[nv] {
				return ClassB
			}
		}
		// 键本身表达覆盖/破坏语义且取值"为真"
		if c.lex.overwrite[nk] && truthy {
			return ClassB
		}
		if c.lex.destructive[nk] && truthy {
			return ClassA
		}
		return ""
	}
	if r.Query != nil {
		for k, vs := range r.Query {
			for _, v := range vs {
				if cls := check(k, v); cls != "" {
					return cls
				}
			}
		}
	}
	if len(r.Body) > 0 {
		if json.Valid(r.Body) {
			var m map[string]any
			if json.Unmarshal(r.Body, &m) == nil {
				for k, v := range m {
					if cls := check(k, v); cls != "" {
						return cls
					}
				}
			}
		} else if form, err := url.ParseQuery(string(r.Body)); err == nil {
			for k, vs := range form {
				for _, v := range vs {
					if cls := check(k, v); cls != "" {
						return cls
					}
				}
			}
		}
	}
	return ""
}

// valueString 把参数值转成可比字符串，并返回它是否"为真"。
func valueString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		n := normToken(t)
		return t, n == "1" || n == "true" || n == "yes" || n == "on" || n == "y"
	case bool:
		if t {
			return "true", true
		}
		return "false", false
	case float64:
		if t == 1 {
			return "1", true
		}
		return fmt.Sprintf("%v", t), false
	case nil:
		return "", false
	default:
		return fmt.Sprintf("%v", t), false
	}
}

// collectWords 汇总所有判定面（method 不在此列）：路径段、query 键值、body 键值、方法伪装头。
func (c *Classifier) collectWords(r Request) ([]string, []string) {
	seen := map[string]bool{}
	var words, ev []string
	add := func(s, src string) {
		if s == "" {
			return
		}
		if !seen[s] {
			seen[s] = true
			words = append(words, s)
		}
		if len(ev) < 8 {
			ev = append(ev, src+"="+s)
		}
	}
	// 路径（先做一次 URL 解码，/user%2Fdelete 也认）
	p := r.Path
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	for _, w := range splitWords(p) {
		add(w, "path")
	}
	if r.Query != nil {
		keys := make([]string, 0, len(r.Query))
		for k := range r.Query {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, w := range splitWords(k) {
				add(w, "query_key")
			}
			for _, v := range r.Query[k] {
				for _, w := range splitWords(v) {
					add(w, "query_val")
				}
			}
		}
	}
	if len(r.Body) > 0 {
		if json.Valid(r.Body) {
			var v any
			if json.Unmarshal(r.Body, &v) == nil {
				walkJSON(v, func(s string) { add(s, "body") })
			}
		} else if form, err := url.ParseQuery(string(r.Body)); err == nil {
			for k, vs := range form {
				for _, w := range splitWords(k) {
					add(w, "body_key")
				}
				for _, v := range vs {
					for _, w := range splitWords(v) {
						add(w, "body_val")
					}
				}
			}
		}
	}
	return words, ev
}

// walkJSON 递归收集 JSON 的键与字符串值（只取前 512 个，防御超大 body）。
func walkJSON(v any, fn func(string)) {
	n := 0
	var walk func(any)
	walk = func(v any) {
		if n > 512 {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			for k, sub := range t {
				fn(k)
				n++
				walk(sub)
			}
		case []any:
			for _, sub := range t {
				walk(sub)
			}
		case string:
			fn(t)
			n++
		}
	}
	walk(v)
}

// NeesRulesHint 返回分类所用规则数量（供健康检查/诊断使用）。
func (c *Classifier) RulesCount() int { return len(c.lex.classOf) }
