package vulngate

import (
	"strings"
	"testing"
)

func okCounterexamples(n int) []Counterexample {
	out := make([]Counterexample, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, Counterexample{
			Ordinal: i, Claim: "变体路径" + string(rune('A'+i)),
			Method:   "改用只读参数变体" + string(rune('A'+i)),
			Expected: "返回 200 且不产生副作用", Observed: "返回 200，无副作用",
			Passed: true, Evidence: "traffic: 0xdeadbeef",
		})
	}
	return out
}

func okNovelty(n int) []NoveltyCheck {
	classes := []string{"cve", "vendor", "github", "search"}
	out := make([]NoveltyCheck, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, NoveltyCheck{Query: "示例产品 " + string(rune('a'+i)) + " 漏洞", SourceClass: classes[i%len(classes)]})
	}
	return out
}

func TestAssessPassesWhenBothGatesSatisfied(t *testing.T) {
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: okNovelty(3)})
	if !v.Passed() {
		t.Fatalf("应放行，reasons=%v", v.Reasons)
	}
	if v.DistinctVectors != 5 || v.NoveltyQueries != 3 {
		t.Fatalf("统计不对：%+v", v)
	}
}

func TestAssessBlocksWhenCounterexamplesShort(t *testing.T) {
	v := Assess(Assessment{Counterexamples: okCounterexamples(4), Novelty: okNovelty(3)})
	if v.Passed() {
		t.Fatal("只有 4 条反例不该放行")
	}
	if !strings.Contains(strings.Join(v.Reasons, "; "), "反例验证不足") {
		t.Fatalf("原因不对：%v", v.Reasons)
	}
}

func TestAssessBlocksOnDuplicateVectors(t *testing.T) {
	cs := okCounterexamples(5)
	for i := 1; i < len(cs); i++ {
		cs[i].Claim, cs[i].Method = cs[0].Claim, cs[0].Method
	}
	v := Assess(Assessment{Counterexamples: cs, Novelty: okNovelty(3)})
	if v.Passed() {
		t.Fatal("5 条同手法副本不该放行")
	}
	if v.DistinctVectors != 1 {
		t.Fatalf("不同手法数应为 1，得到 %d", v.DistinctVectors)
	}
}

func TestAssessBlocksOnFailedCounterexample(t *testing.T) {
	cs := okCounterexamples(5)
	cs[2].Passed = false
	v := Assess(Assessment{Counterexamples: cs, Novelty: okNovelty(3)})
	if v.Passed() {
		t.Fatal("有反例未通过不该放行")
	}
	if v.FailedCounterexamples != 1 {
		t.Fatalf("失败数应为 1，得到 %d", v.FailedCounterexamples)
	}
}

func TestAssessBlocksOnMissingFields(t *testing.T) {
	cs := okCounterexamples(5)
	cs[0].Evidence = ""
	v := Assess(Assessment{Counterexamples: cs, Novelty: okNovelty(3)})
	if v.Passed() {
		t.Fatal("缺凭据不该放行")
	}
}

func TestAssessBlocksOnCollision(t *testing.T) {
	ns := okNovelty(3)
	ns[1].SameVuln = true
	ns[1].Hits = []string{"CVE-2026-12345"}
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: ns})
	if v.Passed() {
		t.Fatal("撞车必须阻断")
	}
	if !strings.Contains(strings.Join(v.Reasons, "; "), "CVE-2026-12345") {
		t.Fatalf("原因应带上撞车编号：%v", v.Reasons)
	}
}

func TestAssessBlocksWhenSourceClassesTooFew(t *testing.T) {
	ns := []NoveltyCheck{
		{Query: "查询一", SourceClass: "cve"},
		{Query: "查询二", SourceClass: "cve"},
		{Query: "查询三", SourceClass: "cve"},
	}
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: ns})
	if v.Passed() {
		t.Fatal("只查一类信息源不该放行")
	}
	if v.SourceClasses != 1 {
		t.Fatalf("类别数应为 1，得到 %d", v.SourceClasses)
	}
}

func TestAssessDedupsIdenticalQueries(t *testing.T) {
	ns := []NoveltyCheck{
		{Query: "Same  Query", SourceClass: "cve"},
		{Query: "same query", SourceClass: "vendor"},
		{Query: "another", SourceClass: "github"},
	}
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: ns})
	if v.NoveltyQueries != 2 {
		t.Fatalf("大小写/空白不同的同一条检索应去重，得到 %d", v.NoveltyQueries)
	}
}

func TestVerdictJSONShape(t *testing.T) {
	v := Assess(Assessment{})
	if v.State != StateBlocked {
		t.Fatalf("空记录必须是 blocked，得到 %q", v.State)
	}
	if len(v.Reasons) < 2 {
		t.Fatalf("应同时报出两道门的问题，得到 %v", v.Reasons)
	}
}
