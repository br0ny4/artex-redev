package vulngate

import (
	"strings"
	"testing"
	"time"
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

func okPoc() *Poc {
	return &Poc{Kind: "http", Input: "curl -X POST https://target/api/order -d '{\"id\":1}'",
		Expected: "返回他人订单", Observed: "返回他人订单内容", Reproduced: 3, Evidence: "traffic: 7f3a"}
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
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: okNovelty(3), Poc: okPoc()})
	if !v.Passed() {
		t.Fatalf("应放行，reasons=%v", v.Reasons)
	}
	if v.DistinctVectors != 5 || v.NoveltyQueries != 3 || v.PocReproductions != 3 {
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

func TestAssessBlocksWithoutPoc(t *testing.T) {
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: okNovelty(3)})
	if v.Passed() {
		t.Fatal("没有 PoC 不算 finding")
	}
	if !strings.Contains(strings.Join(v.Reasons, "; "), "触发验证缺失") {
		t.Fatalf("原因应说明缺 PoC：%v", v.Reasons)
	}
}

func TestAssessBlocksOnLowReproductions(t *testing.T) {
	p := okPoc()
	p.Reproduced = 1
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: okNovelty(3), Poc: p})
	if v.Passed() {
		t.Fatal("只复现一次不该放行")
	}
	if !strings.Contains(strings.Join(v.Reasons, "; "), "复现次数不足") {
		t.Fatalf("原因应说明复现不足：%v", v.Reasons)
	}
}

func TestAssessBlocksOnIncompletePoc(t *testing.T) {
	p := okPoc()
	p.Input = ""
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: okNovelty(3), Poc: p})
	if v.Passed() || !strings.Contains(strings.Join(v.Reasons, "; "), "input") {
		t.Fatalf("缺输入应阻断：%v", v.Reasons)
	}
}

func TestVerdictJSONShape(t *testing.T) {
	v := Assess(Assessment{})
	if v.State != StateBlocked {
		t.Fatalf("空记录必须是 blocked，得到 %q", v.State)
	}
	if len(v.Reasons) < 3 {
		t.Fatalf("应同时报出三道门的问题，得到 %v", v.Reasons)
	}
}

// 平台代检只说明"查到了这些条目"，是否同一漏洞必须人复核。未复核就想过门等于
// 让机器替人下结论——这正是准入门要防的"伪证据"。
func TestAssessBlocksUnreviewedPlatformProbe(t *testing.T) {
	nov := append(okNovelty(2),
		NoveltyCheck{Query: "acme widget path traversal", SourceClass: "cve",
			Hits: []string{"CVE-2021-0001 · Acme Widget traversal"}, Origin: "platform"})
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: nov, Poc: okPoc()})
	if v.Passed() {
		t.Fatalf("平台代检命中未复核不该放行，reasons=%v", v.Reasons)
	}
	if v.NoveltyUnreviewed != 1 {
		t.Fatalf("未复核数应为 1，得到 %d", v.NoveltyUnreviewed)
	}
	if !strings.Contains(strings.Join(v.Reasons, "; "), "尚未复核") {
		t.Fatalf("原因没提复核：%v", v.Reasons)
	}
}

// 复核后（无同一漏洞）应放行，并在 notes 里说明复核留痕已落库。
func TestAssessPassesAfterPlatformReview(t *testing.T) {
	reviewed := time.Now()
	nov := append(okNovelty(2),
		NoveltyCheck{Query: "acme widget path traversal", SourceClass: "cve",
			Hits: []string{"CVE-2021-0001 · Acme Widget traversal"}, Origin: "platform",
			ReviewedBy: "alice", ReviewedAt: &reviewed, ReviewNote: "命中是另一个产品线，不构成撞车"})
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: nov, Poc: okPoc()})
	if !v.Passed() {
		t.Fatalf("复核后应放行，reasons=%v", v.Reasons)
	}
	if v.NoveltyUnreviewed != 0 {
		t.Fatalf("复核后未复核数应为 0，得到 %d", v.NoveltyUnreviewed)
	}
	if !strings.Contains(strings.Join(v.Notes, "; "), "已人工复核") {
		t.Fatalf("notes 应说明已复核：%v", v.Notes)
	}
}

// 复核结论是"撞车"时仍然阻断，并把命中条目带出来让人能直接去看。
func TestAssessBlocksOnReviewedDuplicate(t *testing.T) {
	nov := append(okNovelty(2),
		NoveltyCheck{Query: "acme widget rce", SourceClass: "cve",
			Hits: []string{"CVE-2021-0001 · Acme Widget traversal"}, Origin: "platform",
			SameVuln: true, ReviewedBy: "alice", ReviewNote: "同一组件同一触发点"})
	v := Assess(Assessment{Counterexamples: okCounterexamples(5), Novelty: nov, Poc: okPoc()})
	if v.Passed() {
		t.Fatal("复核为撞车时不该放行")
	}
	if !strings.Contains(strings.Join(v.Reasons, "; "), "CVE-2021-0001") {
		t.Fatalf("撞车原因应带命中编号：%v", v.Reasons)
	}
}
