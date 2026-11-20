package server

// 0day 准入门的端到端：反例不足挡、撞车挡、两门都齐才放行，以及导出被门拦下时
// 的 409/force 行为。

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFindingGateBlocksUntilBothGatesSatisfied(t *testing.T) {
	_, f, req := trafficEvidenceServer(t)
	fid := f.FindingID

	// 初始：什么都不做 → blocked，且同时报出两道门的问题。
	w := req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), "")
	if w.Code != 200 {
		t.Fatalf("GET gate: %d %s", w.Code, w.Body)
	}
	var g struct {
		Gate struct {
			State   string   `json:"state"`
			Reasons []string `json:"reasons"`
		} `json:"gate"`
		Requirements map[string]any `json:"requirements"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	if g.Gate.State != "blocked" || len(g.Gate.Reasons) < 2 {
		t.Fatalf("空记录应 blocked 且报两道门：%+v", g.Gate)
	}

	// 4 条反例：仍 blocked（少于 5 条）。
	for i := 1; i <= 4; i++ {
		body := fmt.Sprintf(`{"claim":"误报路径%d","method":"变体手法%d","expected":"200 无副作用","observed":"200 无副作用","passed":true,"evidence":"traffic:%d"}`, i, i, i)
		if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/counterexamples", fid), body); w.Code != 200 {
			t.Fatalf("POST counterexample: %d %s", w.Code, w.Body)
		}
	}
	w = req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), "")
	_ = json.Unmarshal(w.Body.Bytes(), &g)
	if g.Gate.State != "blocked" {
		t.Fatal("4 条反例不该放行")
	}
	if !strings.Contains(strings.Join(g.Gate.Reasons, "; "), "反例验证不足") {
		t.Fatalf("原因应说明反例不足：%v", g.Gate.Reasons)
	}

	// 第 5 条（但复制第 1 条手法 → 仍是不同路径不足）。
	dup := `{"claim":"误报路径1","method":"变体手法1","expected":"200 无副作用","observed":"200 无副作用","passed":true,"evidence":"traffic:9"}`
	if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/counterexamples", fid), dup); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w = req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), "")
	_ = json.Unmarshal(w.Body.Bytes(), &g)
	if !strings.Contains(strings.Join(g.Gate.Reasons, "; "), "反例重复") {
		t.Fatalf("同一手法副本应报反例重复：%v", g.Gate.Reasons)
	}

	// 换个真实不同的第 5 条 → 门一过。
	fifth := `{"claim":"误报路径5","method":"权限降级对照","expected":"匿名访问返回 401","observed":"匿名访问返回 401","passed":true,"evidence":"traffic:5"}`
	if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/counterexamples", fid), fifth); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w = req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), "")
	_ = json.Unmarshal(w.Body.Bytes(), &g)
	if g.Gate.State != "blocked" || !strings.Contains(strings.Join(g.Gate.Reasons, "; "), "撞车比对不足") {
		t.Fatalf("门一过后应只剩撞车门挡着：%v", g.Gate.Reasons)
	}

	// 撞车：同一漏洞已公开 → 立刻 blocked，且原因带编号。
	collide := `{"query":"示例产品 RCE","source_class":"cve","hits":["CVE-2026-99999"],"same_vuln":true}`
	if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty", fid), collide); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w = req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), "")
	_ = json.Unmarshal(w.Body.Bytes(), &g)
	if g.Gate.State != "blocked" || !strings.Contains(strings.Join(g.Gate.Reasons, "; "), "CVE-2026-99999") {
		t.Fatalf("撞车应阻断并带编号：%v", g.Gate.Reasons)
	}
	// 导出此时必须 409，且列出被挡 finding。
	w = req("GET", fmt.Sprintf("/api/exploration/findings/export?format=md-single&scope=selected&ids=%d", fid), "")
	if w.Code != 409 {
		t.Fatalf("未过门导出应 409：%d %s", w.Code, w.Body)
	}
	var blocked struct {
		Blocked []struct {
			FindingID string   `json:"finding_id"`
			Reasons   []string `json:"reasons"`
		} `json:"blocked"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &blocked); err != nil {
		t.Fatal(err)
	}
	// finding_id 用了 `json:"finding_id,string"`：解码到字符串再比。
	if len(blocked.Blocked) != 1 || blocked.Blocked[0].FindingID == "" || len(blocked.Blocked[0].Reasons) == 0 {
		t.Fatalf("409 应列出被挡 finding 与原因：%+v", blocked)
	}

	// force 必须带 reason。
	if w := req("GET", fmt.Sprintf("/api/exploration/findings/export?format=md-single&scope=selected&ids=%d&force=1", fid), ""); w.Code != 400 {
		t.Fatalf("force 无 reason 应 400：%d", w.Code)
	}
}

func TestFindingGatePassesAndAllowsExport(t *testing.T) {
	_, f, req := trafficEvidenceServer(t)
	fid := f.FindingID
	for i := 1; i <= 5; i++ {
		body := fmt.Sprintf(`{"claim":"误报路径%d","method":"变体手法%d","expected":"200 无副作用","observed":"200 无副作用","passed":true,"evidence":"traffic:%d"}`, i, i, i)
		if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/counterexamples", fid), body); w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
	for _, c := range []struct{ q, sc string }{
		{"产品版本 RCE", "cve"}, {"厂商安全公告", "vendor"}, {"github issue 检索", "github"},
	} {
		body := fmt.Sprintf(`{"query":%q,"source_class":%q,"hits":[],"same_vuln":false}`, c.q, c.sc)
		if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty", fid), body); w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
	w := req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), "")
	var g struct {
		Gate struct {
			State                 string `json:"state"`
			PassedCounterexamples int    `json:"passed_counterexamples"`
			NoveltyQueries        int    `json:"novelty_queries"`
			SourceClasses         int    `json:"source_classes"`
		} `json:"gate"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	if g.Gate.State != "passed" || g.Gate.PassedCounterexamples != 5 || g.Gate.NoveltyQueries != 3 || g.Gate.SourceClasses != 3 {
		t.Fatalf("两门齐应 passed：%+v", g.Gate)
	}
	w = req("GET", fmt.Sprintf("/api/exploration/findings/export?format=md-single&scope=selected&ids=%d", fid), "")
	if w.Code != 200 {
		t.Fatalf("过门后导出应 200：%d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "Evidence API") {
		t.Fatalf("导出内容应含 finding 标题：%s", w.Body.String()[:200])
	}
}

func TestFindingCounterexampleRejectsMissingFields(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	_ = s
	w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/counterexamples", f.FindingID), `{"claim":"x"}`)
	if w.Code != 400 {
		t.Fatalf("缺字段应 400：%d %s", w.Code, w.Body)
	}
	for _, m := range []string{"method", "expected", "observed", "evidence"} {
		if !strings.Contains(w.Body.String(), m) {
			t.Fatalf("400 应逐个列出缺的字段，缺 %s：%s", m, w.Body)
		}
	}
}

func TestFindingNoveltyRejectsUnknownSourceClass(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	_ = s
	body := fmt.Sprintf(`{"query":"x","source_class":"%s"}`, "weibo")
	w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty", f.FindingID), body)
	if w.Code != 400 {
		t.Fatalf("未知信息源类别应 400：%d %s", w.Code, w.Body)
	}
}

var _ = httptest.NewRecorder
