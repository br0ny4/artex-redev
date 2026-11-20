package server

// 0day 准入门的 HTTP 接口（门一只认反例记录，门二只认撞车比对记录）。
//
// 为什么不把这两件事塞进 report_finding 的入参：上报时还没验证完是常态。门的设计是
// "候选先记下来，验证够了才允许导出/提交"——所以它是**增量记录 + 导出时判定**，
// 而不是一次性的表单校验。

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/br0ny4/artex-redev/db"
	"github.com/br0ny4/artex-redev/vulngate"
)

// findingGateEnabled 报告门是否启用。默认启用；ARTEX_FINDING_GATE=off 只用于
// 迁移旧数据/特殊流程，导出仍可用 ?force=1&reason= 逐次放行（会记日志）。
func findingGateEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("ARTEX_FINDING_GATE")), "off")
}

// gateRequirements 是给前端/agent 看的"还差什么"的静态说明。
func gateRequirements() map[string]any {
	return map[string]any{
		"min_counterexamples": vulngate.MinCounterexamples,
		"min_novelty_queries": vulngate.MinNoveltyQueries,
		"min_source_classes":  vulngate.MinSourceClasses,
		"min_reproductions":   vulngate.MinReproductions,
		"source_classes":      []string{"cve", "vendor", "github", "advisory", "search", "other"},
	}
}

// getFindingGate 返回该 finding 的全部门记录与当前结论。
func (s *Server) getFindingGate(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	a, err := s.m.pg.FindingGateAssessment(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	replays, err := s.m.pg.ListFindingPocReplays(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"finding_id":      id,
		"gate":            vulngate.Assess(a),
		"counterexamples": a.Counterexamples,
		"novelty_checks":  a.Novelty,
		"poc":             a.Poc,
		"poc_replays":     replays,
		"requirements":    gateRequirements(),
	})
}

type counterexamplePayload struct {
	Ordinal  int    `json:"ordinal"`
	Claim    string `json:"claim"`
	Method   string `json:"method"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Passed   bool   `json:"passed"`
	Evidence string `json:"evidence"`
	// TrafficIDs 是可选的真实流量 id 引用；给了就必须在流量索引里存在。
	TrafficIDs []string `json:"traffic_ids"`
}

// addFindingCounterexample 追加一条反例。缺字段直接 400 并说明缺哪个——
// 让 agent 一次补齐，而不是反复试。
func (s *Server) addFindingCounterexample(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var p counterexamplePayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
		writeErr(w, 400, "解析请求失败: "+err.Error())
		return
	}
	var missing []string
	for _, f := range []struct {
		name string
		val  string
	}{
		{"claim", p.Claim}, {"method", p.Method}, {"expected", p.Expected},
		{"observed", p.Observed}, {"evidence", p.Evidence},
	} {
		if strings.TrimSpace(f.val) == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		writeErr(w, 400, "反例记录缺少字段: "+strings.Join(missing, ", ")+
			"（claim=要排除的误报路径, method=验证手法, expected=正常应观察到什么, observed=实际观察到什么, evidence=流量 id/命令输出）")
		return
	}
	// 凭据核对：允许引用真实流量 id，但引用的必须是真实抓到的流量。这样
	// "随手编一个 id" 过不了录入；离线域不强制（没有流量）。
	trafficIDs := make([]string, 0, len(p.TrafficIDs))
	for _, raw := range p.TrafficIDs {
		tid := strings.TrimSpace(raw)
		if tid == "" {
			continue
		}
		if s.m.traffic == nil {
			writeErr(w, 400, "当前没有可用的流量索引，不能核对反例凭据 traffic id="+tid)
			return
		}
		if _, _, err := s.m.traffic.Get(tid); err != nil {
			writeErr(w, 400, "反例凭据 traffic id="+tid+" 不在流量索引中：凭据必须是真实抓到的流量")
			return
		}
		trafficIDs = append(trafficIDs, tid)
	}
	ce, err := s.m.pg.AddFindingCounterexample(r.Context(), id, vulngate.Counterexample{
		Ordinal: p.Ordinal, Claim: p.Claim, Method: p.Method, Expected: p.Expected,
		Observed: p.Observed, Passed: p.Passed, Evidence: p.Evidence, TrafficIDs: trafficIDs,
	})
	if err != nil {
		if err == db.ErrFindingNotFound {
			writeErr(w, 404, "finding not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	a, err := s.m.pg.FindingGateAssessment(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	v := vulngate.Assess(a)
	writeJSON(w, 200, map[string]any{"counterexample": ce, "gate": v, "requirements": gateRequirements()})
}

// deleteFindingCounterexample 撤回一条反例（写错时用）。
func (s *Server) deleteFindingCounterexample(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	ceID := int64(atoiDefault(r.PathValue("ceid"), 0))
	if id <= 0 || ceID <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	if err := s.m.pg.DeleteFindingCounterexample(r.Context(), id, ceID); err != nil {
		writeErr(w, 404, "counterexample not found")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": ceID})
}

type noveltyPayload struct {
	Query       string   `json:"query"`
	SourceClass string   `json:"source_class"`
	Hits        []string `json:"hits"`
	SameVuln    bool     `json:"same_vuln"`
}

var noveltySourceClasses = map[string]bool{
	"cve": true, "vendor": true, "github": true, "advisory": true, "search": true, "other": true,
}

// addFindingNoveltyCheck 追加一次撞车比对。
func (s *Server) addFindingNoveltyCheck(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var p noveltyPayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
		writeErr(w, 400, "解析请求失败: "+err.Error())
		return
	}
	if strings.TrimSpace(p.Query) == "" {
		writeErr(w, 400, "query 不能为空：要记录实际使用的检索关键词（便于复核）")
		return
	}
	p.SourceClass = strings.ToLower(strings.TrimSpace(p.SourceClass))
	if !noveltySourceClasses[p.SourceClass] {
		writeErr(w, 400, "source_class 取值必须是 cve|vendor|github|advisory|search|other")
		return
	}
	for i, h := range p.Hits {
		p.Hits[i] = strings.TrimSpace(h)
	}
	n, err := s.m.pg.AddFindingNoveltyCheck(r.Context(), id, vulngate.NoveltyCheck{
		Query: p.Query, SourceClass: p.SourceClass, Hits: p.Hits, SameVuln: p.SameVuln,
	})
	if err != nil {
		if err == db.ErrFindingNotFound {
			writeErr(w, 404, "finding not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	a, err := s.m.pg.FindingGateAssessment(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	v := vulngate.Assess(a)
	writeJSON(w, 200, map[string]any{"novelty_check": n, "gate": v, "requirements": gateRequirements()})
}

// deleteFindingNoveltyCheck 撤回一次撞车比对。
func (s *Server) deleteFindingNoveltyCheck(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	nid := int64(atoiDefault(r.PathValue("nid"), 0))
	if id <= 0 || nid <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	if err := s.m.pg.DeleteFindingNoveltyCheck(r.Context(), id, nid); err != nil {
		writeErr(w, 404, "novelty check not found")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": nid})
}

// enforceFindingGate 在导出前判定：有任何一条 finding 未过门就挡住，给出逐条原因。
// force=1 且带 reason 时放行并记日志（迁移旧报告或客户明确要求时的逃生口）。
func (s *Server) enforceFindingGate(w http.ResponseWriter, r *http.Request, fs []*db.DBFinding) bool {
	if !findingGateEnabled() || len(fs) == 0 {
		return true
	}
	ids := make([]int64, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	verdicts, err := s.m.pg.FindingGateVerdicts(r.Context(), ids)
	if err != nil {
		writeErr(w, 500, "评估 0day 准入失败: "+err.Error())
		return false
	}
	blocked := db.GateBlockedSummary(fs, verdicts)
	if len(blocked) == 0 {
		return true
	}
	q := r.URL.Query()
	if q.Get("force") == "1" {
		reason := strings.TrimSpace(q.Get("reason"))
		if reason == "" {
			writeErr(w, 400, "force=1 需要同时给出 reason（说明为什么在未过门的情况仍要导出）")
			return false
		}
		log.Printf("[finding-gate] 强制放行导出：%d 条未过门，reason=%q", len(blocked), reason)
		return true
	}
	writeJSON(w, http.StatusConflict, map[string]any{
		"error": "导出被 0day 准入拦下：每条结论都需要一条可复现的 PoC（≥2 次连续复现）、" +
			"≥5 条反例验证与 ≥3 次跨源撞车比对。补齐后可重试；确需跳过用 force=1&reason=…（会记日志）。",
		"blocked":      blocked,
		"requirements": gateRequirements(),
	})
	return false
}

// strconvInt64 是给 query 参数解析用的小工具（避免 handler 里堆 if）。
func strconvInt64(s string) int64 {
	if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
		return n
	}
	return 0
}

// setFindingPoc 写入/覆盖触发验证记录（门三）。为什么允许覆盖而不是追加：
// "能复现的触发方式"应当是收敛结论；保留历史尝试没有审计价值，反而会让报告出现多份
// 互相矛盾的 PoC。
func (s *Server) setFindingPoc(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var p struct {
		Kind       string `json:"kind"`
		Input      string `json:"input"`
		Expected   string `json:"expected"`
		Observed   string `json:"observed"`
		Reproduced int    `json:"reproduced"`
		Evidence   string `json:"evidence"`
		// ExpectStatus / ExpectBodyContains 是机器可判预期：只有填了它们平台才能
		// 代执行重放并自动判定"这次到底复现没有"。
		ExpectStatus       int      `json:"expect_status"`
		ExpectBodyContains []string `json:"expect_body_contains"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
		writeErr(w, 400, "解析请求失败: "+err.Error())
		return
	}
	var missing []string
	for _, f := range []struct{ name, val string }{
		{"kind", p.Kind}, {"input", p.Input}, {"observed", p.Observed}, {"evidence", p.Evidence},
	} {
		if strings.TrimSpace(f.val) == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		writeErr(w, 400, "触发验证记录缺少字段: "+strings.Join(missing, ", ")+
			"（kind=触发方式, input=可复制粘贴的复现步骤, observed=实际观察结果, evidence=流量 id/命令输出）")
		return
	}
	// 机器可判预期做最基本的清洗：空片段丢掉，状态码只接受 100..599。
	expectContains := make([]string, 0, len(p.ExpectBodyContains))
	for _, frag := range p.ExpectBodyContains {
		if frag = strings.TrimSpace(frag); frag != "" {
			expectContains = append(expectContains, frag)
		}
	}
	if p.ExpectStatus < 0 || p.ExpectStatus > 599 {
		writeErr(w, 400, "expect_status 必须是 100..599 之间的状态码（或 0 表示不判定）")
		return
	}
	poc, err := s.m.pg.UpsertFindingPoc(r.Context(), id, vulngate.Poc{
		Kind: strings.ToLower(strings.TrimSpace(p.Kind)), Input: p.Input, Expected: p.Expected,
		Observed: p.Observed, Reproduced: p.Reproduced, Evidence: p.Evidence,
		ExpectStatus: p.ExpectStatus, ExpectBodyContains: expectContains,
	})
	if err != nil {
		if err == db.ErrFindingNotFound {
			writeErr(w, 404, "finding not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	a, err := s.m.pg.FindingGateAssessment(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"poc": poc, "gate": vulngate.Assess(a), "requirements": gateRequirements()})
}

// deleteFindingPoc 撤回触发验证记录。
func (s *Server) deleteFindingPoc(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	if err := s.m.pg.DeleteFindingPoc(r.Context(), id); err != nil {
		writeErr(w, 404, "poc not found")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true})
}
