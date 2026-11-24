package server

// PoC 平台重放的 HTTP 端到端：带机器可判预期的 PoC 经平台重放后，复现次数由机器
// 累加、observed/evidence 被真实重放结果回填；不一致的重放不计数也不覆盖人工证据。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/br0ny4/artex-redev/vulngate"
)

// stubPocReplay 把真实发包替换成固定结果，返回调用计数。
func stubPocReplay(t *testing.T, status int, body, trafficID, denied string) *int {
	t.Helper()
	n := 0
	prev := pocReplayExecutor
	pocReplayExecutor = func(ctx context.Context, m *Manager, req *vulngate.ReplayRequest) (*vulngate.ReplayResult, error) {
		n++
		return &vulngate.ReplayResult{Status: status, Body: body, TrafficID: trafficID, Denied: denied, Detail: "stub 重放"}, nil
	}
	t.Cleanup(func() { pocReplayExecutor = prev })
	return &n
}

// gateView 是测试里对 gate 响应的最小解码。
type gateView struct {
	Gate struct {
		State             string   `json:"state"`
		Reasons           []string `json:"reasons"`
		Notes             []string `json:"notes"`
		PocReproductions  int      `json:"poc_reproductions"`
		PocReplays        int      `json:"poc_replays"`
		PocReplayMatched  int      `json:"poc_replay_matched"`
		NoveltyPlatform   int      `json:"novelty_platform"`
		NoveltyUnreviewed int      `json:"novelty_unreviewed"`
	} `json:"gate"`
	Poc struct {
		Kind               string   `json:"kind"`
		Observed           string   `json:"observed"`
		Evidence           string   `json:"evidence"`
		Reproduced         int      `json:"reproduced"`
		ExpectStatus       int      `json:"expect_status"`
		ExpectBodyContains []string `json:"expect_body_contains"`
	} `json:"poc"`
	PocReplays []struct {
		TrafficID  string `json:"traffic_id"`
		StatusCode int    `json:"status_code"`
		Matched    bool   `json:"matched"`
		Detail     string `json:"detail"`
	} `json:"poc_replays"`
	Candidates []struct {
		ID           int64  `json:"id"`
		Title        string `json:"title"`
		Reachability string `json:"reachability"`
	} `json:"candidates"`
	Novelty []struct {
		ID          int64    `json:"id"`
		Query       string   `json:"query"`
		SourceClass string   `json:"source_class"`
		Origin      string   `json:"origin"`
		Hits        []string `json:"hits"`
		SameVuln    bool     `json:"same_vuln"`
		ReviewedBy  string   `json:"reviewed_by"`
		ReviewedAt  string   `json:"reviewed_at"`
		ReviewNote  string   `json:"review_note"`
	} `json:"novelty_checks"`
}

// Checks 返回撞车比对记录（门二的记录在 gate 响应的 novelty_checks 里）。
func (g gateView) Checks() []struct {
	ID          int64    `json:"id"`
	Query       string   `json:"query"`
	SourceClass string   `json:"source_class"`
	Origin      string   `json:"origin"`
	Hits        []string `json:"hits"`
	SameVuln    bool     `json:"same_vuln"`
	ReviewedBy  string   `json:"reviewed_by"`
	ReviewedAt  string   `json:"reviewed_at"`
	ReviewNote  string   `json:"review_note"`
} {
	return g.Novelty
}

func decodeGate(t *testing.T, w *httptest.ResponseRecorder) gateView {
	t.Helper()
	var g gateView
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatalf("解析 gate 响应失败: %v（%s）", err, w.Body)
	}
	return g
}

// setTrafficOnForTest 打开录制标记：重放要求经过录制代理，这里只测日志与回填，
// 真实代理路径由 traffic 包的 L3 端到端用例覆盖。
func setTrafficOnForTest(t *testing.T, s *Server) {
	t.Helper()
	s.m.mu.Lock()
	s.m.trafficOn = true
	s.m.mu.Unlock()
}

func TestFindingPocReplayBackfillsMachineEvidence(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	fid := f.FindingID
	setTrafficOnForTest(t, s)

	pocBody := fmt.Sprintf(`{"kind":"http","input":"GET /api/user/list HTTP/1.1\nHost: in-scope.example.com\n\n",` +
		`"expected":"返回全部用户","observed":"人工观察到 200 和用户列表","reproduced":0,` +
		`"evidence":"traffic:manual-1","expect_status":200,"expect_body_contains":["admin"]}`)
	if w := req("PUT", fmt.Sprintf("/api/exploration/findings/%d/gate/poc", fid), pocBody); w.Code != 200 {
		t.Fatalf("PUT poc: %d %s", w.Code, w.Body)
	}

	stub := stubPocReplay(t, 200, "welcome admin", "t-replay-1", "")

	// 第一次重放：一致 → 复现次数由机器抬到 1，证据换成真实流量。
	w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/poc/replay", fid), "")
	if w.Code != 200 {
		t.Fatalf("第一次重放: %d %s", w.Code, w.Body)
	}
	var out struct {
		Matched    bool     `json:"matched"`
		Mismatches []string `json:"mismatches"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Matched || len(out.Mismatches) != 0 {
		t.Fatalf("应判定一致：%+v", out)
	}
	g := decodeGate(t, req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), ""))
	if g.Gate.PocReproductions != 1 || g.Poc.Reproduced != 1 {
		t.Fatalf("第一次一致重放后复现次数应为 1：gate=%+v poc=%+v", g.Gate, g.Poc)
	}
	if !strings.Contains(g.Poc.Evidence, "t-replay-1") || !strings.Contains(g.Poc.Observed, "平台重放") {
		t.Fatalf("应回填机器证据：evidence=%q observed=%q", g.Poc.Evidence, g.Poc.Observed)
	}
	if g.Gate.PocReplays != 1 || g.Gate.PocReplayMatched != 1 {
		t.Fatalf("重放统计不符：%+v", g.Gate)
	}
	if len(g.PocReplays) != 1 || !g.PocReplays[0].Matched || g.PocReplays[0].TrafficID != "t-replay-1" {
		t.Fatalf("重放历史不符：%+v", g.PocReplays)
	}

	// 第二次重放 → 复现次数 2，触发验证这条不再挡。
	w = req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/poc/replay", fid), "")
	if w.Code != 200 {
		t.Fatalf("第二次重放: %d %s", w.Code, w.Body)
	}
	g = decodeGate(t, req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), ""))
	if g.Gate.PocReproductions != 2 || *stub != 2 {
		t.Fatalf("两次一致重放后复现次数应为 2、调用次数 2：gate=%+v calls=%d", g.Gate, *stub)
	}
	reasons := strings.Join(g.Gate.Reasons, "; ")
	if strings.Contains(reasons, "复现次数不足") || strings.Contains(reasons, "触发验证缺失") {
		t.Fatalf("重放两次后不该再报触发验证问题：%s", reasons)
	}
	// 门一/门二还没做，所以整体仍是 blocked——这是预期（三道门各自独立）。
	if g.Gate.State != "blocked" {
		t.Fatalf("反例与撞车未做时应仍 blocked：%+v", g.Gate)
	}
	if len(g.Gate.Notes) == 0 || !strings.Contains(strings.Join(g.Gate.Notes, "; "), "平台重放已验证") {
		t.Fatalf("应带一条机器重放通过的 note：%v", g.Gate.Notes)
	}
}

func TestFindingPocReplayMismatchDoesNotCount(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	fid := f.FindingID
	setTrafficOnForTest(t, s)

	// reproduced 先给 2（模拟人工已复现），gate 的触发验证部分是过的。
	pocBody := `{"kind":"http","input":"https://in-scope.example.com/api","expected":"返回 200",` +
		`"observed":"人工复现 2 次","reproduced":2,"evidence":"traffic:manual","expect_status":200}`
	if w := req("PUT", fmt.Sprintf("/api/exploration/findings/%d/gate/poc", fid), pocBody); w.Code != 200 {
		t.Fatalf("PUT poc: %d %s", w.Code, w.Body)
	}
	stubPocReplay(t, 500, "boom", "", "")

	w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/poc/replay", fid), "")
	if w.Code != 200 {
		t.Fatalf("重放: %d %s", w.Code, w.Body)
	}
	var out struct {
		Matched    bool     `json:"matched"`
		Mismatches []string `json:"mismatches"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Matched || len(out.Mismatches) == 0 {
		t.Fatalf("500 与 expect_status=200 不一致，应判不一致：%+v", out)
	}

	g := decodeGate(t, req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), ""))
	if g.Poc.Reproduced != 2 {
		t.Fatalf("不一致的重放不能改复现次数：%+v", g.Poc)
	}
	if strings.Contains(g.Poc.Observed, "平台重放") {
		t.Fatalf("不一致的重放不该覆盖人工 observed：%q", g.Poc.Observed)
	}
	if len(g.PocReplays) != 1 || g.PocReplays[0].Matched || !strings.Contains(g.PocReplays[0].Detail, "不一致") {
		t.Fatalf("应留下一条不一致的重放历史：%+v", g.PocReplays)
	}
	if g.Gate.PocReplays != 1 || g.Gate.PocReplayMatched != 0 {
		t.Fatalf("重放统计不符：%+v", g.Gate)
	}
	if !strings.Contains(strings.Join(g.Gate.Notes, "; "), "未经平台重放") &&
		!strings.Contains(strings.Join(g.Gate.Notes, "; "), "与预期不符") {
		t.Fatalf("应提示重放未通过或未验证：%v", g.Gate.Notes)
	}
}

func TestFindingPocReplayValidation(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	fid := f.FindingID
	setTrafficOnForTest(t, s)

	// 1) 没有 PoC 记录 → 404，提示先录入。
	if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/poc/replay", fid), ""); w.Code != 404 {
		t.Fatalf("无 PoC 时应 404：%d %s", w.Code, w.Body)
	}

	// 2) command 类不许平台代跑 → 400。
	cmd := `{"kind":"command","input":"curl -s https://in-scope.example.com","observed":"手工执行过","reproduced":2,"evidence":"term-1"}`
	if w := req("PUT", fmt.Sprintf("/api/exploration/findings/%d/gate/poc", fid), cmd); w.Code != 200 {
		t.Fatalf("PUT poc: %d %s", w.Code, w.Body)
	}
	if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/poc/replay", fid), ""); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "kind=http") {
		t.Fatalf("command 类应拒绝重放：%d %s", w.Code, w.Body)
	}

	// 3) http 但没有机器可判预期 → 400，说明要补 expect_status。
	noExpect := `{"kind":"http","input":"https://in-scope.example.com/api","observed":"人工观察","reproduced":2,"evidence":"traffic:manual"}`
	if w := req("PUT", fmt.Sprintf("/api/exploration/findings/%d/gate/poc", fid), noExpect); w.Code != 200 {
		t.Fatalf("PUT poc: %d %s", w.Code, w.Body)
	}
	if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/poc/replay", fid), ""); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "expect_status") {
		t.Fatalf("缺 expect_status 应拒绝重放：%d %s", w.Code, w.Body)
	}

	// 4) input 解析不了 → 400 且错误可照着改。
	badInput := `{"kind":"http","input":"这不是一个请求","observed":"人工观察","reproduced":2,"evidence":"traffic:manual","expect_status":200}`
	if w := req("PUT", fmt.Sprintf("/api/exploration/findings/%d/gate/poc", fid), badInput); w.Code != 200 {
		t.Fatalf("PUT poc: %d %s", w.Code, w.Body)
	}
	if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/poc/replay", fid), ""); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "请求行") {
		t.Fatalf("坏 input 应 400 且说明请求行问题：%d %s", w.Code, w.Body)
	}
}
