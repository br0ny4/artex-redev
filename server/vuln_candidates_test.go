package server

// 0day 流水线阶段 2–3 的接口验收：候选落库、可达性路径的平台侧核对。
// 关键点：agent 自填的证据不算数——流量 id 必须真实存在，源码位置必须在授权目录清单内。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/br0ny4/artex-redev/policy"
	"github.com/br0ny4/artex-redev/vulnpipe"
)

type candidateView struct {
	Candidate struct {
		ID           int64          `json:"id"`
		TaskID       int64          `json:"task_id"`
		FindingID    int64          `json:"finding_id"`
		Title        string         `json:"title"`
		Status       string         `json:"status"`
		Reachability string         `json:"reachability"`
		VerifiedHops int            `json:"verified_hops"`
		Unverified   int            `json:"unverified_hops"`
		Hops         []vulnpipe.Hop `json:"hops"`
	} `json:"candidate"`
}

func decodeCandidate(t *testing.T, w *httptest.ResponseRecorder) candidateView {
	t.Helper()
	if w.Code != 200 && w.Code != 201 {
		t.Fatalf("期望成功，got %d %s", w.Code, w.Body)
	}
	var out candidateView
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析响应失败: %v %s", err, w.Body)
	}
	return out
}

// TestVulnCandidateTrafficHopVerified：在线域候选的每一跳都要对上真实流量 id。
func TestVulnCandidateTrafficHopVerified(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	seedServerEvidenceFlow(t, s, "t-cand-1", []byte("order id=1"))
	task, err := s.m.CreateTask("candidate traffic", "local", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { s.m.pg.DeleteTask(tid) })

	body := fmt.Sprintf(`{"task_id":%d,"title":"订单查询 id 直接拼 SQL","kind":"sink","location":"GET /api/order/detail?id=1","entry":"id 参数","sink":"字符串拼接进 SELECT","hops":[{"ref_kind":"traffic","ref":"t-cand-1","claim":"入口请求"}]}`, tid)
	c := decodeCandidate(t, req("POST", "/api/exploration/candidates", body))
	if c.Candidate.Reachability != vulnpipe.ReachVerified || c.Candidate.VerifiedHops != 1 {
		t.Fatalf("真实流量 id 应核对通过：%+v", c.Candidate)
	}
	if !strings.Contains(c.Candidate.Hops[0].VerifiedDetail, "t-cand-1") {
		t.Fatalf("核对详情应带流量 id：%q", c.Candidate.Hops[0].VerifiedDetail)
	}

	// 编一个不存在的流量 id：这一跳不算核对上，可达性退回 partial。
	w := req("POST", fmt.Sprintf("/api/exploration/candidates/%d/hops", c.Candidate.ID),
		`{"ref_kind":"traffic","ref":"t-编的","claim":"随便补的入口"}`)
	c = decodeCandidate(t, w)
	if c.Candidate.Reachability != vulnpipe.ReachPartial || c.Candidate.Unverified != 1 {
		t.Fatalf("编造流量 id 不应算核对：%+v", c.Candidate)
	}
	if !strings.Contains(c.Candidate.Hops[1].VerifiedDetail, "不在流量索引") {
		t.Fatalf("应说明流量 id 不存在：%q", c.Candidate.Hops[1].VerifiedDetail)
	}

	// 候选转结论：关联 finding 后状态 converted，准入页能看到"结论从哪来"。
	w = req("POST", fmt.Sprintf("/api/exploration/candidates/%d/link", c.Candidate.ID),
		fmt.Sprintf(`{"finding_id":%d}`, f.FindingID))
	c = decodeCandidate(t, w)
	if c.Candidate.Status != "converted" || c.Candidate.FindingID != f.FindingID {
		t.Fatalf("转结论失败：%+v", c.Candidate)
	}
	g := decodeGate(t, req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", f.FindingID), ""))
	if len(g.Candidates) != 1 || g.Candidates[0].ID != c.Candidate.ID {
		t.Fatalf("准入页应带出关联候选：%+v", g.Candidates)
	}

	// 坏输入：缺 location / 非法状态都要 400。
	if w := req("POST", "/api/exploration/candidates", `{"title":"没有位置"}`); w.Code != 400 || !strings.Contains(w.Body.String(), "location") {
		t.Fatalf("缺 location 应 400：%d %s", w.Code, w.Body)
	}
	if w := req("POST", fmt.Sprintf("/api/exploration/candidates/%d/status", c.Candidate.ID), `{"status":"bogus"}`); w.Code != 400 {
		t.Fatalf("非法状态应 400：%d %s", w.Code, w.Body)
	}
}

// TestVulnCandidateSourceHopScope：离线域候选的源码位置必须落在授权目录清单内。
func TestVulnCandidateSourceHopScope(t *testing.T) {
	installTestPolicyPack(t, "binary-re", false)
	roots := localScopeRoots()
	if len(roots) == 0 {
		t.Fatal("离线域包应带出 scope.local_paths")
	}
	root := roots[0]
	src := filepath.Join(root, "handler.go")
	if err := os.WriteFile(src, []byte("package x\n\nfunc H() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.go")
	if err := os.WriteFile(outside, []byte("package y\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	s.archiveWG.Wait()
	<-s.side.done
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	req := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	body := fmt.Sprintf(`{"title":"解析器整数溢出","kind":"parse","location":%q,"hops":[{"ref_kind":"source","ref":%q,"claim":"入口解析"},{"ref_kind":"source","ref":%q,"claim":"授权外文件"},{"ref_kind":"source","ref":%q,"claim":"行号越界"}]}`,
		filepath.Base(src)+":3", src+":3", outside+":1", src+":99")
	c := decodeCandidate(t, req("POST", "/api/exploration/candidates", body))
	if len(c.Candidate.Hops) != 3 {
		t.Fatalf("应落三跳：%+v", c.Candidate.Hops)
	}
	if !c.Candidate.Hops[0].Verified {
		t.Fatalf("授权目录内文件应核对通过：%q", c.Candidate.Hops[0].VerifiedDetail)
	}
	if c.Candidate.Hops[1].Verified || !strings.Contains(c.Candidate.Hops[1].VerifiedDetail, "不在授权目录") {
		t.Fatalf("授权外文件不应通过：%+v", c.Candidate.Hops[1])
	}
	if c.Candidate.Hops[2].Verified || !strings.Contains(c.Candidate.Hops[2].VerifiedDetail, "行号越界") {
		t.Fatalf("行号越界不应通过：%+v", c.Candidate.Hops[2])
	}
	if c.Candidate.Reachability != vulnpipe.ReachPartial || c.Candidate.VerifiedHops != 1 {
		t.Fatalf("应为 partial/1：%+v", c.Candidate)
	}

	// 没有目录清单授权时，源码证据一律不能算核对上。
	policy.Install(nil) // 撤掉授权上下文，源码证据失去可核对的目录清单
	w := req("GET", fmt.Sprintf("/api/exploration/candidates/%d", c.Candidate.ID), "")
	c = decodeCandidate(t, w)
	if c.Candidate.Reachability != vulnpipe.ReachClaimed {
		t.Fatalf("空授权下源码证据应退回 claimed：%+v", c.Candidate)
	}
	if !strings.Contains(c.Candidate.Hops[0].VerifiedDetail, "目录清单授权") {
		t.Fatalf("应说明缺目录清单：%q", c.Candidate.Hops[0].VerifiedDetail)
	}
}
