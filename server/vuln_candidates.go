package server

// 0day 流水线阶段 2–3 的 HTTP 接口：候选（可疑点）与可达性路径。
//
// 这里不做"模型说它可达就算可达"：路径的每一跳都拿到平台侧核对——在线域核对流量
// id 是否真的存在（不是编的），离线域核对源码位置是否真的在授权目录清单里。核对
// 结果写回 hop 行，候选的可达性结论由 vulnpipe.Reachability 从核对结果推导。
//
// 它不阻断导出（闸门在 vulngate 三道门），但会在准入页展示"结论从哪来"：候选是否
// 有路径、路径里几跳是自己说的、几跳平台对上了。

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/br0ny4/artex-redev/policy"
	"github.com/br0ny4/artex-redev/vulnpipe"
)

type candidatePayload struct {
	TaskID    int64               `json:"task_id"`
	NodeID    int64               `json:"node_id"`
	Title     string              `json:"title"`
	Kind      string              `json:"kind"`
	Location  string              `json:"location"`
	Entry     string              `json:"entry"`
	Sink      string              `json:"sink"`
	Rationale string              `json:"rationale"`
	Hops      []vulnpipe.HopInput `json:"hops"`
}

type candidateHopPayload struct {
	RefKind string `json:"ref_kind"`
	Ref     string `json:"ref"`
	Claim   string `json:"claim"`
}

// listVulnCandidates 列出候选（task_id 可选；默认全部）。每一跳都重新核对——
// 流量可能被清理，源码文件可能被移走，读的时候的结论比落库时可信。
func (s *Server) listVulnCandidates(w http.ResponseWriter, r *http.Request) {
	taskID := int64(atoiDefault(r.URL.Query().Get("task_id"), 0))
	limit := atoiDefault(r.URL.Query().Get("limit"), 200)
	list, err := s.m.pg.ListVulnCandidates(r.Context(), taskID, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, c := range list {
		s.verifyCandidateHops(r.Context(), c)
	}
	writeJSON(w, 200, map[string]any{"candidates": list})
}

// createVulnCandidate 落一条候选。候选允许入口/汇点先空着——那正是阶段 3 要补的。
func (s *Server) createVulnCandidate(w http.ResponseWriter, r *http.Request) {
	var p candidatePayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
		writeErr(w, 400, "解析请求失败: "+err.Error())
		return
	}
	if p.TaskID > 0 {
		var exists bool
		if err := s.m.pg.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1)`, p.TaskID).Scan(&exists); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if !exists {
			writeErr(w, 404, "task not found")
			return
		}
	}
	in := vulnpipe.CandidateInput{
		Title: p.Title, Kind: p.Kind, Location: p.Location, Entry: p.Entry,
		Sink: p.Sink, Rationale: p.Rationale, Hops: p.Hops,
	}
	if err := vulnpipe.ValidateCandidate(in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	id, err := s.m.pg.CreateVulnCandidate(r.Context(), p.TaskID, p.NodeID, in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	c, err := s.m.pg.GetVulnCandidate(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.verifyCandidateHops(r.Context(), c)
	writeJSON(w, 201, map[string]any{"candidate": c})
}

// getVulnCandidate 读一条候选并按当前证据重新核对可达性。
func (s *Server) getVulnCandidate(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad candidate id")
		return
	}
	c, err := s.m.pg.GetVulnCandidate(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "candidate not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	s.verifyCandidateHops(r.Context(), c)
	writeJSON(w, 200, map[string]any{"candidate": c, "reach_label": vulnpipe.ReachLabel(c.Reachability)})
}

// addVulnCandidateHop 追加一跳并立刻核对。
func (s *Server) addVulnCandidateHop(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad candidate id")
		return
	}
	var p candidateHopPayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
		writeErr(w, 400, "解析请求失败: "+err.Error())
		return
	}
	if _, err := s.m.pg.AddVulnCandidateHop(r.Context(), id, vulnpipe.HopInput{RefKind: p.RefKind, Ref: p.Ref, Claim: p.Claim}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "candidate not found")
			return
		}
		writeErr(w, 400, err.Error())
		return
	}
	s.respondCandidate(w, r, id)
}

// deleteVulnCandidateHop 删一跳（写错了的路径不该留在证据里）。
func (s *Server) deleteVulnCandidateHop(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	hid := int64(atoiDefault(r.PathValue("hid"), 0))
	if id <= 0 || hid <= 0 {
		writeErr(w, 400, "bad candidate/hop id")
		return
	}
	if err := s.m.pg.DeleteVulnCandidateHop(r.Context(), id, hid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "hop not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	s.respondCandidate(w, r, id)
}

// setVulnCandidateStatus 改处置状态（open/converted/dismissed）。
func (s *Server) setVulnCandidateStatus(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad candidate id")
		return
	}
	var p struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&p); err != nil {
		writeErr(w, 400, "解析请求失败: "+err.Error())
		return
	}
	if err := s.m.pg.SetVulnCandidateStatus(r.Context(), id, strings.TrimSpace(p.Status)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "candidate not found")
			return
		}
		writeErr(w, 400, err.Error())
		return
	}
	s.respondCandidate(w, r, id)
}

// linkVulnCandidateFinding 把候选关联到 finding（候选转结论）。
func (s *Server) linkVulnCandidateFinding(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad candidate id")
		return
	}
	var p struct {
		FindingID int64 `json:"finding_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&p); err != nil {
		writeErr(w, 400, "解析请求失败: "+err.Error())
		return
	}
	if p.FindingID <= 0 {
		writeErr(w, 400, "缺少 finding_id：候选转结论要指明是哪条 finding")
		return
	}
	if err := s.m.pg.LinkVulnCandidateFinding(r.Context(), id, p.FindingID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "candidate 或 finding 不存在")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	s.respondCandidate(w, r, id)
}

func (s *Server) respondCandidate(w http.ResponseWriter, r *http.Request, id int64) {
	c, err := s.m.pg.GetVulnCandidate(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.verifyCandidateHops(r.Context(), c)
	writeJSON(w, 200, map[string]any{"candidate": c, "reach_label": vulnpipe.ReachLabel(c.Reachability)})
}

// verifyCandidateHops 逐跳核对并落库核对结果。
func (s *Server) verifyCandidateHops(ctx context.Context, c *vulnpipe.Candidate) {
	for i := range c.Hops {
		h := &c.Hops[i]
		verified, detail := s.verifyCandidateHop(ctx, h.RefKind, h.Ref)
		if h.Verified != verified || h.VerifiedDetail != detail {
			_ = s.m.pg.SetVulnCandidateHopVerification(ctx, h.ID, verified, detail)
		}
		h.Verified, h.VerifiedDetail = verified, detail
	}
	c.Reachability, c.VerifiedHops, c.Unverified = vulnpipe.Reachability(c.Hops)
}

// verifyCandidateHop 核对一跳：只认平台能独立验证的证据。
func (s *Server) verifyCandidateHop(ctx context.Context, refKind, ref string) (bool, string) {
	ref = strings.TrimSpace(ref)
	switch vulnpipe.NormalizeHopKind(refKind) {
	case vulnpipe.HopTraffic:
		if s.m.traffic == nil {
			return false, "流量录制未开启：没有流量索引可核对这一跳"
		}
		req, _, err := s.m.traffic.Get(ref)
		if err != nil {
			return false, "traffic id 不在流量索引中（编的 id 或已被清理）"
		}
		return true, "traffic " + ref + " · " + firstRequestLine(req)
	case vulnpipe.HopSource:
		return verifySourceRef(ref)
	default:
		return false, "命令/其他证据平台不代跑，需人工复核"
	}
}

// verifySourceRef 核对源码位置：文件必须存在、在授权目录清单内、行号不越界。
func verifySourceRef(ref string) (bool, string) {
	path, line := splitPathLine(ref)
	if path == "" {
		return false, "源码位置为空"
	}
	roots := localScopeRoots()
	if len(roots) == 0 {
		return false, "当前域包没有目录清单授权（scope.local_paths 为空），源码位置无法核对"
	}
	abs, root, ok := resolveInRoots(path, roots)
	if !ok {
		return false, "源码位置不在授权目录清单内（scope.local_paths）：" + path
	}
	st, err := os.Stat(abs)
	if err != nil || st.IsDir() {
		return false, "源码文件不存在：" + path
	}
	if line > 0 {
		n, err := countLines(abs)
		if err != nil {
			return false, "读取源码文件失败：" + err.Error()
		}
		if line > n {
			return false, "行号越界：文件只有 " + strconv.Itoa(n) + " 行"
		}
	}
	detail := "源码 " + abs
	if line > 0 {
		detail += ":" + strconv.Itoa(line)
	}
	return true, detail + " 位于授权目录 " + root
}

// localScopeRoots 返回当前域包 engagement.scope.local_paths（绝对路径）。
func localScopeRoots() []string {
	eng := policy.Default()
	if eng == nil || eng.Engagement() == nil {
		return nil
	}
	var out []string
	for _, p := range eng.Engagement().Scope.LocalPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			out = append(out, abs)
		}
	}
	return out
}

// resolveInRoots 判断 path 是否落在某个授权根目录内；相对路径按根目录逐个拼接尝试。
func resolveInRoots(path string, roots []string) (string, string, bool) {
	candidates := []string{path}
	if !filepath.IsAbs(path) {
		candidates = candidates[:0]
		for _, r := range roots {
			candidates = append(candidates, filepath.Join(r, path))
		}
	}
	for _, cand := range candidates {
		abs, err := filepath.Abs(cand)
		if err != nil {
			continue
		}
		for _, root := range roots {
			rel, err := filepath.Rel(root, abs)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			return abs, root, true
		}
	}
	return "", "", false
}

// splitPathLine 拆 "path:line"（行号必须是纯数字；Windows 盘符不会被误拆）。
func splitPathLine(ref string) (string, int) {
	i := strings.LastIndex(ref, ":")
	if i <= 0 || i == len(ref)-1 {
		return strings.TrimSpace(ref), 0
	}
	suffix := ref[i+1:]
	n, err := strconv.Atoi(suffix)
	if err != nil || n <= 0 {
		return strings.TrimSpace(ref), 0
	}
	return strings.TrimSpace(ref[:i]), n
}

// countLines 数文件行数（上限 20 万行，避免被超大文件拖住）。
func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64<<10)
	sc.Buffer(buf, 1<<20)
	n := 0
	for sc.Scan() {
		n++
		if n > 200000 {
			break
		}
	}
	return n, sc.Err()
}

// firstRequestLine 取请求头第一行（请求行），没有就返回空。
func firstRequestLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
