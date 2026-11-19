package server

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/br0ny4/artex-redev/db"
	"github.com/br0ny4/artex-redev/policy"
)

// installPolicyAuditor 把规范判定事件异步写入 PG（hash chain）。
//
// 关键约束：判定在请求/工具调用路径上，**绝不能因为数据库慢而阻塞**。所以这里用
// 有界队列 + 单写协程，队列满时丢弃并计数（宁可少记一条，不可卡住一次拦截）。
func installPolicyAuditor(ctx context.Context, pg *db.DB) {
	if pg == nil {
		return
	}
	const queue = 1024
	ch := make(chan policy.Event, queue)
	var dropped atomic.Int64

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-ch:
				wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				// L5 挂起单独落 policy_holds：它是"全量停止 + 等答复"的载体，
				// 与普通判定流水账不是一回事（规范 7.3）。
				if ev.Source == "L5-hold" {
					if _, err := pg.OpenPolicyHold(wctx, db.PolicyHold{
						TaskID:       ev.TaskID,
						EngagementID: ev.EngagementID,
						EngineHoldID: ev.HoldID,
						Reason:       ev.Rule,
						Question:     ev.Question,
					}); err != nil {
						log.Printf("[policy] 挂起落库失败（内存挂起仍生效）: %v", err)
					}
				}
				_, err := pg.AppendPolicyDecision(wctx, db.PolicyDecision{
					TS:           ev.TS,
					EngagementID: ev.EngagementID,
					TaskID:       ev.TaskID,
					Source:       ev.Source,
					Host:         ev.Host,
					Method:       ev.Method,
					Path:         ev.Path,
					Class:        ev.Class,
					Action:       ev.Action,
					Rule:         ev.Rule,
					Reason:       ev.Reason,
					Budget:       ev.Budget,
				})
				cancel()
				if err != nil {
					log.Printf("[policy] 审计落库失败（判定本身已生效）: %v", err)
				}
			}
		}
	}()

	policy.SetAuditor(func(ev policy.Event) {
		select {
		case ch <- ev:
		default:
			n := dropped.Add(1)
			if n == 1 || n%1000 == 0 {
				log.Printf("[policy] 审计队列已满，已丢弃 %d 条（判定不受影响）", n)
			}
		}
	})
}

// GET /api/policy/status — 当前规范执行层状态（是否启用、模式、授权上下文摘要）。
func (s *Server) pgPolicyStatus(w http.ResponseWriter, r *http.Request) {
	eng := policy.Default()
	if eng == nil {
		writeJSON(w, 200, map[string]any{
			"enabled": false,
			"reason":  "未配置 ARTEX_ENGAGEMENT_FILE：授权范围/预算/语义拦截不生效",
		})
		return
	}
	resp := map[string]any{
		"enabled":      true,
		"mode":         eng.Mode(),
		"enforcing":    eng.Enforcing(),
		"spec_version": eng.SpecVersion(),
		"handshake":    eng.HandshakeToken(),
	}
	if e := eng.Engagement(); e != nil {
		resp["engagement"] = map[string]any{
			"id":        e.ID,
			"client":    e.Client,
			"title":     e.Title,
			"window":    e.Window,
			"scope":     e.Scope,
			"artifacts": e.Artifacts,
			"spec":      e.Compliance.SpecVersion,
		}
	}
	writeJSON(w, 200, resp)
}

// GET /api/policy/decisions?limit=N — 最近的判定记录（新→旧）。
func (s *Server) pgPolicyDecisions(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := pg.ListPolicyDecisions(r.Context(), limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"decisions": rows, "count": len(rows)})
}

// GET /api/policy/chain — 校验判定审计链完整性（报告里"证据链完整"的依据）。
func (s *Server) pgPolicyChain(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	n, err := pg.VerifyPolicyChain(r.Context())
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "verified": n, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "verified": n})
}
