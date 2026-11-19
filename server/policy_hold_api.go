package server

import (
	"net/http"
	"strconv"

	"github.com/br0ny4/artex-redev/db"
	"github.com/br0ny4/artex-redev/policy"
)

// 全局挂起的操作员接口（规范 7.3）。
//
// 语义：Agent 遇到"需要向本方确认"的情形（范围不明 / 语义判不清 / 预算耗尽）时，平台
// **全量停止**，把问题原样转述给操作员，未获明确答复前不恢复。这里提供两件事：
//   - GET  /api/policy/holds            看当前挂起（?all=1 看历史）
//   - POST /api/policy/holds/{id}/answer 答复；resume=true 才恢复测试
//
// 注意：答复模糊时不要 resume——宁可再问一次，也不要自行解释后继续（规范 7.3）。

// GET /api/policy/holds
func (s *Server) pgPolicyHolds(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var (
		holds any
		err   error
	)
	if r.URL.Query().Get("all") == "1" {
		limits := 100
		if v, e := strconv.Atoi(r.URL.Query().Get("limit")); e == nil && v > 0 {
			limits = v
		}
		holds, err = pg.ListPolicyHolds(r.Context(), limits)
	} else {
		holds, err = pg.ListOpenPolicyHolds(r.Context())
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	eng := policy.Default()
	resp := map[string]any{"holds": holds}
	if eng != nil {
		if h, ok := eng.ActiveHold(); ok {
			resp["engine_hold"] = h
			// 引擎仍在停止，但对应记录已经是 answered（操作员先记了一笔）：必须把它
			// 一并返回，否则界面拿不到 DB id，永远无法 resume——全量停止就成了永久停止。
			if list, ok := holds.([]db.PolicyHold); ok {
				found := false
				for _, row := range list {
					if row.EngineHoldID == h.ID && row.Status != "resumed" {
						found = true
						break
					}
				}
				if !found {
					if row, err := pg.GetPolicyHoldByEngineID(r.Context(), h.ID); err == nil && row != nil && row.Status != "resumed" {
						resp["holds"] = append([]db.PolicyHold{*row}, list...)
					}
				}
			}
		}
	}
	writeJSON(w, 200, resp)
}

// POST /api/policy/holds/{id}/answer
//
// body: {"answer": "...", "resume": true}
func (s *Server) pgPolicyAnswerHold(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的挂起 id")
		return
	}
	var req struct {
		Answer string `json:"answer"`
		Resume bool   `json:"resume"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.Resume && req.Answer == "" {
		// 规范 7.3：答复模糊不恢复。这里把"答复为空却要求恢复"直接拒掉。
		writeErr(w, 400, "要求恢复时必须写明答复内容（答复模糊时请再确认）")
		return
	}

	hold, err := pg.GetPolicyHold(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if hold == nil {
		writeErr(w, 404, "挂起记录不存在")
		return
	}
	// answered 允许再答：先记录答复、后拿到客户确认再 resume 是正常流程。
	if hold.Status != "open" && hold.Status != "answered" {
		writeErr(w, 409, "该挂起已处理（状态："+hold.Status+"）")
		return
	}

	resumed := false
	if req.Resume {
		if eng := policy.Default(); eng != nil {
			// 引擎里可能已经不存在（例如进程重启后的新实例）：此时只记录 DB 答复，
			// 由操作员手动确认任务是否继续，避免"解除了一个不存在的挂起"造成误解。
			resumed = eng.ReleaseGlobalHold(hold.EngineHoldID)
		}
	}
	if err := pg.AnswerPolicyHold(r.Context(), id, req.Answer, "operator", req.Resume); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":            true,
		"resumed":       resumed,
		"resume_intent": req.Resume,
	})
}
