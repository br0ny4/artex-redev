package server

import (
	"log"

	"github.com/br0ny4/artex-redev/agent"
	"github.com/br0ny4/artex-redev/policy"
)

// 规范全量停止（Stop-All）与任务调度联动：挂起 → 暂停正在跑的任务；操作员答复
// 并恢复 → 把这些任务续跑。
//
// 为什么必须暂停：判定挡下一个请求后，Agent 的本能是换条路径重试，每次重试都是一次
// LLM 调用。挂起可能要等客户确认几小时，不暂停就是在空烧 token，而这些请求必然全部
// 被挡下，除了判定流水什么也产不出。
//
// 边界：只续跑"因本次挂起被平台暂停"的任务；操作员自己暂停的任务不动。记录按挂起 id
// 分开保存，且只存在内存里——进程重启后挂起仍在 DB、任务暂停状态也已持久化，此时由
// 操作员在任务页手动恢复，不做隐式续跑。

// pauseTasksForPolicyHold 暂停所有非终态、非用户暂停的任务。
func (s *Server) pauseTasksForPolicyHold(h policy.HoldInfo) {
	if s == nil || s.m == nil {
		return
	}
	// 并发上限的准入/回收都走 concMu，这里按任务逐个调用控制接口，避免一次拿住锁太久。
	var paused []string
	for _, t := range s.m.List() {
		if t == nil {
			continue
		}
		lc := t.lifecycleSnapshot()
		if isTerminalStatus(lc.Status) || lc.Paused {
			continue
		}
		if _, err := s.applyTaskControlWithCause(t, "pause", agent.AbortPausedByPolicy); err != nil {
			// 常见于任务刚好结束/正在删除：不重试，继续处理其它任务。
			log.Printf("[policy] 挂起 #%d 时暂停任务 #%s 失败：%v", h.ID, t.ID, err)
			continue
		}
		paused = append(paused, t.ID)
	}
	if len(paused) == 0 {
		return
	}
	s.policyHoldMu.Lock()
	s.policyHoldPaused[h.ID] = paused
	s.policyHoldMu.Unlock()
	log.Printf("[policy] 全量停止 #%d（%s）：已暂停 %d 个任务 %v", h.ID, h.Rule, len(paused), paused)
}

// resumeTasksAfterPolicyHold 续跑被本次挂起暂停的任务。
func (s *Server) resumeTasksAfterPolicyHold(h policy.HoldInfo) {
	if s == nil || s.m == nil {
		return
	}
	s.policyHoldMu.Lock()
	ids := s.policyHoldPaused[h.ID]
	delete(s.policyHoldPaused, h.ID)
	s.policyHoldMu.Unlock()
	if len(ids) == 0 {
		return
	}
	resumed := 0
	for _, id := range ids {
		t, ok := s.m.Task(id)
		if !ok {
			continue
		}
		if _, err := s.applyTaskControlWithCause(t, "resume", nil); err != nil {
			log.Printf("[policy] 恢复挂起 #%d 后任务 #%s 未能续跑：%v（可在任务页手动恢复）", h.ID, id, err)
			continue
		}
		resumed++
	}
	log.Printf("[policy] 挂起 #%d 已答复：续跑 %d/%d 个任务", h.ID, resumed, len(ids))
}
