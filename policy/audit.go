package policy

import (
	"sync/atomic"
	"time"
)

// Event 是一条判定审计事件（只写不改）。落库由 server 侧的 auditor 完成，
// policy 包不依赖数据库，保持可单测。
type Event struct {
	TS           time.Time
	EngagementID string
	TaskID       string
	Source       string // L1-command | L3-request | L3-response
	Host         string
	Method       string
	Path         string
	Class        string
	Action       string // deny | hold | warn
	Rule         string
	HoldID       int64  // 仅 L5-hold：对应 engine 全局挂起的 id
	Question     string // 仅 L5-hold：要转述给操作员的问题
	Reason       string
	Budget       map[string]float64
}

type auditorFunc func(Event)

var auditor atomic.Pointer[auditorFunc]

// SetAuditor 安装审计出口（传 nil 卸载）。server 负责把它接到 db.AppendPolicyDecision。
func SetAuditor(fn func(Event)) {
	if fn == nil {
		auditor.Store(nil)
		return
	}
	f := auditorFunc(fn)
	auditor.Store(&f)
}

// audit 投递事件；未安装出口时是空操作（这也是单测能跑的前提）。
func audit(ev Event) {
	p := auditor.Load()
	if p == nil {
		return
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now()
	}
	(*p)(ev)
}

// emit 补齐 engagement 后投递。
func (e *Engine) emit(ev Event) {
	if e.eng != nil {
		ev.EngagementID = e.eng.ID
	}
	audit(ev)
}
