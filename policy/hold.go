package policy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// HoldInfo 描述当前**全局挂起**（规范第七章 Stop-All）。
//
// 语义：任何一次"需要向本方确认"的判定（范围不明、语义判不清、预算耗尽）都会把整个
// engagement 挂起——不是只挡这一条请求。未获得操作员明确答复前，所有请求/命令一律
// 被平台挡下（规范 7.3："停止是全量的，不是单接口的"）。
type HoldInfo struct {
	ID       int64     `json:"id"`
	Rule     string    `json:"rule"`
	Reason   string    `json:"reason"`
	Question string    `json:"question"`
	Since    time.Time `json:"since"`
}

var holdSeq atomic.Int64

// 观察者：挂起/恢复时通知上层（server 用它暂停正在跑的任务）。
//
// 放在包级而不是 Engine 字段上，是因为安装顺序不固定：main 在 NewManager 之前
// InstallFromFile，测试里则在 server 建好之后安装。包级注册对两种顺序都成立。
var (
	holdObserverMu sync.RWMutex
	holdObserver   func(HoldInfo)
	resumeObserver func(HoldInfo)
)

// SetHoldObserver 注册全局挂起与恢复的回调。传 nil 取消注册。
//
// 回调在独立 goroutine 里执行：挂起发生在判定热路径（流量代理/guard）上，暂停任务
// 要拿并发的锁，不能让它阻塞判定本身。
func SetHoldObserver(onHold, onResume func(HoldInfo)) {
	holdObserverMu.Lock()
	holdObserver, resumeObserver = onHold, onResume
	holdObserverMu.Unlock()
}

func notifyHold(h HoldInfo) {
	holdObserverMu.RLock()
	f := holdObserver
	holdObserverMu.RUnlock()
	if f == nil {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		f(h)
	}()
}

func notifyResume(h HoldInfo) {
	holdObserverMu.RLock()
	f := resumeObserver
	holdObserverMu.RUnlock()
	if f == nil {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		f(h)
	}()
}

// RaiseHold 开启全局挂起。已处于挂起状态时幂等返回现有挂起（不会覆盖原因）。
func (e *Engine) RaiseHold(rule, reason, question string) (HoldInfo, bool) {
	e.holdMu.Lock()
	if e.hold != nil {
		h := *e.hold
		e.holdMu.Unlock()
		return h, false
	}
	h := HoldInfo{ID: holdSeq.Add(1), Rule: rule, Reason: reason, Question: question, Since: time.Now()}
	e.hold = &h
	e.holdMu.Unlock()
	notifyHold(h)
	return h, true
}

// ActiveHold 返回当前挂起状态。
func (e *Engine) ActiveHold() (HoldInfo, bool) {
	e.holdMu.Lock()
	defer e.holdMu.Unlock()
	if e.hold == nil {
		return HoldInfo{}, false
	}
	return *e.hold, true
}

// ReleaseGlobalHold 解除指定全局挂起。只有操作员明确答复后才应调用（规范 7.3）；
// id 不匹配时拒绝解除（防止旧答复把新挂起解掉）。
func (e *Engine) ReleaseGlobalHold(id int64) bool {
	e.holdMu.Lock()
	if e.hold == nil || e.hold.ID != id {
		e.holdMu.Unlock()
		return false
	}
	h := *e.hold
	e.hold = nil
	e.holdMu.Unlock()
	notifyResume(h)
	return true
}

// stopAllDecision 是"已挂起"时对所有请求/命令的统一答复。
func (e *Engine) stopAllDecision() Decision {
	e.holdMu.Lock()
	h := e.hold
	e.holdMu.Unlock()
	if h == nil {
		return Decision{}
	}
	return Decision{
		Action: ActionHold,
		Rule:   "STOP_ALL",
		Reason: "平台已全局挂起（等待操作员答复）：" + h.Reason,
	}
}

// raiseHoldDecision 创建挂起并返回判定；只有首次创建时发审计事件，
// 避免 agent 重试时把同一条挂起刷满审计表。
func (e *Engine) raiseHoldDecision(rule, reason, question string, class string) Decision {
	h, created := e.RaiseHold(rule, reason, question)
	if created {
		e.emit(Event{
			Source: "L5-hold", Class: class, Action: string(ActionHold), HoldID: h.ID,
			Rule: rule, Reason: fmt.Sprintf("%s（挂起 #%d）", reason, h.ID), Question: question,
		})
	}
	return Decision{Action: ActionHold, Rule: rule, Reason: reason, Class: class}
}
