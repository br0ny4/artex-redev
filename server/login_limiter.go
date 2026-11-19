package server

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// 登录失败限速（P0 硬化）。
//
// 背景：上游 /api/auth/login 没有任何失败计数，公网实例可以被低成本爆破；再叠加
// /api/auth/init 未认证可抢占，暴露在公网的实例基本等于敞开。这里做最小可用的
// 按来源 IP 失败计数 + 锁定：
//   - 10 分钟窗口内失败 5 次 → 锁定 15 分钟；
//   - 成功登录清零；
//   - 锁定期间返回 429 + Retry-After。
//
// 注意：这是**单实例内存**限速，不做分布式；多副本部署应由前置网关承担。
const (
	loginMaxFails     = 5
	loginFailWindow   = 10 * time.Minute
	loginLockDuration = 15 * time.Minute
	loginLimiterMax   = 10000 // 防御性上限，避免被随机 IP 打爆内存
)

type loginState struct {
	fails   int
	firstAt time.Time
	until   time.Time
}

type loginLimiter struct {
	mu    sync.Mutex
	now   func() time.Time
	state map[string]*loginState
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{now: time.Now, state: map[string]*loginState{}}
}

// check 返回是否允许尝试；被锁定时同时返回剩余等待时间。
func (l *loginLimiter) check(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.state[key]
	if !ok {
		return true, 0
	}
	now := l.now()
	if st.until.After(now) {
		return false, st.until.Sub(now)
	}
	// 锁定过期，顺手清掉该键
	if !st.until.IsZero() {
		delete(l.state, key)
		return true, 0
	}
	// 窗口过期 → 计数清零
	if now.Sub(st.firstAt) > loginFailWindow {
		delete(l.state, key)
	}
	return true, 0
}

// fail 记一次失败，必要时锁定。
func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	st, ok := l.state[key]
	if !ok {
		if len(l.state) >= loginLimiterMax {
			l.evictLocked(now)
		}
		st = &loginState{firstAt: now}
		l.state[key] = st
	}
	if now.Sub(st.firstAt) > loginFailWindow {
		st.fails = 0
		st.firstAt = now
	}
	st.fails++
	if st.fails >= loginMaxFails {
		st.until = now.Add(loginLockDuration)
		st.fails = 0
	}
}

// reset 在登录成功后清零。
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.state, key)
}

func (l *loginLimiter) evictLocked(now time.Time) {
	for k, st := range l.state {
		if st.until.Before(now) && now.Sub(st.firstAt) > loginFailWindow {
			delete(l.state, k)
		}
	}
	if len(l.state) >= loginLimiterMax {
		// 仍然过满：整体清空（宁可短暂放宽，也不让内存无界增长）
		l.state = map[string]*loginState{}
	}
}

// clientIP 取来源 IP。默认只用 RemoteAddr；显式设置 ARTEX_TRUST_PROXY=1 时才采信
// X-Forwarded-For 的第一跳（前面确实有可信反代时才有意义，否则可被伪造）。
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	if os.Getenv("ARTEX_TRUST_PROXY") == "1" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if first != "" {
				return first
			}
		}
		if rip := strings.TrimSpace(r.Header.Get("X-Real-IP")); rip != "" {
			return rip
		}
	}
	return host
}
