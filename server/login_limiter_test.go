package server

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginLimiterLocksAfterFailures(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }

	for i := 0; i < loginMaxFails; i++ {
		if ok, _ := l.check("1.2.3.4"); !ok {
			t.Fatalf("第 %d 次尝试不应被锁", i+1)
		}
		l.fail("1.2.3.4")
	}
	ok, retry := l.check("1.2.3.4")
	if ok {
		t.Fatal("连续失败 5 次后必须锁定")
	}
	if retry <= 0 || retry > loginLockDuration {
		t.Fatalf("retryAfter=%v 超出预期范围", retry)
	}

	// 其他 IP 不受影响
	if ok, _ := l.check("5.6.7.8"); !ok {
		t.Fatal("锁定必须按来源 IP 隔离")
	}

	// 锁定到期后放行
	now = now.Add(loginLockDuration + time.Second)
	if ok, _ := l.check("1.2.3.4"); !ok {
		t.Fatal("锁定到期后应放行")
	}
}

func TestLoginLimiterWindowExpiry(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }

	// 窗口内失败 4 次（未到阈值）
	for i := 0; i < loginMaxFails-1; i++ {
		l.fail("9.9.9.9")
	}
	// 窗口过去后计数清零，再失败一次不应触发锁定
	now = now.Add(loginFailWindow + time.Minute)
	l.fail("9.9.9.9")
	if ok, _ := l.check("9.9.9.9"); !ok {
		t.Fatal("失败窗口过期后计数应清零")
	}
}

func TestLoginLimiterResetOnSuccess(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < loginMaxFails-1; i++ {
		l.fail("2.2.2.2")
	}
	l.reset("2.2.2.2")
	for i := 0; i < loginMaxFails-1; i++ {
		l.fail("2.2.2.2")
	}
	if ok, _ := l.check("2.2.2.2"); !ok {
		t.Fatal("成功登录应清零，之后的失败不应立刻触发锁定")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	if got := clientIP(r); got != "203.0.113.7" {
		t.Fatalf("clientIP=%q", got)
	}

	// 默认不信任 XFF（可伪造）
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	if got := clientIP(r); got != "203.0.113.7" {
		t.Fatalf("默认不应采信 XFF，得到 %q", got)
	}
}
