package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/br0ny4/artex-redev/agent"
	"github.com/br0ny4/artex-redev/policy"
)

// 这两个用例走真实 mux，覆盖"工程层硬约束"最容易在重构中失效的两条链路：
// 初始化入口的身份校验，以及"全量停止 → 操作员答复 → 恢复"的闭环。

// installTestPolicy 安装一个最小但完整的授权上下文，返回引擎。
// 用例结束必须恢复全局默认（nil），否则会污染同包其它用例。
func installTestPolicy(t *testing.T) *policy.Engine {
	t.Helper()
	now := time.Now()
	// 用与随仓库发布的模板相同的结构（engagement 段 + 顶层 scope/工具/产出块），
	// 顺便守住"模板能被引擎直接加载"这条。
	ctx := fmt.Sprintf(`engagement:
  id: ENG-E2E
  client: e2e-client
  title: e2e
  authorization_doc_sha256: %s
  window:
    starts_at: "%s"
    ends_at: "%s"
scope:
  domains: [example.com]
test_accounts:
  - id: ta-1
    username: pentest_a
    bound_contact:
      phone: "+8613800000000"
report:
  channel: https://src.example.com/report/ENG-E2E
artifacts:
  dir: ./artifacts/ENG-E2E
compliance:
  spec_version: "2.5"
`,
		policy.SHA256Hex([]byte("authorization-doc")),
		now.Add(-time.Hour).Format(time.RFC3339),
		now.Add(time.Hour).Format(time.RFC3339),
	)
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	if err := os.WriteFile(path, []byte(ctx), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := policy.InstallFromFile(path)
	if err != nil {
		t.Fatalf("安装测试授权上下文失败: %v", err)
	}
	t.Cleanup(func() { policy.Install(nil) })
	return eng
}

// TestAuthInitRequiresSetupToken 覆盖未认证抢占这条路径：没有口令就不能设密码。
func TestAuthInitRequiresSetupToken(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("database unavailable (%v) — skipping", err)
	}
	defer m.Close()
	if m.pg == nil {
		t.Skip("postgres unavailable — skipping")
	}
	// 同一套 PG 会被反复跑：上一条用例可能已经设过密码，先清掉再验"未初始化"行为。
	if _, err := m.pg.ExecContext(context.Background(),
		`DELETE FROM settings WHERE key=$1`, "auth.password_hash"); err != nil {
		t.Fatalf("重置管理员密码状态: %v", err)
	}
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)
	h := s.Handler()

	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/auth/init", bytes.NewReader([]byte(body))))
		return rec
	}

	if rec := post(`{"password":"correct horse battery"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("不带口令应 403，得到 %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := post(`{"password":"correct horse battery","setup_token":"wrong-token"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("口令错误应 403，得到 %d body=%s", rec.Code, rec.Body.String())
	}
	body, _ := json.Marshal(map[string]string{
		"password":    "correct horse battery",
		"setup_token": s.setupToken,
	})
	rec := post(string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("口令正确应初始化成功，得到 %d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil || payload.Token == "" {
		t.Fatalf("初始化成功应返回 token，得到 %s (%v)", rec.Body.String(), err)
	}
	if rec := post(string(body)); rec.Code == http.StatusOK {
		t.Fatal("重复初始化不应成功（否则任何人都能重置已设好的密码）")
	}
}

// TestPolicyHoldLifecycle 覆盖规范 7.3：挂起是"全量停止"，必须操作员明确答复才恢复。
func TestPolicyHoldLifecycle(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("database unavailable (%v) — skipping", err)
	}
	defer m.Close()
	if m.pg == nil {
		t.Skip("postgres unavailable — skipping")
	}
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)
	h := s.Handler()
	// 引擎在 Manager 之后安装：Manager 的策略启用检查要求录制代理就绪（防 L3 绕过），
	// 这里只验证挂起/答复闭环，不重复测启动检查。
	eng := installTestPolicy(t)
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	do := func(method, path string, body any) (int, map[string]any) {
		var req *http.Request
		if body != nil {
			b, _ := json.Marshal(body)
			req = httptest.NewRequest(method, path, bytes.NewReader(b))
		} else {
			req = httptest.NewRequest(method, path, nil)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	// 执行层状态可观测：启用、规范版本 2.5、授权 ID。
	code, out := do("GET", "/api/policy/status", nil)
	if code != 200 || out["enabled"] != true {
		t.Fatalf("status=%d out=%v，期望 enabled=true", code, out)
	}
	if out["spec_version"] != "2.5" {
		t.Fatalf("spec_version=%v want 2.5", out["spec_version"])
	}

	// 触发全量停止：走真实判定链，而不是直接 RaiseHold（后者不发 L5-hold 审计，
	// 落库只发生在 raiseHoldDecision 里）。用 .invalid 域名（RFC 2606 保证 NXDOMAIN）
	// 让 DNS 解析失败 → 归属不明 → SCOPE_UNCERTAIN 全量停止。
	dctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d := eng.DecideRequest(dctx, "task-e2e", policy.Request{
		Method: "GET", Host: "unlisted-host.invalid", Path: "/",
	})
	if d.Action != policy.ActionHold {
		t.Fatalf("越界/归属不明应触发全量停止，得到 action=%q rule=%q reason=%q", d.Action, d.Rule, d.Reason)
	}
	hold, active := eng.ActiveHold()
	if !active || hold.Question == "" {
		t.Fatalf("引擎应持有挂起：active=%v hold=%+v", active, hold)
	}

	// 挂起必须对操作员可见（引擎内存视角）。
	code, out = do("GET", "/api/policy/holds", nil)
	if code != 200 {
		t.Fatalf("holds status=%d body=%v", code, out)
	}
	eh, _ := out["engine_hold"].(map[string]any)
	if eh == nil || eh["question"] != hold.Question || eh["rule"] != hold.Rule {
		t.Fatalf("engine_hold 缺失或与引擎不一致: %v (want %+v)", out["engine_hold"], hold)
	}

	// 审计是异步落库的：等一下拿到 DB 记录（id 用于答复）。
	var holdID float64
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, out = do("GET", "/api/policy/holds", nil)
		if arr, ok := out["holds"].([]any); ok && len(arr) > 0 {
			if row, ok := arr[0].(map[string]any); ok {
				if id, ok := row["id"].(float64); ok && id > 0 {
					holdID = id
					break
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if holdID == 0 {
		t.Fatal("挂起没有落库：操作员看不到就无法答复，全量停止会变成永久停止")
	}

	// 答复为空却要求恢复：必须拒绝（规范 7.3"答复模糊时不要 resume"）。
	if code, _ := do("POST", fmt.Sprintf("/api/policy/holds/%d/answer", int64(holdID)),
		map[string]any{"answer": "", "resume": true}); code != 400 {
		t.Fatalf("空答复要求恢复应 400，得到 %d", code)
	}
	// 只记录答复：测试仍保持停止。
	if code, out := do("POST", fmt.Sprintf("/api/policy/holds/%d/answer", int64(holdID)),
		map[string]any{"answer": "还在确认，先别动", "resume": false}); code != 200 {
		t.Fatalf("记录答复失败: %d %v", code, out)
	}
	if _, active := eng.ActiveHold(); !active {
		t.Fatal("未要求恢复时不应解除挂起")
	}

	// 明确答复 + 恢复。
	code, out = do("POST", fmt.Sprintf("/api/policy/holds/%d/answer", int64(holdID)),
		map[string]any{"answer": "已确认在授权范围内，可继续", "resume": true})
	if code != 200 || out["resumed"] != true {
		t.Fatalf("答复并恢复失败: %d %v", code, out)
	}
	if _, active := eng.ActiveHold(); active {
		t.Fatal("恢复后挂起应解除")
	}
}

// TestPolicyHoldPausesAndResumesTasks 覆盖"全量停止 = 真的停下来"这一闭环：
// 挂起必须暂停正在跑的任务（否则等待答复期间 Agent 会不停换路径重试、空烧 token），
// 操作员答复恢复后续跑，且不能把操作员自己暂停的任务也顺手恢复。
func TestPolicyHoldPausesAndResumesTasks(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("database unavailable (%v) — skipping", err)
	}
	defer m.Close()
	if m.pg == nil {
		t.Skip("postgres unavailable — skipping")
	}
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)
	eng := installTestPolicy(t)

	task, err := m.CreateTask("policy hold pause", "hold pause goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	// 另一个任务由"操作员自己"暂停：挂起/恢复都不该碰它。
	userTask, err := m.CreateTask("user paused", "user paused goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(userTask.ID, DeleteTaskOptions{}) }()
	if _, err := s.applyTaskControlWithCause(userTask, "pause", agent.AbortPausedByUser); err != nil {
		t.Fatalf("模拟操作员暂停任务失败: %v", err)
	}

	hold, created := eng.RaiseHold("SCOPE_UNCERTAIN", "范围归属不明", "example.com 是否在授权范围内？")
	if !created {
		t.Fatal("首次挂起应成功")
	}

	waitFor := func(name string, want bool, get func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if get() == want {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: 10s 内未达到期望状态 %v", name, want)
	}
	waitFor("挂起后任务应被暂停", true, func() bool { return task.Paused })
	if !s.engine.IsPaused(task.ID) {
		t.Fatal("挂起暂停应同时停下引擎侧执行")
	}

	if !eng.ReleaseGlobalHold(hold.ID) {
		t.Fatal("答复后应能解除挂起")
	}
	waitFor("答复恢复后任务应续跑", false, func() bool { return task.Paused })
	waitFor("任务续跑后引擎应解除暂停", false, func() bool { return s.engine.IsPaused(task.ID) })

	// 操作员自己暂停的任务必须保持暂停：平台不能替操作员做这个决定。
	if !userTask.Paused {
		t.Fatal("操作员手动暂停的任务被自动恢复了")
	}
}
