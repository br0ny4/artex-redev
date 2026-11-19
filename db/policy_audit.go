package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// PolicyDecision 是规范执行层的一条判定审计记录（只写不改）。
type PolicyDecision struct {
	ID           int64              `json:"id"`
	TS           time.Time          `json:"ts"`
	EngagementID string             `json:"engagement_id"`
	TaskID       string             `json:"task_id"`
	Source       string             `json:"source"` // L1-command | L3-request | L3-response
	Host         string             `json:"host"`
	Method       string             `json:"method"`
	Path         string             `json:"path"`
	Class        string             `json:"class"`
	Action       string             `json:"action"` // deny | hold | warn
	Rule         string             `json:"rule"`
	Reason       string             `json:"reason"`
	Budget       map[string]float64 `json:"budget,omitempty"`
	PrevHash     string             `json:"prev_hash"`
	Hash         string             `json:"hash"`
}

// policyAuditMu serializes the read-last-hash → insert step so the chain can't fork
// under concurrent decisions. Multi-replica deployments would need a DB-level lock
// instead (documented in docs/redev/05-decisions.md).
var policyAuditMu sync.Mutex

// decisionHash 计算链上的一条摘要：prev_hash 参与，任何一条被改都会让后续全部失配。
func decisionHash(prev string, d PolicyDecision) string {
	budget, _ := json.Marshal(d.Budget)
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		prev, d.TS.UTC().Format(time.RFC3339Nano), d.EngagementID, d.TaskID, d.Source,
		d.Host, d.Method, d.Path, d.Class, d.Action, d.Rule, d.Reason)
	h.Write(budget)
	return hex.EncodeToString(h.Sum(nil))
}

// AppendPolicyDecision 追加一条判定并返回落库后的记录（含 hash）。
func (d *DB) AppendPolicyDecision(ctx context.Context, in PolicyDecision) (PolicyDecision, error) {
	if in.TS.IsZero() {
		in.TS = time.Now()
	}
	policyAuditMu.Lock()
	defer policyAuditMu.Unlock()

	prev := ""
	// 取链尾；空表时 prev 为空串（创世记录）。
	if err := d.QueryRowContext(ctx,
		`SELECT hash FROM policy_decisions ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil && err.Error() != "sql: no rows in result set" {
		return in, fmt.Errorf("读取判定链尾: %w", err)
	}
	in.PrevHash = prev
	in.Hash = decisionHash(prev, in)
	budget, _ := json.Marshal(in.Budget)
	if in.Budget == nil {
		budget = []byte("{}")
	}
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO policy_decisions
  (ts, engagement_id, task_id, source, host, method, path, class, action, rule, reason, budget, prev_hash, hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
RETURNING id`,
		in.TS, in.EngagementID, in.TaskID, in.Source, in.Host, in.Method, in.Path,
		in.Class, in.Action, in.Rule, in.Reason, budget, in.PrevHash, in.Hash).Scan(&id)
	if err != nil {
		return in, fmt.Errorf("写入判定审计: %w", err)
	}
	in.ID = id
	return in, nil
}

// ListPolicyDecisions 返回最近的判定记录（新→旧）。
func (d *DB) ListPolicyDecisions(ctx context.Context, limit int) ([]PolicyDecision, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := d.QueryContext(ctx, `
SELECT id, ts, engagement_id, task_id, source, host, method, path, class, action, rule, reason, budget, prev_hash, hash
FROM policy_decisions ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyDecision
	for rows.Next() {
		var r PolicyDecision
		var budget []byte
		if err := rows.Scan(&r.ID, &r.TS, &r.EngagementID, &r.TaskID, &r.Source, &r.Host,
			&r.Method, &r.Path, &r.Class, &r.Action, &r.Rule, &r.Reason, &budget, &r.PrevHash, &r.Hash); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(budget, &r.Budget)
		out = append(out, r)
	}
	return out, rows.Err()
}

// VerifyPolicyChain 校验审计链自洽（报告中"证据链完整"的断言就靠它）。
func (d *DB) VerifyPolicyChain(ctx context.Context) (int, error) {
	rows, err := d.QueryContext(ctx, `
SELECT id, ts, engagement_id, task_id, source, host, method, path, class, action, rule, reason, budget, prev_hash, hash
FROM policy_decisions ORDER BY id ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	prev := ""
	n := 0
	for rows.Next() {
		var r PolicyDecision
		var budget []byte
		if err := rows.Scan(&r.ID, &r.TS, &r.EngagementID, &r.TaskID, &r.Source, &r.Host,
			&r.Method, &r.Path, &r.Class, &r.Action, &r.Rule, &r.Reason, &budget, &r.PrevHash, &r.Hash); err != nil {
			return n, err
		}
		_ = json.Unmarshal(budget, &r.Budget)
		if r.PrevHash != prev {
			return n, fmt.Errorf("判定链在 id=%d 断裂：prev_hash=%q 期望 %q", r.ID, r.PrevHash, prev)
		}
		if want := decisionHash(prev, r); want != r.Hash {
			return n, fmt.Errorf("判定链在 id=%d 被篡改：hash=%q 期望 %q", r.ID, r.Hash, want)
		}
		prev = r.Hash
		n++
	}
	return n, rows.Err()
}
