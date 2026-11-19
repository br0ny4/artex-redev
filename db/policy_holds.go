package db

import (
	"context"
	"database/sql"
	"time"
)

// PolicyHold 是一次"全局挂起"的持久化记录（规范 7.3）。
//
// 与 intercept_pending 的区别：intercept 管的是"某一次工具调用要不要批准"，
// hold 管的是"整个 engagement 停下来，等操作员把问题答清楚"。
type PolicyHold struct {
	ID           int64      `json:"id"`
	TaskID       string     `json:"task_id"`
	EngagementID string     `json:"engagement_id"`
	EngineHoldID int64      `json:"engine_hold_id"`
	Reason       string     `json:"reason"` // SCOPE_UNCERTAIN / SEMANTICS_UNCERTAIN / BUDGET_EXHAUSTED …
	Question     string     `json:"question"`
	Status       string     `json:"status"` // open | answered | resumed | expired
	Answer       string     `json:"answer"`
	AnsweredBy   string     `json:"answered_by"`
	CreatedAt    time.Time  `json:"created_at"`
	AnsweredAt   *time.Time `json:"answered_at"`
}

// OpenPolicyHold 记录一次挂起。同一条引擎挂起重复投递时返回已有记录（幂等）。
func (d *DB) OpenPolicyHold(ctx context.Context, h PolicyHold) (int64, error) {
	if h.Status == "" {
		h.Status = "open"
	}
	if h.EngineHoldID > 0 {
		var id int64
		err := d.QueryRowContext(ctx,
			`SELECT id FROM policy_holds WHERE engine_hold_id=$1 AND status='open' LIMIT 1`,
			h.EngineHoldID).Scan(&id)
		if err == nil {
			return id, nil
		}
		if err != sql.ErrNoRows {
			return 0, err
		}
	}
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO policy_holds (task_id, engagement_id, engine_hold_id, reason, question, status)
VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		h.TaskID, h.EngagementID, h.EngineHoldID, h.Reason, h.Question, h.Status).Scan(&id)
	return id, err
}

// AnswerPolicyHold 记录操作员答复。resume=true 表示"确认可以继续"，status 置 resumed；
// 否则置 answered（答复了但仍不允许恢复，需要进一步处理）。
func (d *DB) AnswerPolicyHold(ctx context.Context, id int64, answer, answeredBy string, resume bool) error {
	status := "answered"
	if resume {
		status = "resumed"
	}
	res, err := d.ExecContext(ctx, `
UPDATE policy_holds
SET status=$2, answer=$3, answered_by=$4, answered_at=now()
WHERE id=$1 AND status='open'`, id, status, answer, answeredBy)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

const policyHoldCols = `id, task_id, engagement_id, engine_hold_id, reason, question, status, answer, answered_by, created_at, answered_at`

func scanPolicyHold(rows interface {
	Scan(dest ...any) error
}) (PolicyHold, error) {
	var h PolicyHold
	var answeredAt sql.NullTime
	err := rows.Scan(&h.ID, &h.TaskID, &h.EngagementID, &h.EngineHoldID, &h.Reason, &h.Question,
		&h.Status, &h.Answer, &h.AnsweredBy, &h.CreatedAt, &answeredAt)
	if err != nil {
		return h, err
	}
	if answeredAt.Valid {
		t := answeredAt.Time
		h.AnsweredAt = &t
	}
	return h, nil
}

// ListOpenPolicyHolds 返回所有未处理的挂起（新→旧）。
func (d *DB) ListOpenPolicyHolds(ctx context.Context) ([]PolicyHold, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+policyHoldCols+` FROM policy_holds WHERE status='open' ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyHold
	for rows.Next() {
		h, err := scanPolicyHold(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ListPolicyHolds 返回最近的挂起记录（含已处理），用于审计/排查。
func (d *DB) ListPolicyHolds(ctx context.Context, limit int) ([]PolicyHold, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.QueryContext(ctx,
		`SELECT `+policyHoldCols+` FROM policy_holds ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyHold
	for rows.Next() {
		h, err := scanPolicyHold(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// GetPolicyHold 按 id 读取。
func (d *DB) GetPolicyHold(ctx context.Context, id int64) (*PolicyHold, error) {
	row := d.QueryRowContext(ctx, `SELECT `+policyHoldCols+` FROM policy_holds WHERE id=$1`, id)
	h, err := scanPolicyHold(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}
