package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/br0ny4/artex-redev/vulnpipe"
)

// 0day 流水线阶段 2–3 的持久化：候选（可疑点）与可达性路径。
// 判定规则在 vulnpipe 包（纯函数）；这里只存取，hop 的 verified 由服务端核对后写入。

// candidateStatuses 是候选允许的处置状态。
var candidateStatuses = map[string]bool{"open": true, "converted": true, "dismissed": true}

// CreateVulnCandidate 落一条候选及其可达性路径（同一事务，避免只写进一半）。
func (d *DB) CreateVulnCandidate(ctx context.Context, taskID, nodeID int64, in vulnpipe.CandidateInput) (int64, error) {
	if err := vulnpipe.ValidateCandidate(in); err != nil {
		return 0, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO vuln_candidates (task_id, node_id, title, kind, location, entry, sink, rationale)
		VALUES (NULLIF($1,0), NULLIF($2,0), $3, $4, $5, $6, $7, $8) RETURNING id`,
		taskID, nodeID, strings.TrimSpace(in.Title), vulnpipe.NormalizeKind(in.Kind),
		strings.TrimSpace(in.Location), strings.TrimSpace(in.Entry), strings.TrimSpace(in.Sink),
		strings.TrimSpace(in.Rationale)).Scan(&id); err != nil {
		return 0, err
	}
	for i, h := range in.Hops {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vuln_candidate_hops (candidate_id, ordinal, ref_kind, ref, claim)
			VALUES ($1,$2,$3,$4,$5)`,
			id, i+1, vulnpipe.NormalizeHopKind(h.RefKind), strings.TrimSpace(h.Ref), strings.TrimSpace(h.Claim)); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

// AddVulnCandidateHop 追加一跳（ordinal 自动 MAX+1）。
func (d *DB) AddVulnCandidateHop(ctx context.Context, candidateID int64, h vulnpipe.HopInput) (int64, error) {
	if strings.TrimSpace(h.Ref) == "" {
		return 0, errors.New("跳缺少 ref：traffic 写真实流量 id，source 写授权目录内的源码位置")
	}
	var exists bool
	if err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM vuln_candidates WHERE id=$1)`, candidateID).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, sql.ErrNoRows
	}
	var id int64
	err := d.QueryRowContext(ctx, `
		INSERT INTO vuln_candidate_hops (candidate_id, ordinal, ref_kind, ref, claim)
		VALUES ($1, (SELECT COALESCE(MAX(ordinal),0)+1 FROM vuln_candidate_hops WHERE candidate_id=$1), $2, $3, $4)
		RETURNING id`, candidateID, vulnpipe.NormalizeHopKind(h.RefKind), strings.TrimSpace(h.Ref), strings.TrimSpace(h.Claim)).Scan(&id)
	return id, err
}

// DeleteVulnCandidateHop 删除一跳。
func (d *DB) DeleteVulnCandidateHop(ctx context.Context, candidateID, hopID int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM vuln_candidate_hops WHERE id=$1 AND candidate_id=$2`, hopID, candidateID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetVulnCandidateHopVerification 写入一跳的核对结果（服务端核对后调用）。
func (d *DB) SetVulnCandidateHopVerification(ctx context.Context, hopID int64, verified bool, detail string) error {
	_, err := d.ExecContext(ctx, `UPDATE vuln_candidate_hops SET verified=$2, verified_detail=$3 WHERE id=$1`,
		hopID, verified, strings.TrimSpace(detail))
	return err
}

// SetVulnCandidateStatus 改候选处置状态（open/converted/dismissed）。
func (d *DB) SetVulnCandidateStatus(ctx context.Context, id int64, status string) error {
	if !candidateStatuses[status] {
		return errors.New("候选状态只能是 open / converted / dismissed")
	}
	res, err := d.ExecContext(ctx, `UPDATE vuln_candidates SET status=$2, updated_at=now() WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// LinkVulnCandidateFinding 把候选关联到 finding（候选转结论）；finding 必须存在。
func (d *DB) LinkVulnCandidateFinding(ctx context.Context, id, findingID int64) error {
	var exists bool
	if err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1)`, findingID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return sql.ErrNoRows
	}
	res, err := d.ExecContext(ctx, `UPDATE vuln_candidates SET finding_id=$2, status='converted', updated_at=now() WHERE id=$1`, id, findingID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetVulnCandidate 读一条候选（含路径与可达性结论）。
func (d *DB) GetVulnCandidate(ctx context.Context, id int64) (*vulnpipe.Candidate, error) {
	rows, err := d.QueryContext(ctx, candidateSelect+` WHERE c.id=$1`, id)
	if err != nil {
		return nil, err
	}
	list, err := scanCandidates(rows)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, sql.ErrNoRows
	}
	return list[0], nil
}

// ListVulnCandidates 按任务读候选；taskID<=0 时读全部（运维视图）。
func (d *DB) ListVulnCandidates(ctx context.Context, taskID int64, limit int) ([]*vulnpipe.Candidate, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.QueryContext(ctx, candidateSelect+` WHERE ($1=0 OR c.task_id=$1) ORDER BY c.created_at DESC, c.id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	return scanCandidates(rows)
}

// ListVulnCandidatesByFinding 读关联到某 finding 的候选（准入页展示"结论从哪来"）。
func (d *DB) ListVulnCandidatesByFinding(ctx context.Context, findingID int64) ([]*vulnpipe.Candidate, error) {
	rows, err := d.QueryContext(ctx, candidateSelect+` WHERE c.finding_id=$1 ORDER BY c.id`, findingID)
	if err != nil {
		return nil, err
	}
	return scanCandidates(rows)
}

const candidateSelect = `
	SELECT c.id, COALESCE(c.task_id,0), COALESCE(c.node_id,0), COALESCE(c.finding_id,0),
	       c.title, c.kind, c.location, c.entry, c.sink, c.rationale, c.status,
	       COALESCE(h.id,0), COALESCE(h.ordinal,0), COALESCE(h.ref_kind,''), COALESCE(h.ref,''),
	       COALESCE(h.claim,''), COALESCE(h.verified,false), COALESCE(h.verified_detail,''),
	       c.created_at, c.updated_at
	FROM vuln_candidates c
	LEFT JOIN vuln_candidate_hops h ON h.candidate_id = c.id`

// scanCandidates 把 candidate+hops 的行集合折叠成候选列表。
func scanCandidates(rows *sql.Rows) ([]*vulnpipe.Candidate, error) {
	defer rows.Close()
	var out []*vulnpipe.Candidate
	index := map[int64]*vulnpipe.Candidate{}
	for rows.Next() {
		var (
			c   vulnpipe.Candidate
			h   vulnpipe.Hop
			hid int64
		)
		if err := rows.Scan(&c.ID, &c.TaskID, &c.NodeID, &c.FindingID,
			&c.Title, &c.Kind, &c.Location, &c.Entry, &c.Sink, &c.Rationale, &c.Status,
			&hid, &h.Ordinal, &h.RefKind, &h.Ref, &h.Claim, &h.Verified, &h.VerifiedDetail,
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		got := index[c.ID]
		if got == nil {
			cp := c
			index[c.ID] = &cp
			out = append(out, &cp)
		}
		if hid > 0 {
			h.ID = hid
			index[c.ID].Hops = append(index[c.ID].Hops, h)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, c := range out {
		c.Reachability, c.VerifiedHops, c.Unverified = vulnpipe.Reachability(c.Hops)
	}
	return out, nil
}

// RecordCandidate 让探索写入路径也能登记候选（agent 工具用）。
func (s *ExplorationStore) RecordCandidate(ctx context.Context, taskID, nodeID int64, in vulnpipe.CandidateInput) (int64, error) {
	return s.db.CreateVulnCandidate(ctx, taskID, nodeID, in)
}

// LinkCandidateFinding 让上报路径能把候选转成结论（agent 工具用）。
func (s *ExplorationStore) LinkCandidateFinding(ctx context.Context, candidateID, findingID int64) error {
	return s.db.LinkVulnCandidateFinding(ctx, candidateID, findingID)
}
