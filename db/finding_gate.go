package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/br0ny4/artex-redev/vulngate"
)

// 0day 准入门的持久化。判定逻辑在 vulngate 包（纯函数），这里只负责存取与
// "一批 finding 是否都过门"的批量查询——导出报告时一次取齐，避免 N+1。

// AddFindingCounterexample 追加一条反例记录；ordinal 为 0 时按同一 finding 内 MAX+1 生成。
func (d *DB) AddFindingCounterexample(ctx context.Context, findingID int64, c vulngate.Counterexample) (vulngate.Counterexample, error) {
	if findingID <= 0 {
		return c, errors.New("finding_id 必须为正")
	}
	var exists bool
	if err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1)`, findingID).Scan(&exists); err != nil {
		return c, err
	}
	if !exists {
		return c, sql.ErrNoRows
	}
	if c.Ordinal <= 0 {
		if err := d.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(ordinal),0)+1 FROM finding_counterexamples WHERE finding_id=$1`, findingID).Scan(&c.Ordinal); err != nil {
			return c, err
		}
	}
	err := d.QueryRowContext(ctx, `
		INSERT INTO finding_counterexamples (finding_id, ordinal, claim, method, expected, observed, passed, evidence, traffic_ids)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		findingID, c.Ordinal, c.Claim, c.Method, c.Expected, c.Observed, c.Passed, c.Evidence,
		strings.Join(c.TrafficIDs, ",")).Scan(&c.ID)
	return c, err
}

// DeleteFindingCounterexample 删除一条反例（写错了要能撤回，否则操作员会绕过门）。
func (d *DB) DeleteFindingCounterexample(ctx context.Context, findingID, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM finding_counterexamples WHERE id=$1 AND finding_id=$2`, id, findingID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListFindingCounterexamples 按 ordinal 升序返回一条 finding 的反例。
func (d *DB) ListFindingCounterexamples(ctx context.Context, findingID int64) ([]vulngate.Counterexample, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT id, ordinal, claim, method, expected, observed, passed, evidence, traffic_ids
		FROM finding_counterexamples WHERE finding_id=$1 ORDER BY ordinal, id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vulngate.Counterexample
	for rows.Next() {
		var c vulngate.Counterexample
		var trafficIDs string
		if err := rows.Scan(&c.ID, &c.Ordinal, &c.Claim, &c.Method, &c.Expected, &c.Observed, &c.Passed, &c.Evidence, &trafficIDs); err != nil {
			return nil, err
		}
		if trafficIDs != "" {
			c.TrafficIDs = strings.Split(trafficIDs, ",")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddFindingNoveltyCheck 追加一次撞车比对记录。
func (d *DB) AddFindingNoveltyCheck(ctx context.Context, findingID int64, n vulngate.NoveltyCheck) (vulngate.NoveltyCheck, error) {
	if findingID <= 0 {
		return n, errors.New("finding_id 必须为正")
	}
	hits, err := json.Marshal(n.Hits)
	if err != nil {
		return n, err
	}
	var exists bool
	if err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1)`, findingID).Scan(&exists); err != nil {
		return n, err
	}
	if !exists {
		return n, sql.ErrNoRows
	}
	err = d.QueryRowContext(ctx, `
		INSERT INTO finding_novelty_checks (finding_id, query, source_class, hits, same_vuln, origin)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		findingID, n.Query, n.SourceClass, string(hits), n.SameVuln, noveltyOrigin(n.Origin)).Scan(&n.ID)
	return n, err
}

// DeleteFindingNoveltyCheck 删除一次比对记录。
func (d *DB) DeleteFindingNoveltyCheck(ctx context.Context, findingID, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM finding_novelty_checks WHERE id=$1 AND finding_id=$2`, id, findingID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListFindingNoveltyChecks 按写入顺序返回一条 finding 的撞车比对。
func (d *DB) ListFindingNoveltyChecks(ctx context.Context, findingID int64) ([]vulngate.NoveltyCheck, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT id, query, source_class, hits, same_vuln, origin, reviewed_by, reviewed_at, review_note
		FROM finding_novelty_checks WHERE finding_id=$1 ORDER BY id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vulngate.NoveltyCheck
	for rows.Next() {
		n, err := scanNoveltyCheckRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// noveltyScannable 是 sql.Row / sql.Rows 的公共能力（两者都满足）。
type noveltyScannable interface {
	Scan(dest ...any) error
}

// scanNoveltyCheckRow 统一读取撞车记录（含复核留痕三列）。
func scanNoveltyCheckRow(row noveltyScannable) (vulngate.NoveltyCheck, error) {
	var n vulngate.NoveltyCheck
	var hits string
	var reviewedAt sql.NullTime
	if err := row.Scan(&n.ID, &n.Query, &n.SourceClass, &hits, &n.SameVuln, &n.Origin,
		&n.ReviewedBy, &reviewedAt, &n.ReviewNote); err != nil {
		return n, err
	}
	if reviewedAt.Valid {
		t := reviewedAt.Time
		n.ReviewedAt = &t
	}
	_ = json.Unmarshal([]byte(hits), &n.Hits)
	return n, nil
}

// SetFindingNoveltyReview 记录一次人工复核结论：谁复核、何时、依据，以及是否撞车。
// 未复核的平台代检记录不计入门二（见 vulngate.Assess），所以这一步是准入门的一部分。
func (d *DB) SetFindingNoveltyReview(ctx context.Context, findingID, checkID int64, reviewedBy, note string, sameVuln bool) (vulngate.NoveltyCheck, error) {
	if findingID <= 0 || checkID <= 0 {
		return vulngate.NoveltyCheck{}, errors.New("finding_id/check_id 必须为正")
	}
	row := d.QueryRowContext(ctx, `
		UPDATE finding_novelty_checks
		SET same_vuln=$3, reviewed_by=$4, reviewed_at=now(), review_note=$5
		WHERE id=$1 AND finding_id=$2
		RETURNING id, query, source_class, hits, same_vuln, origin, reviewed_by, reviewed_at, review_note`,
		checkID, findingID, sameVuln, reviewedBy, note)
	return scanNoveltyCheckRow(row)
}

// FindingGateAssessment 汇总一条 finding 的全部门记录。
func (d *DB) FindingGateAssessment(ctx context.Context, findingID int64) (vulngate.Assessment, error) {
	var a vulngate.Assessment
	var err error
	if a.Counterexamples, err = d.ListFindingCounterexamples(ctx, findingID); err != nil {
		return a, err
	}
	if a.Novelty, err = d.ListFindingNoveltyChecks(ctx, findingID); err != nil {
		return a, err
	}
	if a.Poc, err = d.GetFindingPoc(ctx, findingID); err != nil {
		return a, err
	}
	if a.PocReplays, a.PocReplayMatched, err = d.CountFindingPocReplays(ctx, findingID); err != nil {
		return a, err
	}
	return a, nil
}

// FindingGateVerdict 给出单条 finding 的门结论。
func (d *DB) FindingGateVerdict(ctx context.Context, findingID int64) (vulngate.Verdict, error) {
	a, err := d.FindingGateAssessment(ctx, findingID)
	if err != nil {
		return vulngate.Verdict{}, err
	}
	return vulngate.Assess(a), nil
}

// FindingGateVerdicts 批量评估（导出报告时一次取齐）。返回的 map 只包含传入的 id，
// 没有记录的一律是 blocked——"没做验证"和"没做够"在门上是一回事。
func (d *DB) FindingGateVerdicts(ctx context.Context, ids []int64) (map[int64]vulngate.Verdict, error) {
	out := make(map[int64]vulngate.Verdict, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	ces := map[int64][]vulngate.Counterexample{}
	rows, err := d.QueryContext(ctx, `
		SELECT finding_id, id, ordinal, claim, method, expected, observed, passed, evidence
		FROM finding_counterexamples WHERE finding_id = ANY($1) ORDER BY finding_id, ordinal, id`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var fid int64
		var c vulngate.Counterexample
		if err := rows.Scan(&fid, &c.ID, &c.Ordinal, &c.Claim, &c.Method, &c.Expected, &c.Observed, &c.Passed, &c.Evidence); err != nil {
			rows.Close()
			return nil, err
		}
		ces[fid] = append(ces[fid], c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	nov := map[int64][]vulngate.NoveltyCheck{}
	rows, err = d.QueryContext(ctx, `
		SELECT finding_id, id, query, source_class, hits, same_vuln, origin, reviewed_by, reviewed_at, review_note
		FROM finding_novelty_checks WHERE finding_id = ANY($1) ORDER BY finding_id, id`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var fid int64
		var n vulngate.NoveltyCheck
		var hits string
		var reviewedAt sql.NullTime
		if err := rows.Scan(&fid, &n.ID, &n.Query, &n.SourceClass, &hits, &n.SameVuln, &n.Origin,
			&n.ReviewedBy, &reviewedAt, &n.ReviewNote); err != nil {
			rows.Close()
			return nil, err
		}
		if reviewedAt.Valid {
			t := reviewedAt.Time
			n.ReviewedAt = &t
		}
		_ = json.Unmarshal([]byte(hits), &n.Hits)
		nov[fid] = append(nov[fid], n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	pocs, err := d.loadPocs(ctx, ids)
	if err != nil {
		return nil, err
	}
	replays, err := d.loadPocReplayCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		rc := replays[id]
		out[id] = vulngate.Assess(vulngate.Assessment{
			Counterexamples: ces[id], Novelty: nov[id], Poc: pocs[id],
			PocReplays: rc[0], PocReplayMatched: rc[1],
		})
	}
	return out, nil
}

// loadPocReplayCounts 批量取重放统计（总次数 / 一致次数），供导出时一次评估。
func (d *DB) loadPocReplayCounts(ctx context.Context, ids []int64) (map[int64][2]int, error) {
	out := map[int64][2]int{}
	rows, err := d.QueryContext(ctx, `
		SELECT finding_id, COUNT(*), COUNT(*) FILTER (WHERE matched)
		FROM finding_poc_replays WHERE finding_id = ANY($1) GROUP BY finding_id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var fid int64
		var total, matched int
		if err := rows.Scan(&fid, &total, &matched); err != nil {
			return nil, err
		}
		out[fid] = [2]int{total, matched}
	}
	return out, rows.Err()
}

// FindingGateSummary 是阻塞项的展示用摘要（导出被挡时返回给调用方）。
type FindingGateSummary struct {
	FindingID int64    `json:"finding_id,string"`
	Name      string   `json:"name"`
	Verdict   string   `json:"verdict"`
	Reasons   []string `json:"reasons"`
}

// GateBlockedSummary 把 verdict map 里 blocked 的条目整理成摘要，按 id 升序。
func GateBlockedSummary(fs []*DBFinding, verdicts map[int64]vulngate.Verdict) []FindingGateSummary {
	var out []FindingGateSummary
	for _, f := range fs {
		v, ok := verdicts[f.ID]
		if !ok {
			v = vulngate.Assess(vulngate.Assessment{})
		}
		if v.Passed() {
			continue
		}
		name := f.Name
		if name == "" {
			name = f.VulnClass
		}
		out = append(out, FindingGateSummary{FindingID: f.ID, Name: name, Verdict: v.State, Reasons: v.Reasons})
	}
	return out
}

// ErrFindingGateBlocked 便于上层用 errors.Is 判断"是门挡的"而不是别的原因。
var ErrFindingGateBlocked = errors.New("finding 未通过 0day 准入门的验证")

// FormatGateReasons 把原因拼成一行（给 HTTP 错误信息用）。
func FormatGateReasons(reasons []string) string {
	out := ""
	for i, r := range reasons {
		if i > 0 {
			out += "；"
		}
		out += fmt.Sprintf("%d) %s", i+1, r)
	}
	return out
}

// UpsertFindingPoc 写入/覆盖一条 finding 的触发验证记录（一条 finding 只保留最新一份）。
func (d *DB) UpsertFindingPoc(ctx context.Context, findingID int64, p vulngate.Poc) (vulngate.Poc, error) {
	if findingID <= 0 {
		return p, errors.New("finding_id 必须为正")
	}
	var exists bool
	if err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1)`, findingID).Scan(&exists); err != nil {
		return p, err
	}
	if !exists {
		return p, sql.ErrNoRows
	}
	expectContains, err := json.Marshal(p.ExpectBodyContains)
	if err != nil {
		return p, err
	}
	_, err = d.ExecContext(ctx, `
		INSERT INTO finding_pocs (finding_id, kind, input, expected, observed, reproduced, evidence, expect_status, expect_body_contains)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (finding_id) DO UPDATE SET
			kind=EXCLUDED.kind, input=EXCLUDED.input, expected=EXCLUDED.expected,
			observed=EXCLUDED.observed, reproduced=EXCLUDED.reproduced,
			evidence=EXCLUDED.evidence, expect_status=EXCLUDED.expect_status,
			expect_body_contains=EXCLUDED.expect_body_contains, updated_at=now()`,
		findingID, p.Kind, p.Input, p.Expected, p.Observed, p.Reproduced, p.Evidence,
		p.ExpectStatus, string(expectContains))
	return p, err
}

// GetFindingPoc 返回一条 finding 的触发验证记录；没有时返回 (nil, nil)。
func (d *DB) GetFindingPoc(ctx context.Context, findingID int64) (*vulngate.Poc, error) {
	var p vulngate.Poc
	var expectContains string
	err := d.QueryRowContext(ctx, `
		SELECT kind, input, expected, observed, reproduced, evidence, expect_status, expect_body_contains
		FROM finding_pocs WHERE finding_id=$1`, findingID).
		Scan(&p.Kind, &p.Input, &p.Expected, &p.Observed, &p.Reproduced, &p.Evidence, &p.ExpectStatus, &expectContains)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(expectContains), &p.ExpectBodyContains)
	return &p, nil
}

// DeleteFindingPoc 删除触发验证记录（PoC 会随 finding 级联删除，这里用于主动撤回）。
func (d *DB) DeleteFindingPoc(ctx context.Context, findingID int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM finding_pocs WHERE finding_id=$1`, findingID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// loadPocs 是批量评估用的 PoC 预取。
func (d *DB) loadPocs(ctx context.Context, ids []int64) (map[int64]*vulngate.Poc, error) {
	out := map[int64]*vulngate.Poc{}
	rows, err := d.QueryContext(ctx, `
		SELECT finding_id, kind, input, expected, observed, reproduced, evidence, expect_status, expect_body_contains
		FROM finding_pocs WHERE finding_id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var fid int64
		var p vulngate.Poc
		var expectContains string
		if err := rows.Scan(&fid, &p.Kind, &p.Input, &p.Expected, &p.Observed, &p.Reproduced, &p.Evidence, &p.ExpectStatus, &expectContains); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(expectContains), &p.ExpectBodyContains)
		pp := p
		out[fid] = &pp
	}
	return out, rows.Err()
}

// FindingPocReplay 是一次平台代执行的 PoC 重放记录（机器证据，保留每一次尝试）。
type FindingPocReplay struct {
	ID         int64     `json:"id,omitempty"`
	TrafficID  string    `json:"traffic_id"`
	StatusCode int       `json:"status_code"`
	Matched    bool      `json:"matched"`
	Detail     string    `json:"detail"`
	CreatedAt  time.Time `json:"created_at"`
}

// AddFindingPocReplay 落一条重放记录。
func (d *DB) AddFindingPocReplay(ctx context.Context, findingID int64, r FindingPocReplay) (FindingPocReplay, error) {
	if findingID <= 0 {
		return r, errors.New("finding_id 必须为正")
	}
	var exists bool
	if err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1)`, findingID).Scan(&exists); err != nil {
		return r, err
	}
	if !exists {
		return r, sql.ErrNoRows
	}
	err := d.QueryRowContext(ctx, `
		INSERT INTO finding_poc_replays (finding_id, traffic_id, status_code, matched, detail)
		VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at`,
		findingID, r.TrafficID, r.StatusCode, r.Matched, r.Detail).Scan(&r.ID, &r.CreatedAt)
	return r, err
}

// ListFindingPocReplays 按写入倒序返回重放记录（最新的在前）。
func (d *DB) ListFindingPocReplays(ctx context.Context, findingID int64) ([]FindingPocReplay, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT id, traffic_id, status_code, matched, detail, created_at
		FROM finding_poc_replays WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingPocReplay
	for rows.Next() {
		var r FindingPocReplay
		if err := rows.Scan(&r.ID, &r.TrafficID, &r.StatusCode, &r.Matched, &r.Detail, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountFindingPocReplays 返回该 finding 的重放总次数与一致次数。
func (d *DB) CountFindingPocReplays(ctx context.Context, findingID int64) (total, matched int, err error) {
	err = d.QueryRowContext(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE matched)
		FROM finding_poc_replays WHERE finding_id=$1`, findingID).Scan(&total, &matched)
	return total, matched, err
}

// UpdateFindingPocVerification 用机器重放结果回填 observed / evidence 与复现次数。
// 只写这几列：kind/input/expected 是人的判断，不能被重放覆盖。
func (d *DB) UpdateFindingPocVerification(ctx context.Context, findingID int64, reproduced int, observed, evidence string) error {
	res, err := d.ExecContext(ctx, `
		UPDATE finding_pocs SET reproduced=$2, observed=$3, evidence=$4, updated_at=now()
		WHERE finding_id=$1`, findingID, reproduced, observed, evidence)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// noveltyOrigin 归一化检索记录的来源标记（只认 manual / platform）。
func noveltyOrigin(o string) string {
	switch o {
	case "platform":
		return "platform"
	case "manual", "":
		return "manual"
	default:
		return "manual"
	}
}
