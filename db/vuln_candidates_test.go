package db

import (
	"context"
	"testing"

	"github.com/br0ny4/artex-redev/vulnpipe"
)

// TestVulnCandidateLifecycle 覆盖候选存取、路径增删、核对结果与转结论。
func TestVulnCandidateLifecycle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	tk, err := d.CreateTask("候选流水线测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)

	if _, err := d.CreateVulnCandidate(ctx, tk.ID, 0, vulnpipe.CandidateInput{Title: "缺位置"}); err == nil {
		t.Fatal("缺少 location 的候选应被拒")
	}
	id, err := d.CreateVulnCandidate(ctx, tk.ID, 0, vulnpipe.CandidateInput{
		Title:    "订单查询 id 直接拼 SQL",
		Kind:     vulnpipe.KindSink,
		Location: "GET /api/order/detail?id=1",
		Entry:    "id 查询参数",
		Sink:     "SELECT * FROM orders WHERE id=" + "id",
		Hops: []vulnpipe.HopInput{
			{RefKind: vulnpipe.HopTraffic, Ref: "t-1", Claim: "入口请求"},
			{RefKind: "unknown-kind", Ref: "src/x.go:12", Claim: "源码汇点"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.GetVulnCandidate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if c.TaskID != tk.ID || c.Kind != vulnpipe.KindSink || len(c.Hops) != 2 {
		t.Fatalf("落库字段不对: %+v", c)
	}
	if c.Reachability != vulnpipe.ReachClaimed || c.Unverified != 2 {
		t.Fatalf("未核对路径应为 claimed/2, got %s/%d", c.Reachability, c.Unverified)
	}
	if c.Hops[1].RefKind != vulnpipe.HopOther {
		t.Errorf("未知 ref_kind 应归一化为 other, got %q", c.Hops[1].RefKind)
	}
	// 核对一跳后 partial，两跳后 verified。
	if err := d.SetVulnCandidateHopVerification(ctx, c.Hops[0].ID, true, "traffic t-1 · GET /api/order/detail?id=1 HTTP/1.1"); err != nil {
		t.Fatal(err)
	}
	c, _ = d.GetVulnCandidate(ctx, id)
	if c.Reachability != vulnpipe.ReachPartial || c.VerifiedHops != 1 {
		t.Fatalf("一跳核对后应为 partial/1, got %s/%d", c.Reachability, c.VerifiedHops)
	}
	if err := d.SetVulnCandidateHopVerification(ctx, c.Hops[1].ID, true, "源码 /repo/x.go:12"); err != nil {
		t.Fatal(err)
	}
	c, _ = d.GetVulnCandidate(ctx, id)
	if c.Reachability != vulnpipe.ReachVerified {
		t.Fatalf("两跳核对后应为 verified, got %s", c.Reachability)
	}

	// 追加/删除跳。
	hid, err := d.AddVulnCandidateHop(ctx, id, vulnpipe.HopInput{RefKind: vulnpipe.HopCommand, Ref: "curl http://x", Claim: "触发命令"})
	if err != nil {
		t.Fatal(err)
	}
	c, _ = d.GetVulnCandidate(ctx, id)
	if len(c.Hops) != 3 || c.Reachability != vulnpipe.ReachPartial {
		t.Fatalf("追加未核对跳后应回到 partial/3, got %s/%d", c.Reachability, len(c.Hops))
	}
	if err := d.DeleteVulnCandidateHop(ctx, id, hid); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteVulnCandidateHop(ctx, id, hid); err == nil {
		t.Fatal("重复删除应报错")
	}

	// 候选转结论：关联 finding 后 status=converted。
	es := d.Exploration(tk.ExplorationID)
	nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x", "severity": "high"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := d.AddFinding(tk.ID, nodeID, "SQLi", "订单查询 SQL 注入", "high", "summary", "poc", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.LinkVulnCandidateFinding(ctx, id, fid); err != nil {
		t.Fatal(err)
	}
	c, _ = d.GetVulnCandidate(ctx, id)
	if c.FindingID != fid || c.Status != "converted" {
		t.Fatalf("转结论后应为 converted/finding=%d, got %s/%d", fid, c.Status, c.FindingID)
	}
	byFinding, err := d.ListVulnCandidatesByFinding(ctx, fid)
	if err != nil || len(byFinding) != 1 {
		t.Fatalf("按 finding 反查失败: %v len=%d", err, len(byFinding))
	}
	if err := d.LinkVulnCandidateFinding(ctx, id, 1<<40); err == nil {
		t.Fatal("关联不存在的 finding 应报错")
	}

	// 状态白名单。
	if err := d.SetVulnCandidateStatus(ctx, id, "bogus"); err == nil {
		t.Fatal("非法状态应被拒")
	}
	if err := d.SetVulnCandidateStatus(ctx, id, "dismissed"); err != nil {
		t.Fatal(err)
	}
	list, err := d.ListVulnCandidates(ctx, tk.ID, 10)
	if err != nil || len(list) != 1 || list[0].Status != "dismissed" {
		t.Fatalf("按任务列候选失败: %v len=%d", err, len(list))
	}
}
