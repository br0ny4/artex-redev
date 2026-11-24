package agent

// 0day 流水线阶段 2–3 的 agent 侧验收：候选登记 → 上报漏洞时带 candidate_id → 候选转结论。
// 可达性核对在服务端，这里只保证"写路径"把候选和结论串起来（否则报告里断链）。

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/br0ny4/artex-redev/db"
)

func TestReportFindingLinksCandidate(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("candidate pipeline", "prove reachability", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	ts := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	ts.SetTaskID(task.ID)

	// 1) add_candidate 落库：标题/位置必填，路径跳可选。
	out := callReadJSON(t, ts.addCandidate(), `{"title":"订单查询 id 直接拼 SQL","kind":"sink","location":"https://shop.example.com/api/order/detail","rationale":"id 未参数化","hops":[{"ref_kind":"traffic","ref":"t-does-exist","claim":"入口请求"}]}`)
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("add_candidate 返回格式不对: %#v", out)
	}
	var candidateID int64
	switch v := m["candidate_id"].(type) {
	case float64:
		candidateID = int64(v)
	case string:
		candidateID, _ = strconv.ParseInt(v, 10, 64)
	}
	if candidateID <= 0 {
		t.Fatalf("没有拿到候选 id: %#v", out)
	}

	// 2) 缺位置必须被拒（候选不能只有一句话）。
	r, err := ts.addCandidate().Call(context.Background(), json.RawMessage(`{"title":"没有位置"}`), nil)
	if err != nil {
		t.Fatalf("add_candidate: %v", err)
	}
	if !strings.Contains(strings.ToLower(r.Flatten()), "location") {
		t.Fatalf("缺 location 应报错：%q", r.Flatten())
	}

	// 3) report_finding 带 candidate_id：漏洞照常入库，候选应变成 converted。
	res, err := ts.addFinding().Call(context.Background(), json.RawMessage(fmt.Sprintf(
		`{"vulnclass":"sqli","severity":"high","summary":"订单接口存在 SQL 注入","evidence":"id=1' 返回数据库错误","candidate_id":%d}`, candidateID)), nil)
	if err != nil {
		t.Fatalf("report_finding: %v", err)
	}
	findingID := recordedFindingID(t, res.Flatten())
	c, err := d.GetVulnCandidate(context.Background(), candidateID)
	if err != nil {
		t.Fatalf("读取候选: %v", err)
	}
	if c.Status != "converted" || c.FindingID != findingID {
		t.Fatalf("候选应转为结论并指向 finding %d: status=%s finding=%d", findingID, c.Status, c.FindingID)
	}
	if len(c.Hops) != 1 || c.Hops[0].Ref != "t-does-exist" {
		t.Fatalf("候选跳应保留: %+v", c.Hops)
	}

	// 4) 候选 id 不存在时不能丢漏洞：只加提示，漏洞仍入库。
	res, err = ts.addFinding().Call(context.Background(), json.RawMessage(`{"vulnclass":"sqli","severity":"low","summary":"另一处注入","evidence":"证据","candidate_id":99999999}`), nil)
	if err != nil {
		t.Fatalf("report_finding: %v", err)
	}
	if !strings.Contains(res.Flatten(), "候选关联失败") {
		t.Fatalf("坏 candidate_id 应只提示不丢漏洞: %q", res.Flatten())
	}
}

// recordedFindingID 从 report_finding 输出（第一行节点编号 + 第二行 JSON）取独立 finding_id。
func recordedFindingID(t *testing.T, raw string) int64 {
	t.Helper()
	parts := strings.SplitN(raw, "\n", 2)
	if len(parts) != 2 {
		t.Fatalf("report_finding 输出缺少 JSON：%q", raw)
	}
	var out struct {
		FindingID int64 `json:"finding_id,string"`
	}
	if err := json.Unmarshal([]byte(parts[1]), &out); err != nil {
		t.Fatalf("解析 report_finding 输出: %v %q", err, parts[1])
	}
	if out.FindingID <= 0 {
		t.Fatalf("finding_id 无效：%q", parts[1])
	}
	return out.FindingID
}
