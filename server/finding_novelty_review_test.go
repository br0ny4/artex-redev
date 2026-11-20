package server

// 门二"复核留痕"的端到端：平台代检把命中条目落库之后，必须有人标记
// "无同一漏洞/撞车"并留下复核人与依据；未复核的平台代检记录不计入门二。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/br0ny4/artex-redev/novelty"
)

// seedPlatformNovelty 用桩造一条平台代检记录（含命中条目），返回 finding id 与记录 id。
func seedPlatformNovelty(t *testing.T) (int64, int64, func(method, path, body string) *httptest.ResponseRecorder) {
	t.Helper()
	_, f, req := trafficEvidenceServer(t)
	fid := f.FindingID
	stubNoveltyProbe(t, func(ctx context.Context, queries []string) ([]novelty.Result, error) {
		return []novelty.Result{{
			Source: "nvd", Class: "cve", Query: queries[0],
			Hits: []novelty.Hit{{
				Source: "nvd", ID: "CVE-2021-0001", Title: "Acme Widget traversal",
				URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-0001",
			}},
		}}, nil
	})
	w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/probe", fid),
		`{"queries":["acme widget traversal"]}`)
	if w.Code != 200 {
		t.Fatalf("probe: %d %s", w.Code, w.Body)
	}
	var out struct {
		Checks []struct {
			ID int64 `json:"id"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Checks) != 1 {
		t.Fatalf("应落一条平台代检记录：%s", w.Body)
	}
	return fid, out.Checks[0].ID, req
}

func TestFindingNoveltyReviewRecordsTrail(t *testing.T) {
	fid, nid, req := seedPlatformNovelty(t)

	// 未复核：门二应明确说"平台代检记录尚未复核"。
	g := decodeGate(t, req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), ""))
	if g.Gate.NoveltyUnreviewed != 1 {
		t.Fatalf("未复核数应为 1：%+v", g.Gate)
	}
	if !strings.Contains(strings.Join(g.Gate.Reasons, "; "), "尚未复核") {
		t.Fatalf("门二原因应提示未复核：%v", g.Gate.Reasons)
	}

	// 复核人不能空：机器不替人下"不是同一漏洞"的结论。
	w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/%d/review", fid, nid),
		`{"reviewed_by":"","same_vuln":false}`)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "复核人") {
		t.Fatalf("缺复核人应 400：%d %s", w.Code, w.Body)
	}

	// 判撞车必须写依据（依据哪条命中）。
	w = req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/%d/review", fid, nid),
		`{"reviewed_by":"alice","same_vuln":true}`)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "依据") {
		t.Fatalf("撞车缺依据应 400：%d %s", w.Code, w.Body)
	}

	// 复核为"无同一漏洞"：留痕落库，门二不再因未复核阻断。
	w = req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/%d/review", fid, nid),
		`{"reviewed_by":"alice","same_vuln":false,"note":"命中是另一产品线，不构成撞车"}`)
	if w.Code != 200 {
		t.Fatalf("复核: %d %s", w.Code, w.Body)
	}
	var rv struct {
		NoveltyCheck struct {
			ReviewedBy string `json:"reviewed_by"`
			ReviewedAt string `json:"reviewed_at"`
			ReviewNote string `json:"review_note"`
		} `json:"novelty_check"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rv); err != nil {
		t.Fatal(err)
	}
	if rv.NoveltyCheck.ReviewedBy != "alice" || rv.NoveltyCheck.ReviewedAt == "" || rv.NoveltyCheck.ReviewNote == "" {
		t.Fatalf("复核留痕没落库：%+v", rv)
	}

	g = decodeGate(t, req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), ""))
	if g.Gate.NoveltyUnreviewed != 0 {
		t.Fatalf("复核后未复核数应为 0：%+v", g.Gate)
	}
	if strings.Contains(strings.Join(g.Gate.Reasons, "; "), "尚未复核") {
		t.Fatalf("复核后不该再提示未复核：%v", g.Gate.Reasons)
	}
	if got := g.Checks()[0]; got.ReviewedBy != "alice" || got.ReviewedAt == "" {
		t.Fatalf("GET gate 应带出复核留痕：%+v", got)
	}

	// 改判为撞车：门二转为撞车阻断，并带出命中编号。
	w = req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/%d/review", fid, nid),
		`{"reviewed_by":"bob","same_vuln":true,"note":"同一组件同一触发点（CVE-2021-0001）"}`)
	if w.Code != 200 {
		t.Fatalf("改判撞车: %d %s", w.Code, w.Body)
	}
	g = decodeGate(t, req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), ""))
	if !strings.Contains(strings.Join(g.Gate.Reasons, "; "), "CVE-2021-0001") {
		t.Fatalf("撞车原因应带命中条目：%v", g.Gate.Reasons)
	}

	// 不存在的记录要 404，不能静默成功。
	w = req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/99999999/review", fid),
		`{"reviewed_by":"alice","same_vuln":false}`)
	if w.Code != 404 {
		t.Fatalf("不存在的记录应 404：%d %s", w.Code, w.Body)
	}
}
