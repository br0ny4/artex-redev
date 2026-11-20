package server

// 门二"平台代执行检索"的端到端：检索结果如实落库（origin=platform）、命中条目可复核、
// 全部检索失败时不落"干净"记录（查不动 ≠ 没撞车）。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/br0ny4/artex-redev/novelty"
)

func stubNoveltyProbe(t *testing.T, fn func(ctx context.Context, queries []string) ([]novelty.Result, error)) *[]string {
	t.Helper()
	var seen []string
	prev := noveltyProbe
	noveltyProbe = func(ctx context.Context, queries []string) ([]novelty.Result, error) {
		seen = append(seen, queries...)
		return fn(ctx, queries)
	}
	t.Cleanup(func() { noveltyProbe = prev })
	return &seen
}

func TestFindingNoveltyProbeRecordsPlatformResults(t *testing.T) {
	_, f, req := trafficEvidenceServer(t)
	fid := f.FindingID

	seen := stubNoveltyProbe(t, func(ctx context.Context, queries []string) ([]novelty.Result, error) {
		return []novelty.Result{
			{Source: "nvd", Class: "cve", Query: queries[0], Hits: []novelty.Hit{
				{Source: "nvd", ID: "CVE-2021-41524", Title: "httpd null pointer deref", URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-41524"},
			}},
			{Source: "cisa-kev", Class: "advisory", Query: queries[0]},
		}, nil
	})

	w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/probe", fid), `{"queries":["apache httpd 2.4.49 null pointer"]}`)
	if w.Code != 200 {
		t.Fatalf("probe: %d %s", w.Code, w.Body)
	}
	if len(*seen) != 1 || (*seen)[0] != "apache httpd 2.4.49 null pointer" {
		t.Fatalf("平台应把原查询透传给检索源：%v", *seen)
	}

	var out struct {
		Checks []struct {
			Query       string   `json:"query"`
			SourceClass string   `json:"source_class"`
			Origin      string   `json:"origin"`
			Hits        []string `json:"hits"`
		} `json:"checks"`
		Gate struct {
			NoveltyPlatform int      `json:"novelty_platform"`
			NoveltyQueries  int      `json:"novelty_queries"`
			SourceClasses   int      `json:"source_classes"`
			Notes           []string `json:"notes"`
		} `json:"gate"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Checks) != 2 {
		t.Fatalf("两个源各落一条记录：%+v", out.Checks)
	}
	for _, c := range out.Checks {
		if c.Origin != "platform" {
			t.Fatalf("平台代检记录必须标 origin=platform：%+v", c)
		}
	}
	if len(out.Checks[0].Hits) != 1 || !strings.Contains(out.Checks[0].Hits[0], "CVE-2021-41524") ||
		!strings.Contains(out.Checks[0].Hits[0], "https://nvd.nist.gov/vuln/detail/") {
		t.Fatalf("命中条目要带编号与可核对链接：%+v", out.Checks[0].Hits)
	}
	if out.Gate.NoveltyPlatform != 2 || out.Gate.NoveltyQueries != 1 || out.Gate.SourceClasses != 2 {
		t.Fatalf("门二统计不符：%+v", out.Gate)
	}
	if !strings.Contains(strings.Join(out.Gate.Notes, "; "), "平台代执行") {
		t.Fatalf("应提示撞车比对已由平台代执行：%v", out.Gate.Notes)
	}

	// 再查一次门状态：记录仍在，来源标记保留。
	g := decodeGate(t, req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), ""))
	if len(g.Checks()) != 2 {
		t.Fatalf("GET gate 应带出平台代检记录：%+v", g)
	}
}

func TestFindingNoveltyProbeAllFailedIs502(t *testing.T) {
	_, f, req := trafficEvidenceServer(t)
	fid := f.FindingID

	stubNoveltyProbe(t, func(ctx context.Context, queries []string) ([]novelty.Result, error) {
		return []novelty.Result{
			{Source: "nvd", Class: "cve", Query: queries[0], Err: "dial tcp: i/o timeout"},
			{Source: "cisa-kev", Class: "advisory", Query: queries[0], Err: "检索源返回 HTTP 503"},
		}, nil
	})

	w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/probe", fid), `{"queries":["some product rce"]}`)
	if w.Code != 502 {
		t.Fatalf("全部失败应 502（不是 200）：%d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "查不动不等于没撞车") {
		t.Fatalf("错误文案要说明为什么不落记录：%s", w.Body)
	}

	// 没落任何记录：gate 应仍提示"只有人工记录"（或直接没有记录）。
	g := decodeGate(t, req("GET", fmt.Sprintf("/api/exploration/findings/%d/gate", fid), ""))
	if len(g.Checks()) != 0 {
		t.Fatalf("失败不应写入撞车比对记录：%+v", g)
	}
}

func TestFindingNoveltyProbePartialFailureStillRecordsSuccesses(t *testing.T) {
	_, f, req := trafficEvidenceServer(t)
	fid := f.FindingID

	stubNoveltyProbe(t, func(ctx context.Context, queries []string) ([]novelty.Result, error) {
		return []novelty.Result{
			{Source: "nvd", Class: "cve", Query: queries[0], Hits: []novelty.Hit{{ID: "CVE-2020-0001", Title: "hit", URL: "u"}}},
			{Source: "cisa-kev", Class: "advisory", Query: queries[0], Err: "检索源返回 HTTP 500"},
		}, nil
	})

	w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/probe", fid), `{"queries":["some product rce"]}`)
	if w.Code != 200 {
		t.Fatalf("部分成功应 200 并带上 errors：%d %s", w.Code, w.Body)
	}
	var out struct {
		Checks []map[string]any    `json:"checks"`
		Errors []map[string]string `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Checks) != 1 || len(out.Errors) != 1 {
		t.Fatalf("一个成功一个失败：checks=%d errors=%d", len(out.Checks), len(out.Errors))
	}
	if out.Errors[0]["source"] != "cisa-kev" {
		t.Fatalf("失败源要如实带出：%+v", out.Errors)
	}
}

func TestFindingNoveltyProbeRejectsEmptyQueries(t *testing.T) {
	_, f, req := trafficEvidenceServer(t)
	fid := f.FindingID
	if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/probe", fid), `{"queries":[]}`); w.Code != 400 {
		t.Fatalf("空查询应 400：%d %s", w.Code, w.Body)
	}
	if w := req("POST", fmt.Sprintf("/api/exploration/findings/%d/gate/novelty/probe", fid),
		`{"queries":["a1","a2","a3","a4","a5","a6"]}`); w.Code != 400 {
		t.Fatalf("超过 5 条应 400：%d %s", w.Code, w.Body)
	}
}
