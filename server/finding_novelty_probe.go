package server

// 门二的"平台代执行检索"：把撞车比对从"agent 说它查过"变成"平台真的查了，
// 返回条目在这里"。设计上刻意不替人判断"是否同一个漏洞"（机器猜错会把真 0day
// 当成重复，也会放过重复项），只保证"查过"这件事有据可查。

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/br0ny4/artex-redev/db"
	"github.com/br0ny4/artex-redev/novelty"
	"github.com/br0ny4/artex-redev/vulngate"
)

// noveltyProbe 是测试桩点：默认真的请求 NVD / CISA KEV。
var noveltyProbe = func(ctx context.Context, queries []string) ([]novelty.Result, error) {
	return novelty.Probe(ctx, novelty.DefaultSearchers(), queries)
}

type noveltyProbePayload struct {
	Queries []string `json:"queries"`
}

// probeFindingNovelty 用平台侧的检索源跑撞车比对，命中条目直接落库（origin=platform）。
// 失败不落"干净"记录：查不动 ≠ 没撞车。
func (s *Server) probeFindingNovelty(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var p noveltyProbePayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
		writeErr(w, 400, "解析请求失败: "+err.Error())
		return
	}
	queries := make([]string, 0, len(p.Queries))
	for _, q := range p.Queries {
		if q = strings.TrimSpace(q); q != "" {
			queries = append(queries, q)
		}
	}
	if len(queries) > 5 {
		writeErr(w, 400, "一次最多 5 条查询：撞车比对要的是准确检索，不是把关键词全丢给漏洞库")
		return
	}
	if len(queries) == 0 {
		writeErr(w, 400, "queries 不能为空：至少给一条检索查询（产品/版本/漏洞特征，例如 \"apache httpd 2.4.49 path traversal\"）")
		return
	}

	results, err := noveltyProbe(r.Context(), queries)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}

	var checks []vulngate.NoveltyCheck
	var failures []map[string]string
	for _, res := range results {
		if res.Err != "" {
			failures = append(failures, map[string]string{"source": res.Source, "query": res.Query, "error": res.Err})
			continue
		}
		hits := make([]string, 0, len(res.Hits))
		for _, h := range res.Hits {
			entry := h.ID
			if h.Title != "" {
				entry += " · " + h.Title
			}
			if h.URL != "" {
				entry += " <" + h.URL + ">"
			}
			hits = append(hits, entry)
		}
		n, err := s.m.pg.AddFindingNoveltyCheck(r.Context(), id, vulngate.NoveltyCheck{
			Query:       res.Query,
			SourceClass: res.Class,
			Hits:        hits,
			// 机器不替人下"就是同一个漏洞"的结论，这一条留给操作员复核后手动标记。
			SameVuln: false,
			Origin:   "platform",
		})
		if err != nil {
			if err == db.ErrFindingNotFound {
				writeErr(w, 404, "finding not found")
				return
			}
			writeErr(w, 500, err.Error())
			return
		}
		checks = append(checks, n)
	}

	if len(checks) == 0 {
		// 一个源都没成功：不能假装"没撞车"。
		writeErr(w, 502, "平台代执行检索全部失败，未记录任何撞车比对结果（查不动不等于没撞车）："+probeFailureSummary(failures))
		return
	}

	a, err := s.m.pg.FindingGateAssessment(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"results":      results,
		"checks":       checks,
		"errors":       failures,
		"gate":         vulngate.Assess(a),
		"requirements": gateRequirements(),
	})
}

func probeFailureSummary(failures []map[string]string) string {
	parts := make([]string, 0, len(failures))
	for _, f := range failures {
		parts = append(parts, f["source"]+": "+f["error"])
	}
	return strings.Join(parts, "；")
}
