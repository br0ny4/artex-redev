// Package novelty 由平台代执行"撞车比对"检索：把查询真的发到公开漏洞库/情报源，
// 记录实际返回的条目，而不是让 agent 在报告里写"我查过，没重复"。
//
// 设计取舍：
//   - 只内置免鉴权、稳定 JSON 的源（NVD、CISA KEV），避免要求客户配 token；
//   - 检索结果只作为证据落库，是否"就是同一个漏洞"仍由人确认（机器猜错会把真 0day
//     当成重复，反过来也会放过重复项）；
//   - 网络失败不落"干净"记录：查不动 ≠ 没撞车。
package novelty

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Hit 是一条检索命中。
type Hit struct {
	Source string `json:"source"`
	ID     string `json:"id"`
	Title  string `json:"title"`
	URL    string `json:"url"`
}

// Result 是单个源对单条查询的结果。
type Result struct {
	Source string `json:"source"`
	Class  string `json:"class"` // cve | advisory | search
	Query  string `json:"query"`
	Hits   []Hit  `json:"hits"`
	Err    string `json:"error,omitempty"`
}

// Searcher 是一个可插拔的检索源（NVD / KEV / 以后接的检索 MCP）。
type Searcher interface {
	// Name 是源标识（落库的 source 字段）。
	Name() string
	// Class 是信息源类别，配合门槛要求"覆盖 ≥2 类信息源"。
	Class() string
	Search(ctx context.Context, query string) ([]Hit, error)
}

// nvdAPI 与 kevFeed 允许测试替换。
var (
	nvdAPI  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	kevFeed = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	httpClient = &http.Client{Timeout: 20 * time.Second}
)

// DefaultSearchers 是内置的免鉴权检索源。
func DefaultSearchers() []Searcher {
	return []Searcher{NVD{}, KEV{}}
}

// Probe 对每条查询跑所有源，返回逐源结果。查询为空或超过 5 条视为调用方错误。
func Probe(ctx context.Context, searchers []Searcher, queries []string) ([]Result, error) {
	if len(queries) == 0 {
		return nil, fmt.Errorf("至少需要一条检索查询")
	}
	if len(queries) > 5 {
		return nil, fmt.Errorf("一次最多 5 条查询（当前 %d 条）", len(queries))
	}
	var out []Result
	for _, q := range queries {
		q = strings.TrimSpace(q)
		if len([]rune(q)) < 3 {
			return nil, fmt.Errorf("查询 %q 太短：写清产品/版本/漏洞特征，否则检索没有意义", q)
		}
		for _, s := range searchers {
			res := Result{Source: s.Name(), Class: s.Class(), Query: q}
			hits, err := s.Search(ctx, q)
			if err != nil {
				res.Err = err.Error()
			}
			res.Hits = hits
			out = append(out, res)
		}
	}
	return out, nil
}

// ---- NVD ----

// NVD 用 keywordSearch 查 CVE 库（免鉴权，公开 API）。
type NVD struct{}

func (NVD) Name() string  { return "nvd" }
func (NVD) Class() string { return "cve" }

func (NVD) Search(ctx context.Context, query string) ([]Hit, error) {
	u := fmt.Sprintf("%s?keywordSearch=%s&resultsPerPage=5", nvdAPI, url.QueryEscape(query))
	body, err := getJSON(ctx, u)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("NVD 返回无法解析：%w", err)
	}
	hits := make([]Hit, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if v.CVE.ID == "" {
			continue
		}
		hits = append(hits, Hit{
			Source: "nvd",
			ID:     v.CVE.ID,
			Title:  truncate(enDescription(v.CVE.Descriptions), 160),
			URL:    "https://nvd.nist.gov/vuln/detail/" + v.CVE.ID,
		})
	}
	return hits, nil
}

// ---- CISA KEV ----

// KEV 查"已知被利用漏洞"目录（判断这个洞是不是已经被在野利用、早已公开）。
// 目录是全量 JSON（约 40MB），进程内缓存 6 小时，按关键词 AND 过滤。
type KEV struct{}

func (KEV) Name() string  { return "cisa-kev" }
func (KEV) Class() string { return "advisory" }

type kevEntry struct {
	CVEID           string `json:"cveID"`
	Vendor          string `json:"vendorProject"`
	Product         string `json:"product"`
	Name            string `json:"vulnerabilityName"`
	Short           string `json:"shortDescription"`
	DateAdded       string `json:"dateAdded"`
	KnownRansomware string `json:"knownRansomwareCampaignUse"`
}

var (
	kevMu      sync.Mutex
	kevCache   []kevEntry
	kevFetched time.Time
)

const kevTTL = 6 * time.Hour

func kevLoad(ctx context.Context) ([]kevEntry, error) {
	kevMu.Lock()
	defer kevMu.Unlock()
	if len(kevCache) > 0 && time.Since(kevFetched) < kevTTL {
		return kevCache, nil
	}
	body, err := getJSON(ctx, kevFeed)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vulnerabilities []kevEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("KEV 目录无法解析：%w", err)
	}
	kevCache = doc.Vulnerabilities
	kevFetched = time.Now()
	return kevCache, nil
}

func (KEV) Search(ctx context.Context, query string) ([]Hit, error) {
	entries, err := kevLoad(ctx)
	if err != nil {
		return nil, err
	}
	tokens := keywordTokens(query)
	if len(tokens) == 0 {
		return nil, nil
	}
	var hits []Hit
	for _, e := range entries {
		hay := strings.ToLower(e.CVEID + " " + e.Vendor + " " + e.Product + " " + e.Name + " " + e.Short)
		ok := true
		for _, t := range tokens {
			if !strings.Contains(hay, t) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		hits = append(hits, Hit{
			Source: "cisa-kev",
			ID:     e.CVEID,
			Title:  truncate(e.Name+"（"+e.Vendor+" "+e.Product+"，加录于 "+e.DateAdded+"）", 160),
			URL:    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
		})
		if len(hits) >= 5 {
			break
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].ID < hits[j].ID })
	return hits, nil
}

// ---- helpers ----

func getJSON(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "artex-redev-novelty-probe/1")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("检索源返回 HTTP %d", resp.StatusCode)
	}
	return body, nil
}

func enDescription(ds []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, d := range ds {
		if d.Lang == "en" && d.Value != "" {
			return d.Value
		}
	}
	if len(ds) > 0 {
		return ds[0].Value
	}
	return ""
}

func truncate(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}

// keywordTokens 把查询切成小写关键词（去掉常见虚词），KEV 用 AND 过滤。
func keywordTokens(q string) []string {
	stop := map[string]bool{"the": true, "and": true, "for": true, "with": true, "that": true, "this": true,
		"vulnerability": true, "vuln": true, "cve": true}
	var out []string
	for _, f := range strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '.'
	}) {
		f = strings.Trim(f, "-.")
		if len(f) < 3 || stop[f] {
			continue
		}
		out = append(out, f)
	}
	sort.Strings(out)
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}
