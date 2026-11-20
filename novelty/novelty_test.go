package novelty

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newNVDTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("keywordSearch"); got != "apache httpd 2.4.49" {
			t.Errorf("keywordSearch 应透传查询：%q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{"cve": map[string]any{
					"id": "CVE-2021-41524",
					"descriptions": []map[string]string{
						{"lang": "en", "value": "While fuzzing the 2.4.49 httpd, a null pointer dereference was detected."},
					},
				}},
			},
		})
	}))
	t.Cleanup(srv.Close)
	old := nvdAPI
	nvdAPI = srv.URL
	t.Cleanup(func() { nvdAPI = old })
	return srv
}

func TestNVDSearchParsesHits(t *testing.T) {
	newNVDTestServer(t)
	hits, err := NVD{}.Search(context.Background(), "apache httpd 2.4.49")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "CVE-2021-41524" {
		t.Fatalf("应解析出一个 CVE 命中：%+v", hits)
	}
	if !strings.HasPrefix(hits[0].URL, "https://nvd.nist.gov/vuln/detail/") {
		t.Fatalf("命中应带可核对链接：%+v", hits[0])
	}
}

func TestKEVSearchFiltersByKeywords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
					"vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
					"shortDescription":  "JNDI lookup allows RCE.", "dateAdded": "2021-12-10",
					"knownRansomwareCampaignUse": "Known"},
				{"cveID": "CVE-2020-0001", "vendorProject": "Other", "product": "Thing",
					"vulnerabilityName": "Unrelated", "shortDescription": "nothing", "dateAdded": "2020-01-01"},
			},
		})
	}))
	t.Cleanup(srv.Close)
	old := kevFeed
	kevFeed = srv.URL
	t.Cleanup(func() { kevFeed = old })
	kevMu.Lock()
	kevCache = nil
	kevMu.Unlock()

	hits, err := KEV{}.Search(context.Background(), "apache log4j2 rce")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "CVE-2021-44228" {
		t.Fatalf("关键词 AND 过滤应只命中 Log4j：%+v", hits)
	}
}

func TestKEVSearchMatchesVersionedQuery(t *testing.T) {
	// 真实场景：查询带版本号与 "httpd"，目录里写的是 "Apache HTTP Server Path Traversal"，
	// 版本号在 KEV 里不存在——不能因为词形不同就漏报。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{"cveID": "CVE-2021-42013", "vendorProject": "Apache", "product": "HTTP Server",
					"vulnerabilityName": "Apache HTTP Server Path Traversal Vulnerability",
					"shortDescription":  "Path traversal in mod_proxy.", "dateAdded": "2021-11-03"},
			},
		})
	}))
	t.Cleanup(srv.Close)
	old := kevFeed
	kevFeed = srv.URL
	t.Cleanup(func() { kevFeed = old })
	kevMu.Lock()
	kevCache = nil
	kevMu.Unlock()

	hits, err := KEV{}.Search(context.Background(), "apache httpd 2.4.49 path traversal")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "CVE-2021-42013" {
		t.Fatalf("带版本号/别名的查询应命中 KEV：%+v", hits)
	}
	if !strings.Contains(hits[0].Title, "匹配") {
		t.Fatalf("命中标题应写明关键词覆盖度，便于复核：%q", hits[0].Title)
	}
}

func TestKeywordTokensDropsVersions(t *testing.T) {
	toks := keywordTokens("apache httpd 2.4.49 path traversal")
	for _, tok := range toks {
		if tok == "2.4.49" || tok == "v2.4.49" {
			t.Fatalf("版本号不该参与关键词匹配：%v", toks)
		}
	}
}

func TestProbeRejectsBadQueries(t *testing.T) {
	if _, err := Probe(context.Background(), DefaultSearchers(), nil); err == nil {
		t.Fatal("空查询应报错")
	}
	if _, err := Probe(context.Background(), DefaultSearchers(), []string{"ab"}); err == nil {
		t.Fatal("过短查询应报错")
	}
	if _, err := Probe(context.Background(), DefaultSearchers(), []string{"a", "b", "c", "d", "e", "f"}); err == nil {
		t.Fatal("超过 5 条应报错")
	}
}

type fakeSearcher struct {
	name  string
	class string
	hits  []Hit
	err   error
}

func (f fakeSearcher) Name() string  { return f.name }
func (f fakeSearcher) Class() string { return f.class }
func (f fakeSearcher) Search(ctx context.Context, q string) ([]Hit, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.hits, nil
}

func TestProbeReportsPerSourceResultsAndErrors(t *testing.T) {
	searchers := []Searcher{
		fakeSearcher{name: "ok", class: "cve", hits: []Hit{{Source: "ok", ID: "CVE-1", Title: "t", URL: "u"}}},
		fakeSearcher{name: "boom", class: "advisory", err: context.DeadlineExceeded},
	}
	res, err := Probe(context.Background(), searchers, []string{"some product rce"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("每条查询应对每个源各产出一条结果：%+v", res)
	}
	if len(res[0].Hits) != 1 || res[0].Err != "" {
		t.Fatalf("正常源应带命中：%+v", res[0])
	}
	if !strings.Contains(res[1].Err, "deadline") {
		t.Fatalf("失败源要如实记录错误，不能落成\"没撞车\"：%+v", res[1])
	}
}
