package server

// PoC 平台重放：门三的"机器证据"入口。
//
// 为什么要有这一层：门三要求"连续复现 ≥2 次"，但次数是人工/agent 填的数字。愿意
// 造假的模型只写 `reproduced: 2` 就能过门。重放让平台自己发包、自己判定、自己落
// 流量：复现次数由机器累加，observed/evidence 由机器回填——"真的跑过"不再靠自觉。
//
// 设计约束：
//   - 只重放 kind=http。command/file/sample 要在宿主机执行目标代码，属于另一类
//     风险，平台不代跑（要动态行为就换沙箱，见 malware-triage 域包）。
//   - 必须经过录制代理：L1/L3 判定照常生效（范围/语义/预算），成功发出的请求被
//     录成流量，报告里的 evidence 才能指到真实请求。绕开代理的重放没有证据价值。
//   - 重放不跟随重定向：3xx 本身可能就是结论的一部分，自动跟随会掩盖真实状态码。

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/br0ny4/artex-redev/db"
	"github.com/br0ny4/artex-redev/vulngate"
)

// errReplayNoProxy 表示没有可用的录制代理（重放会失去证据链）。
var errReplayNoProxy = errors.New("录制代理未开启")

// pocReplayExecutor 是执行一次真实重放的钩子。包级变量便于测试替换成不发包的桩；
// 真实网络路径由 traffic 包的 L3 端到端用例覆盖。
var pocReplayExecutor = replayPocThroughProxy

const (
	replayTimeout    = 30 * time.Second
	replayBodyLimit  = 1 << 20 // 只读 1MB 用于判定，避免把大响应拖进内存
	replayTrafficTTL = 5 * time.Second
)

// replayPocThroughProxy 经录制代理发一次请求。
func replayPocThroughProxy(ctx context.Context, m *Manager, req *vulngate.ReplayRequest) (*vulngate.ReplayResult, error) {
	proxyAddr := m.ProxyAddr()
	if proxyAddr == "" {
		return nil, errReplayNoProxy
	}
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("录制代理地址无法解析：%v", err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath := m.ProxyCACert(); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("读取录制代理 CA 失败：%v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("录制代理 CA 文件无法解析：%s", caPath)
		}
		tlsCfg.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   tlsCfg,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   replayTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL(), bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("构造请求失败：%v", err)
	}
	for k, v := range req.Headers {
		if hopByHopHeader(k) {
			continue
		}
		httpReq.Header.Set(k, v)
	}
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", "artex-poc-replay/1.0")
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("请求未发出或连接失败：%v", err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, replayBodyLimit))
	if readErr != nil && len(body) == 0 {
		return nil, fmt.Errorf("读取响应失败：%v", readErr)
	}
	elapsed := time.Since(start)

	headers := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	res := &vulngate.ReplayResult{
		Status:  resp.StatusCode,
		Body:    string(body),
		Headers: headers,
		Denied:  resp.Header.Get("X-ArtEx-Policy"),
		Detail:  fmt.Sprintf("HTTP %d，%d 字节响应，耗时 %s", resp.StatusCode, len(body), elapsed.Round(time.Millisecond)),
	}
	if res.Denied != "" {
		res.Detail += "（被规范执行层拦下：规则 " + res.Denied + "，未到达目标）"
	}
	// 请求即使被 L3 拦下也会落索引（见 traffic/policy.go），所以失败重放同样能
	// 拿到流量 id——操作员能回查"平台当时到底发了什么/回了什么"。
	res.TrafficID = latestTrafficID(m, req)
	if res.TrafficID == "" {
		res.Detail += "（未取到流量 id：录制可能延迟或未开启）"
	}
	return res, nil
}

// hopByHopHeader 报告该请求头是否应由传输层决定（不能原样转发）。
func hopByHopHeader(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
		"content-length", "host":
		return true
	}
	return false
}

// latestTrafficID 找这次重放刚落的流量记录。不按 ts 精确比较（秒级精度不够），
// 而是取同 host+method 的最新几条里 URL 路径匹配的那条；短时间内重放同样的请求
// 时取最新一条即可——重放本身是幂等证据，不需要严格区分是第几次。
func latestTrafficID(m *Manager, req *vulngate.ReplayRequest) string {
	t := m.Traffic()
	if t == nil {
		return ""
	}
	path := req.Path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	deadline := time.Now().Add(replayTrafficTTL)
	for {
		rows, err := t.DB().Query(`
			SELECT id, url FROM exchanges
			WHERE host=? AND method=? ORDER BY ts DESC, id DESC LIMIT 8`,
			req.Host, req.Method)
		if err == nil {
			for rows.Next() {
				var id, u string
				if rows.Scan(&id, &u) != nil {
					continue
				}
				if strings.Contains(u, path) {
					rows.Close()
					return id
				}
			}
			rows.Close()
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// replayFindingPoc 是 POST /api/exploration/findings/{id}/gate/poc/replay 的 handler。
func (s *Server) replayFindingPoc(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	poc, err := s.m.pg.GetFindingPoc(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if poc == nil {
		writeErr(w, 404, "该 finding 还没有 PoC 记录：先用 PUT …/gate/poc 录入触发方式与输入，再重放")
		return
	}
	if !strings.EqualFold(poc.Kind, "http") {
		writeErr(w, 400, "只有 kind=http 的 PoC 能由平台重放；command/file/sample 涉及在宿主机执行目标代码，平台不代跑（要动态行为请换沙箱与 binary-re 域包）")
		return
	}
	if poc.ExpectStatus <= 0 {
		writeErr(w, 400, "重放需要机器可判的预期：先给 PoC 补 expect_status（可选 expect_body_contains），否则重放结果无法自动判定是否复现")
		return
	}
	req, err := vulngate.ParseReplayRequest(poc.Input)
	if err != nil {
		writeErr(w, 400, "PoC input 无法作为 HTTP 请求解析："+err.Error())
		return
	}
	if !s.m.TrafficEnabled() {
		writeErr(w, 409, "录制未开启，拒绝重放：重放必须经过录制代理，否则没有流量证据链（规范执行层启用时录制不可关闭）")
		return
	}
	res, err := pocReplayExecutor(r.Context(), s.m, req)
	if err != nil {
		if errors.Is(err, errReplayNoProxy) {
			writeErr(w, 409, "录制代理未开启，拒绝重放：重放必须经过录制代理，否则没有流量证据链")
			return
		}
		writeErr(w, 502, "重放失败："+err.Error())
		return
	}
	matched, mismatches := vulngate.MatchExpectation(*poc, *res)
	detail := res.Detail
	if len(mismatches) > 0 {
		detail += "；不一致：" + strings.Join(mismatches, "；")
	}
	rec, err := s.m.pg.AddFindingPocReplay(r.Context(), id, db.FindingPocReplay{
		TrafficID: res.TrafficID, StatusCode: res.Status, Matched: matched, Detail: detail,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 只有"与预期一致"的重放才回填 observed/evidence 并把复现次数抬到机器实测值。
	// 不一致的重放只留在重放历史里：把失败写成 observed 会覆盖掉人的判断。
	if matched {
		reproduced := poc.Reproduced
		if _, matchedCount, err := s.m.pg.CountFindingPocReplays(r.Context(), id); err == nil && matchedCount > reproduced {
			reproduced = matchedCount
		}
		observed := fmt.Sprintf("平台重放 %s %s -> HTTP %d；%s", req.Method, req.URL(), res.Status, res.Detail)
		evidence := "平台重放 traffic=" + res.TrafficID
		if res.TrafficID == "" {
			evidence = "平台重放（未取到流量 id）"
		}
		if err := s.m.pg.UpdateFindingPocVerification(r.Context(), id, reproduced, observed, evidence); err != nil {
			log.Printf("[finding-gate] 回填重放证据失败 finding=%d: %v", id, err)
		}
	}

	a, err := s.m.pg.FindingGateAssessment(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	replays, err := s.m.pg.ListFindingPocReplays(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"replay":       rec,
		"replays":      replays,
		"matched":      matched,
		"mismatches":   mismatches,
		"gate":         vulngate.Assess(a),
		"requirements": gateRequirements(),
	})
}
