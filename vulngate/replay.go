package vulngate

// PoC 平台重放：把 Poc.Input 变成一条**真实请求**，由平台经过录制代理执行，用真实
// 流量回填 observed / evidence。
//
// 为什么需要它：门三要求"≥2 次连续复现"，但复现次数是操作员/agent 自己填的数字。
// 一个愿意造假的模型可以只写 `reproduced: 2` 就过门——门三道因此只是"必须留痕"，
// 而不是"必须真的跑过"。重放把这一环也变成工程强制：平台自己发包、自己记录、自己
// 判定"与预期一致"，复现次数由机器累加，而不是手填。
//
// 只解析、不执行：真正的网络 IO 在 server 层（走录制代理，受 L3 判定管辖）。
// 平台**不**代跑 command/file/sample 类 PoC——那涉及在宿主机执行目标代码，属于
// 另一类风险（也超出"在线域"的范围）。

import (
	"fmt"
	"net/url"
	"strings"
)

// ReplayRequest 是从 PoC input 解析出来的一条可执行请求。
type ReplayRequest struct {
	Method  string
	Scheme  string
	Host    string
	Path    string // path + query
	Headers map[string]string
	Body    []byte
}

// URL 拼出请求的完整 URL。
func (r *ReplayRequest) URL() string {
	return r.Scheme + "://" + r.Host + r.Path
}

// ReplayResult 是一次平台重放的真实结果（由 server 层填充）。
type ReplayResult struct {
	Status    int
	Body      string // 截断后的响应体（用于机器判定）
	Headers   map[string]string
	TrafficID string // 录制代理落下的流量 id（没取到时为空）
	Denied    string // 非空表示被 L3 判定拦下、没有真正到达目标
	Detail    string // 人可读的执行摘要（耗时/字节数/重定向等）
}

// ParseReplayRequest 解析两种输入形态：
//
//  1. 原始 HTTP 请求（Burp/DevTools 复制）：`GET /api/user HTTP/1.1` + Host 头 +
//     空行 + body。请求行里直接写绝对 URL 也可以（`GET https://host/path HTTP/1.1`）。
//     默认 scheme 为 https；要打明文 http 时加一行 `X-ArtEx-Scheme: http`。
//  2. 单行 URL：`https://host/path` → GET。
//
// 解析失败要给"人能照着改"的错误，而不是 `invalid input`。
func ParseReplayRequest(input string) (*ReplayRequest, error) {
	s := strings.TrimSpace(strings.ReplaceAll(input, "\r\n", "\n"))
	if s == "" {
		return nil, fmt.Errorf("PoC input 为空：需要可复制粘贴的请求或 URL")
	}
	firstLine := s
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		firstLine = strings.TrimSpace(s[:i])
	}
	if strings.HasPrefix(firstLine, "http://") || strings.HasPrefix(firstLine, "https://") {
		if !strings.Contains(s, "\n") {
			return requestFromTarget(firstLine, "GET", nil, nil)
		}
	}

	head, body := s, ""
	if i := strings.Index(s, "\n\n"); i >= 0 {
		head, body = s[:i], s[i+2:]
	}
	lines := strings.Split(head, "\n")
	reqLine := strings.Fields(strings.TrimSpace(lines[0]))
	if len(reqLine) < 2 {
		return nil, fmt.Errorf("请求行无法解析（应形如 `GET /path HTTP/1.1`）：%q", lines[0])
	}
	method := strings.ToUpper(reqLine[0])
	target := reqLine[1]
	headers := map[string]string{}
	for _, ln := range lines[1:] {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			return nil, fmt.Errorf("请求头无法解析：%q", ln)
		}
		headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return requestFromTarget(target, method, headers, []byte(body))
}

func requestFromTarget(target, method string, headers map[string]string, body []byte) (*ReplayRequest, error) {
	if headers == nil {
		headers = map[string]string{}
	}
	scheme := "https"
	for k, v := range headers {
		if strings.EqualFold(k, "X-ArtEx-Scheme") {
			scheme = strings.ToLower(strings.TrimSpace(v))
		}
	}

	var u *url.URL
	var err error
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err = url.Parse(target)
	} else {
		host := ""
		for k, v := range headers {
			if strings.EqualFold(k, "Host") {
				host = strings.TrimSpace(v)
			}
		}
		if host == "" {
			return nil, fmt.Errorf("请求行是相对路径 %q 且没有 Host 头：重放需要知道打到哪台机器", target)
		}
		u, err = url.Parse(scheme + "://" + host + target)
	}
	if err != nil {
		return nil, fmt.Errorf("URL 无法解析：%v", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL 缺少 host：%q", target)
	}
	if strings.HasPrefix(u.Scheme, "http") {
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("只支持 http/https 重放，收到 %q", u.Scheme)
		}
	} else {
		return nil, fmt.Errorf("只支持 http/https 重放，收到 %q", u.Scheme)
	}

	out := &ReplayRequest{
		Method:  method,
		Scheme:  u.Scheme,
		Host:    u.Host,
		Path:    u.RequestURI(),
		Headers: map[string]string{},
		Body:    body,
	}
	for k, v := range headers {
		switch {
		case strings.EqualFold(k, "Host"),
			strings.EqualFold(k, "Content-Length"),
			strings.EqualFold(k, "Connection"),
			strings.EqualFold(k, "X-ArtEx-Scheme"):
			continue
		}
		out.Headers[k] = v
	}
	return out, nil
}

// MatchExpectation 用机器可判的预期（expect_status / expect_body_contains）判断这次
// 重放是否复现了漏洞，并返回不一致项。没有 expect_status 时无法自动判定——这不是
// "通过"，而是"预期没写清楚"，由调用方按参数错误处理。
func MatchExpectation(p Poc, res ReplayResult) (bool, []string) {
	var mismatch []string
	if res.Denied != "" {
		mismatch = append(mismatch, "请求被规范执行层拦下，未到达目标："+res.Denied)
	}
	switch {
	case p.ExpectStatus <= 0:
		mismatch = append(mismatch, "PoC 未设置 expect_status，无法机器判定是否复现")
	case res.Status != p.ExpectStatus:
		mismatch = append(mismatch, fmt.Sprintf("状态码不符：期望 %d，实际 %d", p.ExpectStatus, res.Status))
	}
	body := strings.ToLower(res.Body)
	for _, frag := range p.ExpectBodyContains {
		frag = strings.TrimSpace(frag)
		if frag == "" {
			continue
		}
		if !strings.Contains(body, strings.ToLower(frag)) {
			mismatch = append(mismatch, fmt.Sprintf("响应体不含 %q", frag))
		}
	}
	return len(mismatch) == 0, mismatch
}
