package policy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// secretPattern 是规范 5.4「敏感信息命中即停」的一条特征。
type secretPattern struct {
	Kind string
	Re   *regexp.Regexp
}

// LoadSecretPatterns 解析 patterns/secret.txt（每行 `<type>\t<regex>`）。
// 全部规则必须可编译——RE2 不支持 lookaround，写错了在这里就暴露，不会带病上线。
func LoadSecretPatterns(raw string) ([]secretPattern, error) {
	var out []secretPattern
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		parts := strings.SplitN(s, "\t", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("secret.txt 第 %d 行格式错误（应为 type<TAB>regex）", line)
		}
		re, err := regexp.Compile(parts[1])
		if err != nil {
			return nil, fmt.Errorf("secret.txt 第 %d 行正则无效（%s）: %w", line, parts[0], err)
		}
		out = append(out, secretPattern{Kind: parts[0], Re: re})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ResponseInfo 是待检查的响应。
type ResponseInfo struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

// ContentVerdict 是响应检查结果。
type ContentVerdict struct {
	Hold        bool
	Rule        string
	Reason      string
	SecretTypes []string
	PIICount    int
	Rows        int
	Bytes       int
}

// InspectResponse 实现规范 5.1 / 5.3 / 5.4：
//   - 超过单响应体上限 → 视为拖取；
//   - 命中源码/配置/密钥/DSN 等强特征 → 立即停止，只登记类型；
//   - PII 达到计数阈值 → 计入主动获取预算。
//
// 命中即停的语义是 Hold（任务级挂起），不是 deny 单条请求。
func (e *Engine) InspectResponse(resp ResponseInfo) ContentVerdict {
	v := ContentVerdict{Bytes: len(resp.Body)}
	if len(resp.Body) == 0 {
		return v
	}
	limitBytes := int64(e.cfg.Response.MaxBodyMB * 1024 * 1024)
	if limitBytes > 0 && int64(len(resp.Body)) > limitBytes {
		v.Hold = true
		v.Rule = "R2_bulk_export"
		v.Reason = fmt.Sprintf("单响应体 %d 字节超过上限 %.0fMB，视为拖取数据（规范 5.3）", len(resp.Body), e.cfg.Response.MaxBodyMB)
		return v
	}

	if e.cfg.Response.StopOnSecretPatterns {
		// 只在文本类响应上跑正则，二进制直接跳过（避免无意义的 CPU 开销）。
		if isTextual(resp.ContentType, resp.Body) {
			for _, p := range e.secretPatterns {
				if p.Re.Match(resp.Body) {
					v.Hold = true
					v.Rule = "R5_sensitive_hit"
					v.SecretTypes = append(v.SecretTypes, p.Kind)
					if len(v.SecretTypes) >= 8 {
						break
					}
				}
			}
			if v.Hold {
				v.Reason = "响应命中敏感信息（源码/配置/凭据），立即停止，报告只登记类型与位置，不落全文（规范 5.4）：" +
					strings.Join(v.SecretTypes, ", ")
				return v
			}
		}
	}

	v.Rows = countRows(resp.Body, e.cfg.Response.RowCounting.SampleRowsMax)
	if e.cfg.Response.PIIDetector.Enabled && isTextual(resp.ContentType, resp.Body) {
		hits := 0
		for _, p := range e.secretPatterns {
			if !strings.HasPrefix(p.Kind, "pii_") {
				continue
			}
			hits += len(p.Re.FindAll(resp.Body, 64))
		}
		v.PIICount = hits
		if hits > 0 && hits >= e.cfg.Response.PIIDetector.MinHitsToCount && e.cfg.Response.PIIDetector.MinHitsToCount > 0 {
			v.Rule = "PII_counted"
		}
	}
	return v
}

// isTextual 粗略判断是否为文本响应。
func isTextual(ct string, body []byte) bool {
	ct = strings.ToLower(ct)
	if ct != "" {
		for _, t := range []string{"json", "xml", "text", "javascript", "html", "x-www-form-urlencoded", "yaml", "csv"} {
			if strings.Contains(ct, t) {
				return true
			}
		}
		return false
	}
	// 无 content-type 时按可打印比例判断
	sample := body
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	printable := 0
	for _, b := range sample {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7f) || b >= 0x80 {
			printable++
		}
	}
	return printable*100/max(1, len(sample)) > 90
}

// countRows 估算响应里的记录条数：JSON 数组长度，或对象里的 total/count 字段。
// 规范 5.1：证明规模用计数不取数。
func countRows(body []byte, sampleMax int) int {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return 0
	}
	return rowsOf(v, sampleMax)
}

func rowsOf(v any, sampleMax int) int {
	switch t := v.(type) {
	case []any:
		return len(t)
	case map[string]any:
		for _, k := range []string{"total", "count", "totalCount", "totalElements", "recordsTotal"} {
			if n, ok := t[k]; ok {
				if f, ok := toFloat(n); ok {
					return int(f)
				}
			}
		}
		// data/items/list 里再找一层
		for _, k := range []string{"data", "items", "list", "records", "rows", "result"} {
			if sub, ok := t[k]; ok {
				if n := rowsOf(sub, sampleMax); n > 0 {
					return n
				}
			}
		}
	}
	return 0
}
