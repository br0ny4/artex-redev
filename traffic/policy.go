package traffic

// 本文件把规范执行层（policy 包）接到代理出口（L3）：
//   - 请求发出前判定：范围 / 语义分级 / 预算 / 红线。命中则**不发包**，直接回一个
//     平台管控响应（403 + 明确说明），并把这次尝试记进流量索引当证据；
//   - 响应返回后检查：体积 / 敏感信息（源码、配置、密钥）/ 行数 / PII。命中则
//     **不把原文交给 agent**，替换成一条说明，原文不落任何会被模型看到的位置。
//
// 为什么必须在代理层做：提示词可以被目标页面、工具返回、上下文注入说服；代理层看到的是
// 请求真实要去哪里、带什么语义，模型改不了。规范第九章第 3 条要求的"工程层硬约束"。
//
// 未安装引擎（policy.Install(nil)）时本文件全部逻辑为空操作，行为与上游一致。

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/br0ny4/artex-redev/policy"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// requestView 把代理请求转成 policy 判定输入。
func requestView(r *mproxy.Request) policy.Request {
	v := policy.Request{Method: r.Method, Header: r.Header, Body: r.Body}
	if r.URL != nil {
		v.Host = r.URL.Hostname()
		v.Path = r.URL.Path
		v.Query = r.URL.Query()
	}
	return v
}

// decideRequestPolicy 是纯判定（不落库、不发包），便于单测。
// 返回的 second 值表示是否应阻断。
func decideRequestPolicy(eng *policy.Engine, f *mproxy.Flow) (policy.Decision, bool) {
	if eng == nil || f == nil || f.Request == nil || f.Request.URL == nil {
		return policy.Decision{Action: policy.ActionAllow}, false
	}
	dec := eng.DecideRequest(context.Background(), "", requestView(f.Request))
	if dec.Action == policy.ActionAllow {
		return dec, false
	}
	// warn 模式：只记录不阻断（观测期用来量化误拦率）。
	if !eng.Enforcing() {
		log.Printf("[policy][warn] %s %s -> %s：%s", f.Request.Method, f.Request.URL, dec.Rule, dec.Reason)
		return dec, false
	}
	return dec, true
}

// applyRequestPolicy 在 Addon.Request 阶段执行；返回 true 表示请求已被阻断。
func (s *sink) applyRequestPolicy(f *mproxy.Flow) bool {
	eng := policy.Default()
	dec, block := decideRequestPolicy(eng, f)
	if !block {
		return false
	}
	f.Response = &mproxy.Response{
		StatusCode: http.StatusForbidden,
		Header: http.Header{
			"Content-Type":   []string{"text/plain; charset=utf-8"},
			"X-ArtEx-Policy": []string{dec.Rule},
			"Cache-Control":  []string{"no-store"},
		},
		Body: []byte(policyBlockMessage(dec)),
	}
	log.Printf("[policy][deny] %s %s -> %s：%s", f.Request.Method, f.Request.URL, dec.Rule, dec.Reason)
	// 阻断尝试同样入流量索引：既是审计证据，也方便排查误拦。
	s.t.record(f)
	return true
}

// applyResponsePolicy 在 Addon.Response 阶段执行：命中即停的内容不交给 agent。
func (s *sink) applyResponsePolicy(f *mproxy.Flow) {
	if f == nil || f.Request == nil || f.Response == nil || f.Stream {
		return
	}
	eng := policy.Default()
	if eng == nil || len(f.Response.Body) == 0 {
		return
	}
	v := eng.InspectResponse(policy.ResponseInfo{
		StatusCode:  f.Response.StatusCode,
		ContentType: f.Response.Header.Get("Content-Type"),
		Body:        f.Response.Body,
	})
	if !v.Hold {
		// PII 计数只记账不阻断（规范 5.3 允许累计获取，到上限才停）。
		if v.PIICount > 0 {
			eng.Budget().Add(policy.BudgetKey{}, "pii_active_fetch", float64(v.PIICount))
		}
		return
	}
	if !eng.Enforcing() {
		log.Printf("[policy][hold-warn] %s %s -> %s：%s", f.Request.Method, f.Request.URL, v.Rule, v.Reason)
		return
	}
	origLen := len(f.Response.Body)
	f.Response.Body = []byte(policyHoldMessage(v))
	f.Response.Header.Set("Content-Type", "text/plain; charset=utf-8")
	f.Response.Header.Set("X-ArtEx-Policy", v.Rule)
	f.Response.Header.Del("Content-Length")
	f.Response.Header.Del("Content-Encoding")
	log.Printf("[policy][hold] %s %s -> %s：%s（原文 %d 字节未进入模型上下文）",
		f.Request.Method, f.Request.URL, v.Rule, v.Reason, origLen)
}

// policyBlockMessage / policyHoldMessage 的措辞与 guard.systemBlockMessage 一致：
// 明确告诉 agent 这是平台策略，不是目标站点的防御，避免它把拦截当成 WAF 去绕过。
func policyBlockMessage(dec policy.Decision) string {
	return fmt.Sprintf("【ARTEX 平台管控·非目标防御】此请求被平台拦截，未发送到目标。\n"+
		"规则：%s\n原因：%s\n\n"+
		"这不是目标站点的防护，重试、改编码、换路径都不会通过——请改换思路或向操作员确认。",
		dec.Rule, dec.Reason)
}

func policyHoldMessage(v policy.ContentVerdict) string {
	return fmt.Sprintf("【ARTEX 平台管控·响应已被截断】此响应命中敏感信息即停规则，原文未返回给 Agent。\n"+
		"规则：%s\n原因：%s\n\n"+
		"如需继续，请向操作员确认；报告中只登记类型与位置，不贴全文（规范 5.4）。",
		v.Rule, v.Reason)
}
