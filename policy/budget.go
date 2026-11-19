package policy

import (
	"sync"
)

// BudgetKey 标识一个计数器作用域。规范 5.3 的预算按"任务 + 目标 + 类别"计。
type BudgetKey struct {
	Engagement string
	Task       string
	Host       string
}

// Budget 是规范 5.3 与第三章的执行上限计数器。
//
// 设计要点：
//   - 只增不减（测试期间不存在"退款"），避免模型用失败请求把额度刷回来；
//   - 总额度由平台配置，不接受模型或自定义工具传入的 rate/concurrency（第三章 2）；
//   - 并发安全。
type Budget struct {
	mu     sync.Mutex
	limits map[string]float64
	used   map[BudgetKey]map[string]float64
}

// NewBudget 用配置里的上限构造计数器。未列出的名字视为不限。
func NewBudget(cfg BudgetConfig) *Budget {
	return &Budget{
		limits: map[string]float64{
			"vuln_samples":            cfg.VulnSamples,
			"internal_lateral_hosts":  cfg.InternalLateralHosts,
			"send_actions":            cfg.SendActions,
			"pii_active_fetch":        cfg.PIIActiveFetch,
			"test_accounts":           cfg.TestAccounts,
			"rate_rps_per_host":       cfg.RateRPSPerHost,
			"concurrency_per_host":    cfg.ConcurrencyPerHost,
			"retry_max":               cfg.RetryMax,
			"total_requests_per_task": cfg.TotalRequestsPerTask,
			"scanner_burst_max":       cfg.ScannerBurstMax,
			"response_body_max_mb":    cfg.ResponseBodyMaxMB,
		},
		used: map[BudgetKey]map[string]float64{},
	}
}

// ApplyOverrides 应用 engagement 的收紧项。规范：只能比默认更严，更松的覆盖被忽略
// 并记录（返回被忽略的键）。
func (b *Budget) ApplyOverrides(over map[string]any) []string {
	var ignored []string
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, v := range over {
		n, ok := toFloat(v)
		if !ok {
			ignored = append(ignored, k)
			continue
		}
		cur, exists := b.limits[k]
		if exists && n > cur {
			ignored = append(ignored, k)
			continue
		}
		b.limits[k] = n
	}
	return ignored
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case float64:
		return t, true
	case float32:
		return float64(t), true
	}
	return 0, false
}

// Limit 返回某计数器上限（0 表示不限）。
func (b *Budget) Limit(name string) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.limits[name]
}

// Remaining 返回剩余额度；不限时返回 -1。
func (b *Budget) Remaining(k BudgetKey, name string) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	lim, ok := b.limits[name]
	if !ok || lim <= 0 {
		return -1
	}
	return lim - b.used[k][name]
}

// Exceeded 判断是否已用满。
func (b *Budget) Exceeded(k BudgetKey, name string) bool {
	rem := b.Remaining(k, name)
	return rem >= 0 && rem <= 0
}

// Reserve 预占额度：成功返回 true 并累加；超限返回 false 且不累加。
// 规范 5.3「第 5 组后硬停止」即依赖这个语义。
func (b *Budget) Reserve(k BudgetKey, name string, n float64) (bool, float64, float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	lim, ok := b.limits[name]
	if ok && lim > 0 {
		if b.used[k][name]+n > lim {
			return false, b.used[k][name], lim
		}
	}
	m := b.used[k]
	if m == nil {
		m = map[string]float64{}
		b.used[k] = m
	}
	m[name] += n
	return true, m[name], lim
}

// Add 无条件累加（用于记录型指标：响应字节、PII 命中）。
func (b *Budget) Add(k BudgetKey, name string, n float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.used[k]
	if m == nil {
		m = map[string]float64{}
		b.used[k] = m
	}
	m[name] += n
}

// Snapshot 返回某作用域的用量快照（判定入库用）。
func (b *Budget) Snapshot(k BudgetKey) map[string]float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]float64{}
	for name, v := range b.used[k] {
		out[name] = v
	}
	for name, lim := range b.limits {
		if lim > 0 {
			out["limit:"+name] = lim
		}
	}
	return out
}
