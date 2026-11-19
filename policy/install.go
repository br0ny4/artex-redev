package policy

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// NetResolver 用系统 DNS 做解析，并为判定结果加一层 TTL 缓存。
//
// 代理出口上每个请求都要判范围，如果每次都做 DNS，吞吐会被解析拖死；同时缓存也让
// "解析结果钉住"这件事成立——判定用的 IP 与实际连接的 IP 之间不会因为 DNS 轮转而漂移
// （也顺带压掉 DNS rebinding 的时间窗）。失败结果也缓存，但 TTL 更短。
type NetResolver struct {
	ttl     time.Duration
	failTTL time.Duration

	mu      sync.Mutex
	entries map[string]resolverEntry

	// 可注入，便于测试；为 nil 时走 net.DefaultResolver。
	lookupCNAME func(ctx context.Context, host string) (string, error)
	lookupIP    func(ctx context.Context, host string) ([]net.IP, error)
}

type resolverEntry struct {
	cname  string
	ips    []net.IP
	err    error
	expire time.Time
}

// NewNetResolver 构造带缓存的解析器。ttl<=0 时用默认 5 分钟。
func NewNetResolver(ttl time.Duration) *NetResolver {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &NetResolver{ttl: ttl, failTTL: 30 * time.Second, entries: map[string]resolverEntry{}}
}

// LookupAll 一次返回 CNAME 与 IP，命中缓存时零网络开销。
func (r *NetResolver) LookupAll(ctx context.Context, host string) (string, []net.IP, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	now := time.Now()
	r.mu.Lock()
	if e, ok := r.entries[host]; ok && now.Before(e.expire) {
		r.mu.Unlock()
		return e.cname, e.ips, e.err
	}
	r.mu.Unlock()

	cname, cnameErr := r.cnameFn()(ctx, host)
	ips, ipErr := r.ipFn()(ctx, host)
	err := ipErr
	if err == nil && cnameErr != nil {
		// CNAME 查询失败但 A 记录可用时不致命：没有 CNAME 就只按 IP 判。
		cname = ""
	}
	e := resolverEntry{cname: cname, ips: ips, err: err}
	if ipErr != nil || cnameErr != nil {
		e.expire = now.Add(r.failTTL)
	} else {
		e.expire = now.Add(r.ttl)
	}
	r.mu.Lock()
	if r.entries == nil {
		r.entries = map[string]resolverEntry{}
	}
	r.entries[host] = e
	r.mu.Unlock()
	return cname, ips, err
}

func (r *NetResolver) cnameFn() func(context.Context, string) (string, error) {
	if r.lookupCNAME != nil {
		return r.lookupCNAME
	}
	return func(ctx context.Context, host string) (string, error) {
		return net.DefaultResolver.LookupCNAME(ctx, host)
	}
}

func (r *NetResolver) ipFn() func(context.Context, string) ([]net.IP, error) {
	if r.lookupIP != nil {
		return r.lookupIP
	}
	return func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		out := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, a.IP)
		}
		return out, nil
	}
}

// LookupCNAME / LookupIP 满足 Resolver 接口（内部共享同一份缓存）。
func (r *NetResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	c, _, err := r.LookupAll(ctx, host)
	return c, err
}

func (r *NetResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	_, ips, err := r.LookupAll(ctx, host)
	return ips, err
}

// InstallFromFile 读取 deployment-context YAML，构造引擎并安装为全局默认。
// 用于 `ARTEX_ENGAGEMENT_FILE=/path/to/context.yaml artex ...` 的启动方式。
//
// 失败不安装（保持上游原行为，即无策略），调用方应把它视为"在线域未启用"。
func InstallFromFile(path string) (*Engine, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("部署上下文路径为空")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取部署上下文 %s: %w", path, err)
	}
	eng, err := LoadEngagement(raw)
	if err != nil {
		return nil, err
	}
	// 域包选择：部署上下文里的 engagement.pack 优先，ARTEX_POLICY_PACK 可覆盖
	// （同一份上下文在评测环境里换包跑时用）。不认识的包名直接报错，不回退默认，
	// 否则会用 A 域策略跑 B 域作业，而且没人会发现。
	pack := strings.TrimSpace(eng.Pack)
	if v := strings.TrimSpace(os.Getenv("ARTEX_POLICY_PACK")); v != "" {
		pack = v
	}
	cfg, err := PackConfig(pack)
	if err != nil {
		return nil, err
	}
	lx, err := PackLexicon(pack)
	if err != nil {
		return nil, err
	}
	e, err := New(cfg, lx, eng, NewNetResolver(5*time.Minute))
	if err != nil {
		return nil, err
	}
	Install(e)
	return e, nil
}
