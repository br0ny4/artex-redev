package policy

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// ScopeVerdict 是范围判定结果。
type ScopeVerdict string

const (
	ScopeAllow     ScopeVerdict = "allow"
	ScopeDeny      ScopeVerdict = "deny"
	ScopeAmbiguous ScopeVerdict = "ambiguous" // 归属不明 / 第三方托管 / CDN 回源 → 按范围外，需问询
	ScopeInternal  ScopeVerdict = "internal"  // 命中内网段（横向预算 0）
	ScopeMetadata  ScopeVerdict = "metadata"  // 云元数据地址
)

// Resolver 抽象 DNS 解析，便于测试注入。
type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// MultiResolver 可选：一次返回 CNAME 与 IP。实现它才能吃到解析缓存（代理出口上
// 每个请求都要判范围，逐个方法走 DNS 会把吞吐拖死）。
type MultiResolver interface {
	Resolver
	LookupAll(ctx context.Context, host string) (cname string, ips []net.IP, err error)
}

// Scope 实现第一章的授权范围判定：清单为准、未列入即范围外、
// 第三方托管/CDN 回源/归属不明按范围外、内网与元数据一律禁止。
type Scope struct {
	cfg      ScopeConfig
	allow    []hostPattern
	exclude  []hostPattern
	cidrs    []*net.IPNet
	exCIDRs  []*net.IPNet
	internal []*net.IPNet
	metadata []net.IP
	resolver Resolver
}

type hostPattern struct {
	raw    string
	suffix bool   // *.example.com
	host   string // 归一化后的 host（suffix 时为去掉 "*." 的后缀）
}

// NewScope 解析授权范围。eng 为 nil 时返回一个"全拒绝"的 Scope（没有授权就不能发包）。
func NewScope(cfg ScopeConfig, eng *Engagement, resolver Resolver) (*Scope, error) {
	s := &Scope{cfg: cfg, resolver: resolver}
	if eng != nil {
		for _, d := range eng.Scope.Domains {
			s.allow = append(s.allow, parsePattern(d))
		}
		for _, ip := range eng.Scope.IPs {
			if n := parseCIDROrIP(ip); n != nil {
				s.cidrs = append(s.cidrs, n)
			} else {
				s.allow = append(s.allow, parsePattern(ip))
			}
		}
		for _, c := range eng.Scope.CIDRs {
			if n := parseCIDROrIP(c); n != nil {
				s.cidrs = append(s.cidrs, n)
			}
		}
		for _, d := range eng.Scope.Exclude {
			s.exclude = append(s.exclude, parsePattern(d))
		}
	}
	for _, c := range cfg.InternalCIDRsDeny {
		if n := parseCIDROrIP(c); n != nil {
			s.internal = append(s.internal, n)
		}
	}
	for _, m := range cfg.MetadataDeny {
		if ip := net.ParseIP(strings.TrimSpace(m)); ip != nil {
			s.metadata = append(s.metadata, ip)
		}
	}
	return s, nil
}

func parsePattern(raw string) hostPattern {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if strings.HasPrefix(raw, "*.") {
		return hostPattern{raw: raw, suffix: true, host: strings.TrimPrefix(raw, "*.")}
	}
	return hostPattern{raw: raw, host: normalizeHost(raw)}
}

// parseCIDROrIP 兼容 "10.0.0.0/8" 与裸 IP（裸 IP 按 /32 处理）。
func parseCIDROrIP(s string) *net.IPNet {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil
		}
		return n
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
}

// normalizeHost 去掉端口、scheme、尾部点，转小写。
func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.Trim(h, "[]"), ".")
}

// CheckHost 只按清单与网段判定，不做 DNS（规范 1.1 的第一层）。
func (s *Scope) CheckHost(host string) (ScopeVerdict, string) {
	h := normalizeHost(host)
	if h == "" {
		return ScopeDeny, "空目标"
	}
	for _, p := range s.exclude {
		if p.match(h) {
			return ScopeDeny, "命中客户显式排除项 " + p.raw
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		return s.checkIP(ip)
	}
	for _, p := range s.allow {
		if p.match(h) {
			return ScopeAllow, "命中授权清单 " + p.raw
		}
	}
	for _, n := range s.cidrs {
		if ip := net.ParseIP(h); ip != nil && n.Contains(ip) {
			return ScopeAllow, "命中授权网段 " + n.String()
		}
	}
	// 规范 1.1：未列入清单、归属不明 → 按范围外处理。
	if s.cfg.AmbiguousAsOutOfScope {
		return ScopeAmbiguous, "未列入授权清单（归属不明按范围外处理，需向本方确认）"
	}
	return ScopeDeny, "未列入授权清单"
}

func (p hostPattern) match(host string) bool {
	if p.suffix {
		return host == p.host || strings.HasSuffix(host, "."+p.host)
	}
	return host == p.host
}

func (s *Scope) checkIP(ip net.IP) (ScopeVerdict, string) {
	for _, m := range s.metadata {
		if m.Equal(ip) {
			return ScopeMetadata, "云元数据地址（只证明可达，不读凭据）"
		}
	}
	for _, n := range s.internal {
		if n.Contains(ip) {
			return ScopeInternal, "命中内网段 " + n.String() + "（横向预算 0）"
		}
	}
	for _, n := range s.cidrs {
		if n.Contains(ip) {
			return ScopeAllow, "命中授权网段 " + n.String()
		}
	}
	for _, n := range s.allow {
		if n.host == ip.String() {
			return ScopeAllow, "命中授权清单 " + n.raw
		}
	}
	return ScopeDeny, "IP 未列入授权清单"
}

// CheckResolved 在 DNS 解析后做第二层判定：先看解析出的 IP 是否内网/元数据，
// 再看 CNAME 链是否指向第三方托管（CDN 回源按范围外）。
func (s *Scope) CheckResolved(host string, cnames []string, ips []net.IP) (ScopeVerdict, string) {
	if v, reason := s.CheckHost(host); v != ScopeAllow {
		return v, reason
	}
	for _, ip := range ips {
		if v, reason := s.checkIP(ip); v == ScopeInternal || v == ScopeMetadata {
			return v, reason
		}
	}
	for _, cn := range cnames {
		cn = normalizeHost(cn)
		for _, suf := range s.cfg.ThirdPartyDetect.CNAMESuffix {
			suf = strings.ToLower(strings.TrimSpace(suf))
			if suf == "" {
				continue
			}
			if strings.HasSuffix(cn, suf) {
				if s.cfg.ThirdPartyDetect.RequireExplicit {
					return ScopeAmbiguous, "CNAME 指向第三方托管 " + cn + "，按范围外处理，需显式授权"
				}
				return ScopeAllow, "CNAME " + cn
			}
		}
	}
	return ScopeAllow, "解析结果均在授权范围"
}

// ResolveAndCheck 用 Resolver 解析后判定；resolver 为 nil 时退化为 CheckHost。
func (s *Scope) ResolveAndCheck(ctx context.Context, host string) (ScopeVerdict, string) {
	if s.resolver == nil {
		return s.CheckHost(host)
	}
	h := normalizeHost(host)
	if net.ParseIP(h) != nil {
		return s.CheckHost(h)
	}
	var cnames []string
	var ips []net.IP
	var err error
	if mr, ok := s.resolver.(MultiResolver); ok {
		var cn string
		cn, ips, err = mr.LookupAll(ctx, h)
		if cn != "" {
			cnames = append(cnames, cn)
		}
	} else {
		if cn, cerr := s.resolver.LookupCNAME(ctx, h); cerr == nil && cn != "" {
			cnames = append(cnames, cn)
		}
		ips, err = s.resolver.LookupIP(ctx, h)
	}
	if err != nil && len(cnames) == 0 {
		return ScopeAmbiguous, fmt.Sprintf("DNS 解析失败：%v（归属不明按范围外）", err)
	}
	return s.CheckResolved(h, cnames, ips)
}

// EgressAllowed 判断"主机能否作为出网目的地"：只允许目标清单 + 带外域名 +
// 报告通道（红线 8：业务数据/凭据/漏洞细节只能进报告通道）。
func (s *Scope) EgressAllowed(host string) bool {
	h := normalizeHost(host)
	if v, _ := s.CheckHost(h); v == ScopeAllow {
		return true
	}
	for _, suf := range s.cfg.OutOfBandAllowSuffixes {
		suf = strings.ToLower(strings.TrimSpace(suf))
		if suf != "" && (h == strings.TrimPrefix(suf, ".") || strings.HasSuffix(h, suf)) {
			return true
		}
	}
	for _, extra := range s.cfg.EgressAllowlistExtra {
		if normalizeHost(extra) == h {
			return true
		}
	}
	return false
}
