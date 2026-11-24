// Package vulnpipe 是 0day 流水线阶段 2–3 的数据契约与判定规则。
//
// 阶段 2 产出「候选」：一个可疑点，写成「位置 + 为什么可疑」（哪个入口的参数流到
// 哪个危险操作）。阶段 3 产出「可达性路径」：从外部输入走到该位置的每一跳，每跳
// 都要指向**可核对的证据**——在线域是真实抓到的流量 id，离线域是授权目录清单里的
// 源码位置。两条都不接受"我确认过了"这种自述。
//
// 与 vulngate 的分工：vulngate 判定"结论能不能提交"（三道准入门）；vulnpipe 记录
// "结论从哪来"（候选与可达性）。前者是闸门，后者是链条：闸门只拦得住出口，链条
// 能让人复查中间过程到底走没走。
package vulnpipe

import (
	"fmt"
	"strings"
	"time"
)

// 候选类型。不是枚举白名单式的限制——填不准就 other，别为了塞进某个格子硬归类。
const (
	KindSink   = "sink"   // 未过滤/未转义的危险汇点（SQL 拼接、命令拼接、模板、反序列化目标）
	KindParse  = "parse"  // 危险解析：文件格式、压缩包、协议帧、解析器缺陷
	KindLogic  = "logic"  // 逻辑缺陷：越权、竞态、状态机、金额/数量篡改
	KindAuth   = "auth"   // 认证/授权绕过
	KindConfig = "config" // 配置类：默认口令、调试端点、暴露的管理面
	KindOther  = "other"
)

// 可达性路径上的一跳指向什么证据。
const (
	HopTraffic = "traffic" // 真实流量 id（在线域，平台可核对存在性）
	HopSource  = "source"  // 授权目录内的源码位置 path[:line]（离线域，平台核对存在性与范围）
	HopCommand = "command" // 命令/工具输出（平台不代跑，只能人工复核）
	HopOther   = "other"
)

// 可达性结论。前两档是"声称"，后两档才有平台核对过的证据。
const (
	ReachUnknown  = "unknown"  // 还没有任何路径记录
	ReachClaimed  = "claimed"  // 有路径，但一跳都没核对上
	ReachPartial  = "partial"  // 部分跳核对上了
	ReachVerified = "verified" // 每一跳都有平台可核对的证据
)

// HopInput 是录入时的一跳。
type HopInput struct {
	RefKind string `json:"ref_kind"`
	Ref     string `json:"ref"`
	Claim   string `json:"claim"`
}

// CandidateInput 是录入候选时的输入。
type CandidateInput struct {
	Title     string     `json:"title"`
	Kind      string     `json:"kind"`
	Location  string     `json:"location"`
	Entry     string     `json:"entry"`
	Sink      string     `json:"sink"`
	Rationale string     `json:"rationale"`
	Hops      []HopInput `json:"hops"`
}

// Hop 是落库后的一跳（Verified/VerifiedDetail 由平台核对写入）。
type Hop struct {
	ID             int64  `json:"id"`
	Ordinal        int    `json:"ordinal"`
	RefKind        string `json:"ref_kind"`
	Ref            string `json:"ref"`
	Claim          string `json:"claim"`
	Verified       bool   `json:"verified"`
	VerifiedDetail string `json:"verified_detail"`
}

// Candidate 是落库后的候选。
type Candidate struct {
	ID           int64     `json:"id"`
	TaskID       int64     `json:"task_id"`
	NodeID       int64     `json:"node_id"`
	FindingID    int64     `json:"finding_id"`
	Title        string    `json:"title"`
	Kind         string    `json:"kind"`
	Location     string    `json:"location"`
	Entry        string    `json:"entry"`
	Sink         string    `json:"sink"`
	Rationale    string    `json:"rationale"`
	Status       string    `json:"status"`
	Reachability string    `json:"reachability"`
	VerifiedHops int       `json:"verified_hops"`
	Unverified   int       `json:"unverified_hops"`
	Hops         []Hop     `json:"hops"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// NormalizeKind 归一化候选类型；空/未知都落到 other。
func NormalizeKind(k string) string {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case KindSink:
		return KindSink
	case KindParse:
		return KindParse
	case KindLogic:
		return KindLogic
	case KindAuth:
		return KindAuth
	case KindConfig:
		return KindConfig
	default:
		return KindOther
	}
}

// NormalizeHopKind 归一化跳的证据类型；空/未知都落到 other（other 一律算未核对）。
func NormalizeHopKind(k string) string {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case HopTraffic:
		return HopTraffic
	case HopSource:
		return HopSource
	case HopCommand:
		return HopCommand
	default:
		return HopOther
	}
}

// ValidateCandidate 校验录入。位置必填：没有位置的可疑点无法复核，只会变成一句
// "我怀疑这里有问题"。入口/汇点允许先空着——那正是阶段 3 要补的东西。
func ValidateCandidate(in CandidateInput) error {
	if strings.TrimSpace(in.Title) == "" {
		return fmt.Errorf("候选缺少 title：一句话说清是什么可疑点")
	}
	if len([]rune(in.Title)) > 200 {
		return fmt.Errorf("候选 title 过长（%d 字）：压到 200 字以内，细节放 rationale", len([]rune(in.Title)))
	}
	if strings.TrimSpace(in.Location) == "" {
		return fmt.Errorf("候选缺少 location：在线域写 host+路径或接口，离线域写 path[:line]——没有位置的可疑点没法复核")
	}
	for i, h := range in.Hops {
		if strings.TrimSpace(h.Ref) == "" {
			return fmt.Errorf("第 %d 跳缺少 ref：traffic 写真实流量 id，source 写授权目录内的源码位置，command 写命令或输出标识", i+1)
		}
	}
	return nil
}

// Reachability 由每跳的核对结果得出可达性结论：0 跳 unknown，全核对 verified，
// 部分核对 partial，一跳都没核对上 claimed。
func Reachability(hops []Hop) (status string, verified, unverified int) {
	for _, h := range hops {
		if h.Verified {
			verified++
		} else {
			unverified++
		}
	}
	switch {
	case len(hops) == 0:
		return ReachUnknown, 0, 0
	case unverified == 0:
		return ReachVerified, verified, 0
	case verified > 0:
		return ReachPartial, verified, unverified
	default:
		return ReachClaimed, 0, unverified
	}
}

// ReachLabel 是给人看的一行结论。
func ReachLabel(status string) string {
	switch status {
	case ReachVerified:
		return "可达性已核实（每一跳都有平台可核对的证据）"
	case ReachPartial:
		return "可达性部分核实（还有跳只靠自述）"
	case ReachClaimed:
		return "可达性未核实（路径都是自述，平台没对上任何证据）"
	default:
		return "可达性未知（还没有记录路径）"
	}
}
