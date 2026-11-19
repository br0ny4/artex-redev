// Package policy 是规范《SRC 行业授权资产安全测试规范 · Agent 版 v2.5》的工程层实现。
//
// 设计前提（规范第九章第 3 条）：提示词是软约束，涉及请求拦截、预算熔断、范围校验、
// 审计日志的硬约束必须由平台在工程层实现，不依赖模型自觉。本包不信任任何模型输出，
// 只根据平台自己解析出的目标、语义与已用预算做判定。
//
// 本包只提供判定（纯函数 + 有状态计数器），不负责把判定接到哪个出口：
//   - 命令出口（L1）：guard 通过 Policy 接口在 PreToolUse 调用 CheckCommand；
//   - 请求出口（L3）：traffic 代理在发请求前调用 DecideRequest、收响应后调用 InspectResponse；
//   - 挂起/问答（L5）：调用方拿到 ActionHold 后自行挂起任务并向操作员提问。
//
// 配置与判定读同一份数据：deployment-context 既渲染进 system prompt（提示词基线），
// 也由本包解析成 Engagement 参与判定。两者不一致时以本包的解析结果为准。
package policy

import (
	_ "embed"
	"fmt"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// 嵌入式资产：策略配置、词表、敏感特征、规范正文。
// 规范正文只随提示词注入，不参与判定；放在这里是为了「提示词与判定同源同版本」。
var (
	//go:embed web-pentest/policy.yaml
	rawPolicyYAML []byte

	//go:embed web-pentest/verb-lexicon.yaml
	rawLexiconYAML []byte

	//go:embed patterns/secret.txt
	rawSecretPatterns []byte

	//go:embed spec/SRC行业授权资产安全测试规范-Agent版.md
	rawSpecMarkdown []byte
)

// DefaultConfig 解析内置 policy.yaml。返回值每次都是新副本，调用方可安全修改。
func DefaultConfig() (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(rawPolicyYAML, &cfg); err != nil {
		return nil, fmt.Errorf("解析内置 policy.yaml: %w", err)
	}
	return &cfg, nil
}

// DefaultLexicon 解析内置词表。
func DefaultLexicon() (*Lexicon, error) {
	var lx Lexicon
	if err := yaml.Unmarshal(rawLexiconYAML, &lx); err != nil {
		return nil, fmt.Errorf("解析内置 verb-lexicon.yaml: %w", err)
	}
	return &lx, nil
}

// SpecMarkdown 返回规范正文（UTF-8），供 system prompt 注入使用。
func SpecMarkdown() string { return string(rawSpecMarkdown) }

// SecretPatternsRaw 返回敏感特征原始文本（每行 <type>\t<regex>）。
func SecretPatternsRaw() string { return string(rawSecretPatterns) }

// 默认引擎：由 Install 安装，guard 与 proxy 通过 Default() 取用。
// 未安装时为 nil，所有检查保持上游原行为（无策略）。
var defaultEngine atomic.Pointer[Engine]

// Install 安装全局默认引擎；传 nil 表示卸载。返回安装前的引擎。
func Install(e *Engine) *Engine { return defaultEngine.Swap(e) }

// Default 返回当前安装的引擎，可能为 nil。
func Default() *Engine { return defaultEngine.Load() }
