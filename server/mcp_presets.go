package server

import "net/http"

// MCP 工具模板（presets）。
//
// 目的：把"这个平台能接什么逆向/审计/浏览器工具"变成可发现的事实，而不是让使用者
// 去翻文档拼命令行。模板只做**预填**：选中后打开普通的新增表单，命令、参数、环境变量
// 都可改，保存走的还是 POST /api/mcp 那条路径（含首次添加后的工具发现）。
//
// 命令行为什么容易过时：这些工具自身在快速演进（例如 ida-pro-mcp 的 GUI 插件路径已
// 被官方弃用、idalib/stdib 才是当前推荐；IDA 官方 MCP 要求 IDA 9.4+）。所以每条都带
// doc 与 note，说明"跑之前要满足什么"，而不是假装一条命令永远有效。
type MCPPreset struct {
	Key        string   `json:"key"`
	Name       string   `json:"name"`
	Category   string   `json:"category"` // reverse | browser | audit | intel
	Transport  string   `json:"transport"`
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args"`
	URL        string   `json:"url,omitempty"`
	Env        []string `json:"env,omitempty"` // 需要用户填的变量名（不预置值）
	Desc       string   `json:"desc"`
	Install    string   `json:"install,omitempty"`
	Doc        string   `json:"doc"`
	Note       string   `json:"note,omitempty"`
	RequiresID bool     `json:"requires_id,omitempty"` // 需要商业 IDA 授权
}

// mcpPresets 是内置模板列表。顺序即界面展示顺序：逆向 → 浏览器 → 审计 → 情报。
func mcpPresets() []MCPPreset {
	return []MCPPreset{
		{
			Key: "radare2-mcp", Name: "radare2 MCP", Category: "reverse",
			Transport: "stdio", Command: "r2mcp",
			Desc:    "radare2 官方 MCP（MIT）。反汇编、函数/字符串/xref、r2 命令面；支持只读模式与工具白名单，适合容器内批量分析。免费、无授权成本。",
			Install: "r2pm -Uci r2mcp（r2pm 需先装 radare2）",
			Doc:     "https://github.com/radareorg/radare2-mcp",
			Note:    "默认 stdio；只读分析建议加 -R，工具可用 allow/deny 收窄。目标 radare2 6.2.x。",
		},
		{
			Key: "ida-pro-mcp", Name: "IDA MCP（idalib 无头）", Category: "reverse",
			Transport: "stdio", Command: "uv", Args: []string{"run", "idalib-mcp", "--stdio"},
			Desc:       "mrexodia 的 ida-pro-mcp（MIT，idalib 无头模式）。约 60 个工具：decompile/xrefs/rename/patch/struct/symbol 等，是服务端可用的 IDA 形态。",
			Install:    "pip install ida-pro-mcp 或 uv run idalib-mcp；headless 需先 py-activate-idalib.py 全局激活 idalib",
			Doc:        "https://github.com/mrexodia/ida-pro-mcp",
			Note:       "需要 IDA 8.3+（建议 9.x）商业授权与 Python 3.11+；官方 README 已建议改用 Hex-Rays 官方服务器，GUI 插件路径（:13337）已属遗留。",
			RequiresID: true,
		},
		{
			Key: "ida-mcp-hexrays", Name: "IDA MCP（Hex-Rays 官方）", Category: "reverse",
			Transport: "stdio", Command: "uvx", Args: []string{"ida-hcli", "mcp", "serve"},
			Desc:       "Hex-Rays 官方 IDA MCP 服务器（MIT，2026-08 起）。无头优先，带 idb_* 生命周期；与商业 IDA 授权同源，长期最稳。",
			Install:    "uvx ida-hcli mcp install",
			Doc:        "https://github.com/HexRaysSA/ida-mcp",
			Note:       "要求 IDA 9.4+ 与 idalib、uv/git 在 PATH；建议同时只接一个 IDA MCP，避免 Agent 在多个服务器间混淆。命令名以 hcli 版本为准，接入前先 uvx ida-hcli mcp --help 确认。",
			RequiresID: true,
		},
		{
			Key: "ghidra-mcp-headless", Name: "Ghidra MCP（无头）", Category: "reverse",
			Transport: "stdio", Command: "uvx", Args: []string{"--from", "git+https://github.com/bethington/ghidra-mcp", "ghidra-mcp"},
			Desc:    "bethington 的 Ghidra MCP（Apache-2.0），带无头服务器与 Docker 部署，209 个工具，可做批量导入/分析/反编译。免费替代 IDA。",
			Install: "uvx --from git+https://github.com/bethington/ghidra-mcp ghidra-mcp；需 Ghidra 12.1.4 + Java 21",
			Doc:     "https://github.com/bethington/ghidra-mcp",
			Note:    "209 个工具会显著占用上下文：建议按 agent 可见性收窄，或先用 Ghidra analyzeHeadless 批处理再只接分析结果。",
		},
		{
			Key: "reva", Name: "ReVa（Ghidra 逆向助手）", Category: "reverse",
			Transport: "stdio", Command: "uvx", Args: []string{"--from", "git+https://github.com/cyberkaida/reverse-engineering-assistant", "reva-mcp"},
			Desc:    "cyberkaida 的 Reverse Engineering Assistant（Apache-2.0）。刻意做成很多小工具 + 纠错回传，长任务/大二进制/固件友好。",
			Install: "Ghidra 扩展方式安装（Ghidra 12.0+；12.2+ 需 Java 25），再按仓库说明启动其 MCP 端点",
			Doc:     "https://github.com/cyberkaida/reverse-engineering-assistant",
			Note:    "它托管在 Ghidra 扩展里，不是纯 stdio 服务；命令名/传输方式以仓库当前 README 为准（模板只做预填，请核对后再保存）。",
		},
		{
			Key: "playwright-mcp", Name: "Playwright MCP（CDP/浏览器）", Category: "browser",
			Transport: "stdio", Command: "npx", Args: []string{"@playwright/mcp@latest"},
			Desc:    "微软官方浏览器 MCP（Apache-2.0）。a11y 快照、evaluate、cookie/localStorage 全量 CRUD、路由拦截（browser_route）——客户端漏洞（隐藏接口、原型污染、鉴权绕过、Web3 dApp）的主力工具。",
			Install: "npx playwright install chromium",
			Doc:     "https://github.com/microsoft/playwright-mcp",
			Note:    "README 明确写了它不是安全边界；browser_run_code_unsafe 等于页面内任意 JS，务必让 guard 拦截规则覆盖它（本项目默认走 PreToolUse 审批）。",
		},
		{
			Key: "chrome-devtools-mcp", Name: "Chrome DevTools MCP", Category: "browser",
			Transport: "stdio", Command: "npx",
			Args:    []string{"chrome-devtools-mcp@latest", "--no-usage-statistics", "--no-performance-crux"},
			Desc:    "Chrome 官方 DevTools MCP（Apache-2.0）。63 个工具：网络请求/控制台/性能 trace/堆快照/logpoint/screencast，深挖前端问题时比 Playwright 更细。",
			Install: "需要本机 Chrome 或 Chrome for Testing",
			Doc:     "https://github.com/ChromeDevTools/chrome-devtools-mcp",
			Note:    "默认会把使用统计发回 Google；已预置 --no-usage-statistics 与 --no-performance-crux 关掉，涉密项目请勿删除这两个参数。",
		},
		{
			Key: "semgrep-mcp", Name: "Semgrep MCP（代码审计）", Category: "audit",
			Transport: "stdio", Command: "semgrep", Args: []string{"mcp"},
			Desc:    "Semgrep CLI 内置 MCP（LGPL-2.1 CE）。规则化 SAST、自定义规则、AST 输出，用于源码审计与变体搜索。",
			Install: "pip install semgrep（或 brew install semgrep）；确认 semgrep mcp 子命令可用",
			Doc:     "https://docs.semgrep.dev/mcp/overview",
			Note:    "文档主推的是付费 AppSec Platform 的托管 MCP；本地扫描走 CLI 子命令。若 semgrep 版本过旧没有 mcp 子命令，用 shell 工具直接跑 semgrep --json 也行。",
		},
		{
			Key: "virustotal-mcp", Name: "VirusTotal MCP（威胁情报）", Category: "intel",
			Transport: "http", URL: "https://ai.virustotal.com/mcp",
			Desc: "VirusTotal 官方托管 MCP（OAuth，免费 VTAI 档）。样本/URL/域名/IP 情报查询，病毒分析与溯源时补上下文。",
			Doc:  "https://github.com/VirusTotal/virustotal-mcp",
			Note: "托管服务：文件哈希等指标会发给 VirusTotal——客户内部样本请先确认外发授权（等同规范里的带外通道判定）。",
		},
	}
}

// GET /api/mcp/presets
func (s *Server) mcpPresetList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"presets": mcpPresets()})
}
