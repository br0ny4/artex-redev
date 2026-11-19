# ARTEX 二次开发总体方案

> v0.1 · 2026-11-18 · 基线 = 本地快照 **v0.3.15**（CHANGELOG 2026-10-07，闭源前最后一版）
> 配套阅读：`00-arch-map.md`（代码扩展点）、`01-abuse-and-status.md`（滥用态势与许可）、`02-tooling-survey.md`（工具选型）

---

## 0. 结论先行

1. **技术上可行。** 本地快照实测：Go 1.26.3 `go build ./...` 通过；`go test ./guard ./intercept ./agent ./db` 全过；扩展缝清楚（见 00 §10、附录 B）。ARTEX 真正值钱的是**目标拆解 → 规划 → worker → 复测**的双图编排 + 证据/流量/审批基础设施，这部分应当保留。
2. **但"保留渗透能力 + 加 0day 挖掘"这个组合，在法律与运营上是三条完全不同的路**，必须先选路再写代码：
   - **A. 开源分支（AGPL 全开）**——最干净，可自由改，不可闭源商用；
   - **B. 干净重写（Clean-room）**——只借架构不借代码，可闭源商用，工期 3–6 个月；
   - **C. 商业授权**——向版权方（微步）拿授权 / 直接对接 RedAgents，最快但受制于人；
   - **✗ 闭源商用 ARTEX 二开 = 唯一有实质法律风险的选项，不建议。**
3. **推荐**：A 作主线（内核 + 域包全开）；若确需商用，走 B 的"内核重写 + 域包复用"分阶段迁移，或先用 C 探路。
4. **定位建议**：把重心从"在线自主打点"移到"**离线分析为主 + 在线测试受硬约束**"。6 个作业域里 4 个不需要出网——既覆盖红队/挖洞，又天然覆盖蓝队/病毒分析/赏金，并且不依赖打第三方。这是"通用"与"可辩护"的交点。
5. **能力接入主要走 MCP，不改引擎。** MVP 全部免费可容器化：radare2-mcp、Ghidra headless、capa/YARA/FLOSS 自封装、playwright-mcp、VirusTotal MCP、semgrep CE。IDA / Binary Ninja / CodeQL 有 license 门槛，属 v2。
6. **必须先补的三道硬边界**（上游是 fail-open）：未认证 `setup` 抢占、授权范围强制（现在只在资产插入处拦，Bash 直连目标完全不拦）、沙箱出网。

---

## 1. 硬事实基座

### 1.1 滥用态势（详细取证见 01）

| 事件 | 影响 | 来源 |
|---|---|---|
| **FBI FLASH-20261113-001** | 2026-08 起多国多行业遭 ARTEX 自动化入侵，最快 **<3 小时**拿到特权访问；点名的行业覆盖金融/政府/国防/半导体/医疗/能源/制造/电信/法律 | Infosecurity Magazine（2026-11-16） |
| 韩国金融机构 | 约 **6.7 万人** PII 外泄，直接触发 10-08 闭源 | CrowdStrike，经媒体转述 |
| ConnectWise 供应链 | **2,250+** 下游租户可被访问（Microsoft 归因 Storm-0940） | Infosecurity |
| 公网裸奔控制台 | Censys **1,465** 台 / Check Point **1,608** 台在线；10 个实例数据库全裸 | Censys、Check Point |
| 投毒镜像 `tomicdd/artex` | 登录 handler 内置 `sh -c` root 命令执行；9,077 次 pull、637 个仓库引用 | Ostorlab / BadByte |

**含义**：(a) 这不是小众工具，是被写进联邦通报的攻击基础设施；(b) fork 出来的东西会被防守方按 ARTEX 生态对待；(c) **公网暴露面本身就是最大危害源**——面板比漏洞更危险。

### 1.2 本地快照体检（本次实测，非引用）

| 检查项 | 结果 |
|---|---|
| 来源 | 无 `.git`；原仓库 2026-11-18 已 404；版本 0.3.15 —— 与"闭源前最后一版"一致 |
| 完整性 | **7 个文件 mtime 为 10-30**（README、install.sh、update.sh、Dockerfile.local、docker-compose.local.yml、build-image.sh、.github），其余均为 10-07 → **这不是纯净发行包**，是闭源后被人改过"本地构建流程"的快照 |
| 后门排查 | **未发现**：`auth.go` 无 `captcha`/`verifyCaptcha` 字段与 `!` 前缀命令执行；`docker-compose.yml` 仍指向官方 `autumn27/artex`；安装脚本外联仅 `get.docker.com` / goproxy / npmmirror；`release.yml` 无异常外联。与"源码无后门、后门只在第三方镜像"的公开结论吻合 |
| 可构建/可测 | `go build ./...` 通过；`guard/intercept/agent/db` 测试全过；web 无 `node_modules`，需联网 `npm ci` |
| 认证 | 固定用户名 `ARTEX`；bcrypt + JWT（7d，HS256，密钥落盘）；**`POST /api/auth/init` 未认证可抢占**；**无登录限速**；默认监听 `:8787` 全网卡 |
| 安全边界 | RoE 已移除；无规则命中→放行；LLM 裁判失败→`allow`；外传规则默认关；scope 只在 `insert_assets`/`add_intent` 拦，**Bash 直连目标不被拦** |
| 指纹 | `artex-enrich/1.0` UA（`enrich/enrich.go:233`）、`norma/0.4` —— 已被用于真实事件归因（WorkOS 案例） |

### 1.3 许可与法律（决定性）

- **AGPL-3.0**：修改后分发、或通过网络提供服务，须提供完整对应源码（§5/§13），不得改为闭源许可。
- **作者附加条款**（README §520–550）：禁止任何实际测试，**连"授权资产"也一并禁止** —— 与"授权渗透"目标直接冲突。
- **微步声明**（2026-11-06）：自称版权方，闭源商用需商业授权，ARTEX Pro 仅在 RedAgents.cn。
- **商标/身份**：许可证不含商标权；继续用 ARTEX 名义会被下游误认为官方发布。
- **三条红线**：① 闭源商用分发；② 保留 ARTEX 品牌且公网部署；③ 把产品做成"输目标即打"的形态。

---

## 2. 定位：安全作业台（Security Workbench）

目标用户：红队 / 蓝队 / 赏金猎人 / 恶意样本分析师 / 甲方安全。**一个内核，六个作业域**：

| 域 | 输入 | 主要动作 | 产物 | 联网 |
|---|---|---|---|---|
| `web_pentest` | 授权域名/IP/APP | 侦察→攻击面→利用→验证 | 漏洞+PoC+流量证据 | 是（强 scope） |
| `bounty_recon` | 赏金项目 scope | 资产/JS/API 收割，变化监控 | 资产图+新端点+报告草稿 | 是（按 program scope） |
| `source_audit` | 仓库/包/固件源码 | 入口→sink 数据流、变体分析 | 疑似漏洞+路径+触发条件 | 否 |
| `binary_re` | 二进制/固件 | 反编译/交叉引用/符号恢复/差分 | 函数级结论+patch diff | 否 |
| `malware_triage` | 样本 | 静态 + 隔离动态 + 行为 | IOC/TTP/检测规则 | **否（禁出网）** |
| `blue_detect` | 日志/告警/流量 | 狩猎/检测工程/仿真验证 | Sigma/YARA/Suricata | 否 |

设计原则：

1. **离线优先**——6 域中 4 域不需要出网，天然规避"打第三方"风险，也是工作量大头。
2. **在线必须可归因 + 硬边界**——授权范围落地为**网络层白名单**，而非 prompt 里的一句话。
3. **验证即结论**——任何 finding 必须绑定可复现证据（ARTEX 已有 traffic/evidence 机制，需扩展）。
4. **成本可见**——per-task token 预算、模型分级路由、超预算硬停。

---

## 3. 授权与边界（与上游最大的区别）

**落地依据 = 《SRC 行业授权资产安全测试规范 · Agent 版 v2.5》**，已随仓库收口：

- 规范原文（UTF-8）：[policy/spec/SRC行业授权资产安全测试规范-Agent版.md](../../policy/spec/SRC行业授权资产安全测试规范-Agent版.md)
- 机器可读策略：[policy/web-pentest/policy.yaml](../../policy/web-pentest/policy.yaml)
- 语义词表：[policy/web-pentest/verb-lexicon.yaml](../../policy/web-pentest/verb-lexicon.yaml)
- 部署上下文模板：[policy/web-pentest/deployment-context.example.yaml](../../policy/web-pentest/deployment-context.example.yaml)
- **工程层设计**：[04-policy-engine.md](04-policy-engine.md)

规范第九章第 3 条已经写明"提示词是软约束，硬约束必须由平台工程层实现"——这与我们的判断完全一致，下面的设计就是它的实现。**规范与代码读同一份配置**：`deployment-context` 既渲染进 system prompt，也写入 `engagement_policy` 表由代理与 guard 读取。

### 3.1 授权模型：单一口径的 engagement

新增比 task 更高一层的 **engagement**，字段与规范 §9.2 的必填项一一对应：

```
engagement: {
  client, title,
  authorization_doc + sha256,                      # 授权书，哈希进报告附录
  window: {starts_at, ends_at, timezone},          # 只能在窗口内发包
  scope: {domains, ips, cidrs, apps, apis, exclude},
  allowed_egress: [report_channel, "*.dnslog.cn"], # 红线 8：其余一律禁出
  test_accounts: [{id, username, bound_contact}],  # C/D/E 类操作只能用这些账号
  allowed_tools: {always, per_use, denied},        # 扫描器白名单制
  budget_overrides,                                 # 只能更严，放宽需书面记录
  report: {channel, format},
  artifacts: {dir, purge_after_report}
}
task → engagement_id
```

- 没有 engagement 或上下文缺项 → 只能跑离线域 / 被动分析（规范 §9.2）；
- 在线域每次目标解析都在**代理层 + 网络层**双重核对；
- 归属不明/第三方托管/CDN 回源 → 判 `ambiguous`，**问询后人工确认**才放行（规范 1.1）。

### 3.2 五层 fail-closed 强制（详设见 04 §2）

| 层 | 控制 | 拦截对象 |
|---|---|---|
| L1 命令与工具 | guard 前置步骤 + 命令 AST 判定 + 二进制白名单 | `nuclei/sqlmap/nmap` 未审批、RCE 里 `cat .env`、解释器内联 |
| L2 沙箱网络 | netns + nftables **default drop** | raw socket 绕过代理、直连内网、回连 C2 |
| L3 请求代理 | mitmproxy addon：范围 → 语义 → 预算 → 内容 | 换皮删除、分页拖库、越界域名、大响应体 |
| L4 产物与留痕 | artifacts 收口 + 证据快照 + hash-chain 审计 | 产物散落、证据缺失、报告字段不全 |
| L5 挂起与问答 | Stop-All + 操作员问答 + 恢复条件 | 预算耗尽、敏感命中、范围不清后继续测 |

> L2 是"绕过分析"的关键：只靠代理等于放过 raw socket。详见 04 §7 的 8 条绕过路径对照表。

### 3.3 规范 11 条红线的落地方式

规范第二章 11 条红线不做成提示词，而是做成**11 个可判定谓词**（`redlines:` 段），每条对应一个自动化验收用例：

| 红线 | 判定依据（工程） |
|---|---|
| R1 删除/清空/销毁、覆盖/重置/迁移/合并 | 请求语义分类器（A/B 类）+ REST 方法 + 参数开关 |
| R2 拖库/整表/无上限翻页 | 响应行数/体积预算 + `total` 字段优先 |
| R3 DoS | 速率/并发/重试上限（模型不可自调） |
| R4 内网与横向（预算 0） | 解析后 IP 命中内网段 → deny；SSRF 只留"可达"证据 |
| R5 向真实用户触发消息 | 收件人必须属于 `test_accounts.bound_contact` |
| R6 写入型注入自动化 | 注入语义判定 + 自动化工具标记 |
| R7 公域写入 | 目标判定为公共区域 → deny |
| R8 外带数据到第三方 | egress 白名单（仅报告通道 + dnslog/collaborator） |
| R9 领取/兑换/提现/支付 | 语义 D 类高危子类 → deny |
| R10 复用窃取凭据 | 凭据污点标记，任何登录请求命中即拒 |
| R11 批量工单/投诉 | 批量形态模式 → deny |

### 3.4 握手与合规校验（规范第九章）

- 首响应必须以 `[RULES_LOADED v2.5]` 开头，否则**禁用全部工具**（不是警告）；
- 规范版本与 `policy.yaml:spec.version` 不一致 → 拒绝启动在线域；
- 规范 §9.1 说"版本与文件头一致"但**文件头缺版本号**——建议在规范文件头补 `version: 2.5`，见 04 §11。

### 3.5 额外不做

除规范红线外，作为产品我们额外不做：

- 免杀/规避 EDR/隐藏流量特征、反取证、伪造归因；
- 无人工确认的自动化漏洞利用；
- "输入目标列表 → 自动出洞"的无人值守模式；
- 大规模凭据窃取 / 数据外传编排。

理由：这些既是上游被滥用的核心机制，也超出"安全作业"范畴。保留它们会让整个项目无法辩护。

---

## 4. 目标架构改造

### 4.1 内核（kernel）vs 域包（domain pack）

把"通用平台能力"与"某类作业的 prompt/工具/产物"解耦：

```
packs/<id>/
  pack.yaml     # kind(offline|online), agents, tools, mcps, skills,
                # artifact_schemas, policy(scope_required, egress, approval)
  agents/       # prompt 模板
  skills/       # SKILL.md 包
  tools/        # 需要代码的内置工具组（Go）
  evals/        # 验收用例
```

内核提供：agent 编排、沙箱、MCP 编排、产物库、证据链、审批、成本、报告、RBAC。
好处：「通用」不再是堆功能，而是**加域包不改内核**；这同时就是未来商业化的边界。

### 4.2 需要动内核的 9 件事（按依赖排序）

| # | 改造 | 为什么必须动代码 | 参考落点 |
|---|---|---|---|
| K1 | 域包加载 + task→pack 绑定 | 现在 agent/tool/skill 是全局 seed，没有"域"概念 | `db/db.go`、`agent/toolcatalog.go`、`server/task_llm.go` |
| K2 | 产物模型扩展（findings.kind、samples、binaries、code_units、detection_rules） | findings 现在只服务"渗透漏洞" | `db/schema.sql`、`agent/tools_*`、`server/findings_*` |
| K3 | 沙箱执行层（per-task 容器/netns、只读根、资源限额、无网/白名单） | 现在 agent 直接跑在服务容器里，Bash 无隔离 | `agent/worker.go`、`server/manager.go`、`Dockerfile` |
| K4 | 授权范围引擎（engagement + egress 强制 + fail-closed） | RoE 被删；现有 scope 只拦资产插入 | `guard/guard.go`、`intercept/`、`db/asset_intercept_match.go` |
| K5 | MCP 编排（按 task 注入、工具白名单、延迟加载、健康检查） | 现在只有 agent 级可见性 | `server/assembly.go`、`server/mcpdiscover.go` |
| K6 | 成本治理（预算/路由/硬停/看板） | 有 token 统计，无预算硬停 | `llmpool/`、`server/task_llm.go` |
| K7 | 证据链与多域报告（hash-chain、模板、导出） | evidence 已具备，报告是渗透模板 | `evidence/`、`report/` |
| K8 | 认证/多租户/RBAC + 硬化 | 单管理员、明文密钥、默认全外露 | `server/auth.go`、`db/`、`docker-compose.yml` |
| K9 | 评测台（XBOW 104 + AIxCC 风格用例 + 样本集） | 没有回归基线就无法证明"更强了" | 新增 `evals/` |

### 4.3 Agent 层（改造成本低）

- 新增 **assistant 型** agent：`binanalyst` / `srcauditor` / `malanalyst` / `bluedetector` / `bountyrecon`。不需要新编排角色（编排角色硬编码 4 个），只需 DB 行 + prompt + 工具绑定（00 §10a）。
- **保留** goals/planner/worker/retester 双图编排；把 `retester` 升级为"证据验证器"（跑 PoC、跑复现）——正好治理上游的"幻觉成功"。
- 每个域 agent 必须写明"拒绝条件"和"停止条件"（cost/steps/no-progress），而不是上游那种"不轻言放弃"。

### 4.4 工具 / MCP 层

要点：

- **执行类 MCP 与只读类分级**：`patch_asm` / `py_eval` / `browser_run_code_unsafe` / debugger 类单独审批，只读类（反编译、xref、搜索）自动放行。
- **schema 预算**：209 工具的 Ghidra MCP 会撑爆 context。必须走 ARTEX 现成的 **deferred + `mcps:` skill 解锁**机制，按需解锁（00 §3.4）。
- **自写三个薄 MCP** 比等现成实现更稳：`triage`（capa+YARA+FLOSS+DIE）、`symbolic`（angr/Triton）、`audit`（semgrep CE + Joern）。

### 4.5 0day 挖掘流水线（核心新增）

```
intake → 指纹/构建识别 → 攻击面提取 → 候选生成 → 可达性/污点 → 触发验证 → 去重/定级 → 报告+补丁
```

| 阶段 | 手段 | 工具 | 产物 |
|---|---|---|---|
| intake | hash / SBOM / 语言 / 架构 | syft、file、strings | artifact 元数据 |
| 面 | 源码：路由/解析器/sink；二进制：导出函数/IPC/网络解析 | tree-sitter、CodeQL/Joern、IDA/Ghidra | 入口清单 |
| 候选 | 规则 + 模式 + 变体分析（已知 CVE 同族） | semgrep CE、CodeQL taint、diaphora 差分 | 候选（带置信度） |
| 可达 | 数据流 / 符号执行 | Joern CPG、angr、Triton | 可达路径 |
| 触发 | 构造输入、harness、fuzz | libFuzzer/AFL++、ASan/UBSan | 崩溃/PoC |
| 定级 | 去重、root cause、可利用性 | CASR/vulnloc + 人工 | 漏洞报告 |

**关键原则**（来自 AIxCC 冠军 Atlantis / Google Big Sleep / Aardvark）：**LLM 负责理解，执行负责证明**。没有触发证据的候选一律降级为 `suspected`，不进 finding——与 ARTEX 现有"finding 必须有证据"的纪律一致，可直接复用。

### 4.6 恶意样本域

- **intake**：只算 hash，不默认上传云端（VT 按 hash 查）；样本进隔离区，权限 0400。
- **静态**：capa / YARA / FLOSS / DIE / pefile / ELF 解析 → 行为假设。
- **动态**：默认 **无出网**（netns drop）；speakeasy 在 Linux 容器内模拟 Windows；高危样本走本地 VM（QEMU/KVM）+ Frida。记录进程/文件/注册表/网络尝试。
- **产物**：IOC + TTP（ATT&CK）+ Sigma/YARA/Suricata + 家族归因草稿。
- **逃逸风险**：样本目录不挂载宿主，容器 drop caps + seccomp；高危样本强制 VM。

### 4.7 蓝队域（差异化卖点）

- **检测工程**：从一次红队作业/样本自动产出检测规则，并在本地回放验证（Sigma→后端查询、Atomic Red Team 仿真）。
- **"对付 agentic 攻击者"检测包**：ARTEX 及同类框架的指纹（`artex-enrich/1.0`、`norma/`、控制台路径、MCP 端口 13337/8745/8931/8765/24642）、行为节奏（2–25 s 爆发、24–30 h 持续）、典型 C2（vshell / AdaptixC2 / WISP）。这是当下真实需求，也是把"fork 自被滥用工具"转化为正当性的最强方式。

### 4.8 前端

Next.js App Router + sidebar 数组 + `api.ts`（00 §8.2）。新增页面：`engagements`（授权）、`packs`（域包）、`artifacts`（样本/二进制/规则）、`cost`（预算）、`evals`（评测）。沿用现有表格/图组件。

---

## 5. 工具接入清单（摘要，详见 02）

**MVP（全免费 / 可容器 / 可回滚）**

| 能力 | 选型 | 接入 | 备注 |
|---|---|---|---|
| 二进制 RE | **radare2-mcp**（MIT） | stdio，`r2pm -Uci r2mcp` | 自带只读模式 + 工具白/黑名单，与 guard 模型同构 |
| 反编译 | **Ghidra headless** 自封装 | stdio | Apache-2.0，批量反编译导出 |
| 恶意样本 | **自写 triage MCP**（capa/YARA/FLOSS/DIE） | stdio | 最便宜的 triage 收益 |
| 浏览器/前端 | **playwright-mcp** | stdio/http | cookie/localStorage CRUD + route 拦截 + evaluate |
| 情报 | **VirusTotal 官方 MCP** | http | 免费 VTAI 层 |
| 源码审计 | **semgrep CE CLI** 自封装 | stdio | 避开付费 hosted MCP |

**v2（license 门槛）**：Hex-Rays 官方 `ida-mcp`/`idalib-mcp`（IDA 9.4+；mrexodia 版需 8.3+）、Binary Ninja 6 原生 MCP、CodeQL（GHAS）、Joern、angr、speakeasy、CAPE v2。

**明确排除**：Cuckoo（2022 年停更）、CAI（2026-08 归档）、Vulnhuntr（停更）、puppeteer MCP、Semgrep hosted MCP、IDA GUI 插件 + `:13337`（作者已弃用）。

---

## 6. 路线图（按 2 人全职估）

| 期 | 周期 | 内容 | 验收 |
|---|---|---|---|
| **P0 硬化** | 1 周 | 去品牌 / 自建镜像 + SBOM + 签名；setup token；绑 `127.0.0.1`；登录限速；密钥加密；fail-closed 开关；UA 可配置 | 无未认证接管；默认不外露；外部扫描通过 |
| **P1 内核** | 2–3 周 | 域包加载；产物模型；engagement 数据模型；成本预算 | 离线任务不触网；超范围必拦；预算超限硬停 |
| **P1.5 策略引擎** | 2–3 周 | 按 [04](04-policy-engine.md) 实现：范围解析 → 语义分类 → 预算 → 内容检查 → 挂起问答 → 审计链；先 `warn` 后 `hard` | 合规矩阵 1/2/4/5 章用例全过（见 04 §8） |
| **P2 离线域** | 3–4 周 | `binary_re` + `malware_triage` + `source_audit` 三包 + 沙箱（无网） | 20 个已知 CVE 上产出可复现 PoC ≥1 例；样本分析产出可用规则 |
| **P3 在线域** | 3–4 周 | `web_pentest`（继承 ARTEX）+ `bounty_recon` + CDP 包 + L2 netns + 审批 UX | 授权靶场端到端跑通；越界 100% 拦截；规范 11 条红线用例全过 |
| **P4 蓝队 + 产品化** | 持续 | `blue_detect` 包；多域报告；多租户/RBAC；评测台接入 XBOW 104 | 红蓝闭环演示；成本/发现曲线可量化 |

---

## 7. 合规与运营

- **许可**：开源分支保留 AGPL 全文 / 版权 / 变更说明；若提供在线服务，提供源码获取入口（§13）。不做闭源商用。
- **品牌**：换名 + 明确"与 ARTEX 官方无关"；首发说明 fork 动机与安全修复清单（01 §6 的 11 条可直接用）。
- **供应链**：只从自审源码构建；镜像推自有 registry + digest 固定；发布 SHA256 + cosign；**禁止再引用任何 `autumn27/*` 或第三方 artex 镜像**。
- **滥用治理**：AUP + 使用前授权确认（上游 0.3.13 已有弹窗，可加强为"登记授权证明才能开在线域"）；滥用举报渠道；遥测默认关、审计日志默认开。
- **数据**：客户 engagement 数据留存期与删除；样本默认不上传云端；PII 自动脱敏。

---

## 8. 风险登记表（Top 8）

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| 被当作攻击基础设施 / 上通报 | 高 | 极高 | 换名、离线优先、硬边界、AUP、主动披露 |
| AGPL / 微步版权争议 | 中 | 高 | 全开不闭源 / 商业授权 / 干净重写 |
| 供应链投毒（镜像 / fork） | 中 | 极高 | 自建 + 签名 + SBOM + digest 固定 |
| 误伤目标（删数据 / DoS） | 中 | 高 | 破坏性默认 deny；限速；审批；回滚预案 |
| 幻觉成功（假 finding） | 高 | 中 | 证据强制 + 复测 + 结构化验证 |
| 成本失控 | 高 | 中 | 预算硬停 + 模型路由 |
| 样本逃逸 / 分析主机被感染 | 低 | 极高 | 无网 + 只读 + VM |
| IDA / BN / CodeQL 许可限制 | 中 | 中 | 先免费栈，商用场景逐项确认 |

---

## 9. 决策与进度

原"待拍板"事项已由 [05-decisions.md](05-decisions.md) 定案（D1–D8）：

| 事项 | 决定 |
|---|---|
| 许可路径 | **A 开源分支（AGPL 全开）**，不闭源商用 |
| 首个域包 | **`web_pentest`（在线授权测试）**，离线域顺延到 P2 |
| "rea" | 不绑定产品，按可插拔 MCP 实现；MVP 用 radare2-mcp + Ghidra headless |
| 语义分类器 | **不允许 LLM 放行**，判不清一律挂起问询 |
| 规范口径 | 先单包 `policy/web-pentest`；`internal-redteam` 待客户 RoE 模板 |
| 品牌 | 发布前统一改名 + NOTICE；内部一律声明"衍生版" |
| 策略默认值 | 未安装引擎=上游行为；**安装即 hard**，warn 仅观测期 |
| 部署形态 | 单机 / on-prem 单租户；多租户延后 |

**已落地**（本次）：规范收口、策略配置与词表、语义分类器、范围解析、预算引擎、命令策略、
响应检查、判定入口、guard L1 接入、启动接线（`ARTEX_ENGAGEMENT_FILE`）、
P0 硬化（默认只绑回环 + 登录失败限速）。

**下一刀**：L3 代理接线 → L2 出网强制 → 判定落库/审计链 → setup token → 合规矩阵端到端回归。
详见 [05-decisions.md](05-decisions.md) 的"实现进度"与"下一步"。
