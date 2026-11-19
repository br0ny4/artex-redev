# 05 · 决策记录（ADR）

> v0.1 · 2026-11-18 · 背景见 `01-abuse-and-status.md`（滥用与许可）、`03-redev-plan.md`（方案）、`04-policy-engine.md`（策略引擎）
> 本文件记录"为什么这么定"，便于后续复盘与交接。每条决策都写了**触发复盘的条件**。

---

## D1 · 许可路径 = A：开源分支（AGPL 全开）

**决定**：按 AGPL-3.0 继续开源，保留版权声明与变更说明；不闭源、不商用分发。

**理由**：
- v0.3.15 已发布的 AGPL 授权不可撤回，闭源商用是唯一有实质法律风险的路径；
- 版权方（微步）已公开声明闭源商用需商业授权；
- 作者 README 附加条款禁止任何实际测试，与"授权渗透"目标冲突——开源分支 + 明确 AUP 是唯一能同时满足"能用"与"能辩护"的组合。

**后果**：若作为在线服务提供，须按 AGPL §13 向使用者提供源码获取方式；商业诉求只能通过服务/支持实现，不能靠闭源。

**复盘的触发条件**：版权方发出正式授权函 / 本项目出现商业客户 / 法务意见变化。

---

## D2 · 首个域包 = `web_pentest`（在线授权测试）

**决定**：先做在线授权测试域，再做离线域（binary_re / malware_triage / source_audit）。

**理由**：
- 用户明确要保留渗透测试能力，且本次提供的规范就是在线测试口径；
- ARTEX 现有能力（资产图、流量录制、审批、复现）几乎全在 web 渗透上，复用率最高；
- 策略引擎（L1/L3/L4/L5）是该域上线的**前置条件**，正好一并做完——先在线不是"先上车后补票"，而是"先建刹车再造发动机"。

**后果**：离线域（0day 挖掘/逆向/样本分析）顺延到 P2；在此期间平台不能声称覆盖这些场景。

**复盘条件**：`web_pentest` 在授权靶场上跑通 + 11 条红线用例全过。

---

## D3 · "rea" 不绑定具体产品，用可插拔 MCP 兜底

**决定**：`rea` 的三种可能（RevEng.AI / radare2-mcp / ReVa）不阻塞开发，逆向能力按 MCP 插槽实现，MVP 用 **radare2-mcp + Ghidra headless**，IDA（Hex-Rays `ida-mcp` / `idalib-mcp`）与 RevEng.AI 作为可选后端。

**理由**：三者接口形态不同（SaaS REST、stdio MCP、Ghidra 扩展），但都落在 ARTEX 现成的 `mcp_servers` 抽象里；先做插槽才能后接任意一个。

**后果**：MVP 逆向能力是"够用"而非"最好"（无 IDA 反编译质量）。

**复盘条件**：确认 `rea` 的确切所指，或拿到 IDA Pro 授权。

---

## D4 · 语义分类器不允许 LLM 放行

**决定**：判不清一律 `hold`（挂起问询）；LLM 只能用于解释"为什么判不清"，**不得参与放行判定**。

**理由**：规范 4.1"判不清按禁止处理"；把放行权交给模型等于把软约束当硬约束。

**后果**：早期会有较多挂起（操作员需要答复），这是可接受的摩擦；靠词表迭代降低，而不是靠模型放水。

**复盘条件**：观测期 `SEMANTICS_UNCERTAIN` 占比 > 20% 且词表迭代无改善。

---

## D5 · 规范先按 `web-pentest` 单包，`internal-redteam` 延后

**决定**：`policy/web-pentest/` 承载现有规范；**不**现在拆内网红队包。

**理由**：现有规范规定"内网横向预算 0"，与内网红队作业冲突；拆包需要客户侧另一份 RoE 模板，现在没有输入。引擎已经把 scope/budget/egress 全部参数化，后加包不需要改内核。

**复盘条件**：接到内网/甲方红队项目，或客户提供内网 RoE 模板。

---

## D6 · 品牌改名延后到发布前，内部一律声明"衍生版"

**决定**：暂不改 Go module path（`github.com/Autumn-27/artex`）与镜像名；发布前统一改名 + 加 NOTICE + 声明"与 ARTEX 官方无关"。

**理由**：改 module path 要重写全部 import，风险与收益不对称；而"被误认为官方 ARTEX"的风险主要在**对外发布/部署**时，不在开发期。

**后果**：开发期产物不能直接对外分发；发布前必须完成改名清单（module path、镜像、README、UA、NOTICE）。

**复盘条件**：进入 P4 或任何对外分发动作之前。

---

## D7 · 策略引擎默认不安装，安装即 `hard`

**决定**：未配置 `ARTEX_ENGAGEMENT_FILE` 时保持上游行为（无策略）；配置后默认 `hard`（拦截），`warn` 只用于观测期。

**理由**：不破坏现有安装的升级路径；同时避免"装了但不拦"的假安全感。
注意：这与上游"默认放行"不同——**只要启用，就默认拒绝**。

**后果**：未配置的实例仍然是上游行为，README 必须显式提示"在线域请务必配置部署上下文"。

**复盘条件**：观测期误拦数据出来之后，决定是否把默认值从 hard 调整为"hard + 白名单"。

---

## D8 · 部署形态 = 单机 / on-prem 单租户

**决定**：先做单机 + 本地 PostgreSQL；多租户/RBAC 延后。

**理由**：规范本身是"单项目单授权"口径；多租户会引入跨租户数据隔离这一独立的大工程。

**复盘条件**：出现服务化需求（多人同时用、按客户隔离）。

---

# 实现进度（本次已完成）

| 项 | 状态 | 位置 |
|---|---|---|
| 规范收口（GB18030→UTF-8，哈希留痕） | ✅ | `policy/spec/` |
| 策略配置 / 语义词表 / 部署上下文模板 | ✅ | `policy/web-pentest/` |
| 敏感特征库（30 条，RE2 校验） | ✅ | `policy/patterns/secret.txt` |
| 语义分类器（A–F，含换皮/方法伪装/参数开关/中文） | ✅ | `policy/semantics.go` + 测试 |
| 范围解析（清单/排除/通配/内网/元数据/CNAME 第三方/CDN） | ✅ | `policy/scope.go` + 测试 |
| 预算引擎（5.3 表 + 熔断 + 只收紧） | ✅ | `policy/budget.go` + 测试 |
| 命令策略（扫描器白名单、内联解释器、RCE 只读、敏感读取、目标越界） | ✅ | `policy/command.go` + 测试 |
| 响应检查（体积/敏感命中/行数/PII 计数） | ✅ | `policy/content.go` + 测试 |
| 判定入口（请求/命令/挂起/握手） | ✅ | `policy/engine.go` + 测试 |
| guard L1 接入（默认关闭，安装即生效） | ✅ | `guard/guard.go` + `guard/policy_test.go` |
| 启动接线（`ARTEX_ENGAGEMENT_FILE`） | ✅ | `cmd/artex/main.go`、`policy/install.go` |
| P0 硬化：默认只绑回环 | ✅ | `cmd/artex/main.go`、`docker-compose.yml` |
| P0 硬化：登录失败限速（5 次/10 分钟 → 锁 15 分钟） | ✅ | `server/login_limiter.go` + 测试 |
| L3 代理层接线（请求前判定 + 响应侧截断） | ✅ | `traffic/policy.go` + `traffic/policy_test.go` |
| L3 强制前提：启用策略时强制开启流量录制、拒绝关闭 | ✅ | `server/manager.go` |
| 判定落库（`policy_decisions` hash chain，异步不阻塞） | ✅ | `db/policy_audit.go`、`server/policy_audit.go` |
| 判定查询/审计链校验 API | ✅ | `server/policy_api.go`（`/api/policy/{status,decisions,chain}`） |
| DNS 解析缓存（避免每个请求都解析，同时钉住判定 IP） | ✅ | `policy/install.go`（`NetResolver` TTL 缓存） |
| L2 出网强制（compose `internal` 网络 + 唯一 egress 代理） | ✅ | `deploy/egress-lockdown/` + `ARTEX_GLOBAL_PROXY` |
| 全局挂起（Stop-All）：范围不明/语义判不清/预算耗尽 → 全量停止 | ✅ | `policy/hold.go` + 测试 |
| 挂起落库与操作员答复 API | ✅ | `db/policy_holds.go`、`server/policy_hold_api.go`（`/api/policy/holds`） |
| `/api/auth/init` 一次性 setup token（启动日志/环境变量） | ✅ | `server/auth.go`、setup 页 |
| 前端操作台 `/system/policy`：挂起横幅 + 答复（记录/恢复两种）+ 判定流水 + 审计链校验 | ✅ | 顾问/蓝队可直接作业 |
| MCP 工具模板（9 个：radare2 / IDA×2 / Ghidra / ReVa / Playwright / CDP / Semgrep / VirusTotal） | ✅ | `server/mcp_presets.go` + `/api/mcp/presets` + MCP 页模板区 |
| 挂起联动任务调度：全量停止即暂停在跑任务，答复恢复后续跑（只续跑因挂起暂停的） | ✅ | `server/policy_hold_pause.go` + e2e 测试 |
| **未做**：合规矩阵端到端用例（当前各层单测已覆盖） | ⬜ | 下一个切片 |

---

# 下一步（自主执行顺序）

1. **离线域包**：`binary_re` / `malware_triage` / `source_audit` 三个域包（MCP 可插拔接入 radare2-mcp、Ghidra headless、semgrep），复用同一套判定与审计。
2. **策略状态进仪表盘**：把挂起数、拦截数、预算余量做成首页指标，蓝队值班时一眼能看出平台在拦什么。
2. **策略状态进仪表盘**：把"执行层是否启用/是否挂起"提到仪表盘首屏，避免带着未生效策略去测。
4. **合规矩阵端到端**：把 04 §8 的用例扩成端到端（起代理 → 发请求 → 断言 403/截断/挂起）。
5. **L2 之外**：非 compose 部署的 netns 脚本化（`deploy/egress-lockdown/README.md` 已给模板）。
