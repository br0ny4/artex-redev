# 10 · 定位与守则：为什么 fork、我们守什么、改什么

> v1 · 2026-11-20 · 与 [`09-diff-from-upstream.md`](09-diff-from-upstream.md)（差异清单）、
> [`05-decisions.md`](05-decisions.md)（决策记录）配合阅读。
> 本文不是营销文案：§3/§4 里的每个坐标与测试锚点都由 `internal/docscheck` 在 CI 里校验，
> 代码改而文档不跟进，CI 会红。

---

## 1. 一句话定位

**上游 = 能自动打完一条链的渗透 Agent；本仓库 = 同一个引擎 + 真边界 + 机器证据的通用安全作业台。**

两个"加"都不是加在提示词上，而是加在工程层：

1. **真边界**：授权范围从"写在提示词里"变成"没有记录就发不出包"；
2. **机器证据**：结论从"模型说它验过"变成"平台自己跑过、自己判定、自己留下流量"。

## 2. 为什么选 ARTEX（而不是重写，或换一个）

| 候选 | 判断 |
|---|---|
| 商业 XBOW 类 | 不开源，无法做成可审计、可内网部署的平台 |
| CAI | 已归档（2026），无维护 |
| Strix | 偏容器化黑盒"打点"，证据链弱，平台性不足 |
| PentestGPT | 学术原型，工程骨架不足 |
| **ARTEX v0.3.15** | 数据驱动多角色编排 + 探索图 + 全量流量录制 + findings 与流量快照绑定；**平台性远大于提示词技巧**；AGPL 可合法 fork |

结论：**我们买的是"证据基础设施"，不是"更强的攻击提示词"。**
ARTEX 被大规模滥用（FBI FLASH 通报、1400+ 无鉴权控制台）恰好从反面证明：它的执行能力是真的，
缺的是刹车——这正是二次开发该补的部分。

## 3. 守什么（骨架不改，只做周边叠加）

| 骨架资产 | 代码坐标 | 为什么不动 |
|---|---|---|
| 数据驱动多角色编排 | `agent/` | 改它等于重写运行时；能力应通过角色/工具/MCP 扩展 |
| 探索图与黑板 | `db/schema.sql:153`、`db/schema.sql:170`、`db/schema.sql:248`、`db/schema.sql:276` | 决定"攻击路径可交接、可回放" |
| 全量流量录制与索引 | `traffic/traffic.go:445` | 决定"每条结论能回指到具体请求" |
| findings ↔ 证据版本 | `db/schema.sql:1143`、`db/schema.sql:1144` | 决定"报告可复核、证据可追溯" |
| MCP / LLM profile / 调度 | `server/assembly.go:75` | 能力扩展点，只加不改 |

原则：**新增能力以周边叠加实现**；只有"证据/边界"类需求才允许触碰核心，且必须先有失败用例。

## 4. 改什么：只收紧两根轴

### 4.1 从"无刹车"到"边界为真"

| 收紧项 | 落点 | 机器锚点（CI 校验） |
|---|---|---|
| 未配置引擎=上游行为；配置即默认拒绝，判不清挂起 | `policy/engine.go` | `policy TestGlobalHoldStopsEverything` |
| 全量停止幂等，审计只发一次（不刷表） | `policy/hold.go` | `policy TestHoldEmitsAuditOnce` |
| 全量停止暂停任务、答复恢复后续跑（省 token，不空转） | `server/policy_hold_pause.go` | `server TestPolicyHoldPausesAndResumesTasks` |
| 范围/语义判定在**发包前**（L3 代理出口） | `traffic/policy.go` | `traffic TestL3ProxyBlocksOutOfScopeBeforeSending` |
| 在线域：策略启用后录制**不可关闭**、无代理拒绝启动 | `server/manager.go:488` | `server TestManagerRefusesDisablingCaptureUnderPolicy` |
| 离线域：域包声明 `runtime.requires_traffic_capture: false` 后**可免代理启动**、录制可关 | `policy/engine.go` | `server TestManagerStartsWithOfflinePackWithoutProxy` |
| 初始化入口要口令（未认证不可抢占） | `server/auth.go` | `server TestAuthInitRequiresSetupToken` |
| 随仓库发布的部署模板必须真的能装进引擎 | `policy/config.go` | `policy TestLoadEngagementAcceptsShippedTemplate` |

### 4.2 从"无证据断言"到"机器证据"

| 收紧项 | 落点 | 机器锚点（CI 校验） |
|---|---|---|
| 三道准入门：PoC 可复现 + ≥5 条反例 + ≥3 次跨源撞车比对 | `vulngate/gate.go` | `vulngate TestAssessPassesWhenBothGatesSatisfied` |
| 门三：平台经录制代理重放 PoC、机器判定、按实测抬高复现次数 | `server/finding_poc_replay.go` | `server TestFindingPocReplayBackfillsMachineEvidence` |
| 门二：平台代执行撞车检索（NVD / CISA KEV），查不动不算没撞车 | `novelty/novelty.go` | `novelty TestKEVSearchMatchesVersionedQuery` |
| 门二复核留痕：平台代检命中必须人看过才计数（谁复核、何时、依据哪条命中） | `vulngate/gate.go` | `vulngate TestAssessBlocksUnreviewedPlatformProbe` |
| 阶段 2–3：候选可疑点结构化登记，每条结论可回溯「入口→sink」路径 | `vulnpipe/vulnpipe.go` | `vulnpipe TestReachabilityStates` |
| 可达性由平台核对：流量 id 必须真实存在、源码必须在授权目录清单内 | `server/vuln_candidates.go` | `server TestVulnCandidateSourceHopScope` |

### 4.3 对外可验能力（接口必须真实存在于 `server/`）

- 判定状态与审计链：`/api/policy/status`、`/api/policy/decisions`、`/api/policy/chain`
- 全量停止闭环：`/api/policy/holds`、`/api/policy/holds/{id}/answer`
- 三道门：`/api/exploration/findings/{id}/gate`
- 门二机器证据：`/api/exploration/findings/{id}/gate/novelty/probe`
- 门三机器证据：`/api/exploration/findings/{id}/gate/poc/replay`
- 阶段 2–3 候选：`/api/exploration/candidates`、`/api/exploration/candidates/{id}`、`…/{id}/hops`、`…/{id}/status`、`…/{id}/link`

## 5. 风险登记（诚实记录，不美化）

1. **fail-closed 可能把探索切碎**：判不清就全量停，多次模糊请求会长时间停摆。
   缓解：域包调参 + 操作台答复闭环 + 挂起即暂停任务（避免空烧 token）。现状：已实现，仍需实战调参。
2. **强制录制让离线域也必须带代理**：这是"在线域合规"对"离线分析"的反噬。
   缓解：域包声明 `runtime.requires_traffic_capture`，离线域免代理启动、录制可关；
   在线域仍 fail-closed。现状：**已实现**（见 [`07-domain-packs.md`](07-domain-packs.md) §2.1），
   剩余打磨是离线域的证据供给走命令侧审计。
3. **门只在导出出口**：探索与候选生成阶段仍可能做无证据断言。
   缓解：门二/门三已机器化；剩余是探索期提示与阶段产物固化。现状：进行中。
4. **（成本）上游已闭源，没有上游可合**：骨架行为靠本仓库自己维护。
   缓解：把骨架行为写成测试与可校验坐标（本文档即对冲之一）。

## 6. 评审清单（每次改动前问自己）

1. 这条改动动的是**骨架**还是**周边**？
2. 它让证据链更连续，还是更断？
3. 边界是变硬还是变软？任何"方便一下"的放行都需要写清理由。
4. 新增的说法有没有**可机器校验的锚点**（测试 / 接口 / 代码坐标）？
5. 会不会让离线域能力被在线域规则反噬？

## 7. 本文档如何被校验

`internal/docscheck` 的测试会解析本文件并断言：

- `path:line` 形式的代码坐标真实存在，且行号不越界；
- `/api/...` 形式的接口在 `server/` 内有注册；
- §4 表格中的"机器锚点"是真实存在的测试函数（包名 + `TestXxx`）；
- 必需章节未被删除。

所以更新能力时请同步更新：**代码 → 测试 → 本文档坐标**，三者缺一，CI 会指出缺的是哪一处。
