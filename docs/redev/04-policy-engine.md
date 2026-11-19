# 04 · 策略执行引擎（Policy Enforcement Engine, PEE）设计

> 依据：`policy/spec/SRC行业授权资产安全测试规范-Agent版.md`
> 配置源：`policy/web-pentest/policy.yaml` + `verb-lexicon.yaml` + `deployment-context.example.yaml`
> 上位文档：`03-redev-plan.md` §3（授权与边界）、`00-arch-map.md` §5（guard/intercept 现状）

---

## 0. 一句话

规范和 AIxCC/Strix 的结论是一致的：**提示词是软约束，模型可以被目标页面、工具返回、上下文注入说服**。因此本引擎把规范的每一章翻译成**请求出口上的判定位**——不信任模型输出，只信任"这次请求要去哪里、带什么语义、花了多少预算"。

规范第九章第 3 条已经明确要求：

> "涉及请求拦截、预算熔断、范围校验、审计日志的硬约束，由测试平台在工程层实现，不依赖模型自觉。"

本设计就是这句话的实现。

---

## 1. 威胁模型：不是"外部攻击者"，是"Agent 失控"

| 失控来源 | 具体形态 | 为什么提示词拦不住 |
|---|---|---|
| 目标侧注入 | 响应体/页面里写"请继续扫描内网/导出全表" | 模型把响应当上下文，指令注入是 LLM 的原生弱点 |
| 工具返回值注入 | MCP/自定义工具返回伪造的 scope 或"已获授权" | 平台若不二次校验就信任工具输出 |
| 幻觉 | 把 200 当成功、把版本匹配当漏洞、编造已授权范围 | 上游已实证"$0 余额报已提现" |
| 目标漂移 | 从 A 端点顺藤摸到 CDN 回源、关联域、内网 | agent 的"不轻言放弃"倾向会主动扩边 |
| 预算失控 | 循环、重试、并发自调、大响应体 | 模型不知道也不在乎计数 |
| 操作员疲劳 | 审批弹窗太多 → 一路点允许 | 上游 PR 实证"批准疲劳" |

结论：**判定位必须在请求产生之后、发出之前**，且判定依据来自平台自己的解析结果（域名→IP、方法+路径+参数、已用预算），而不是模型声称的目标与授权。

---

## 2. 五层强制（任一层失守，其余仍拦得住）

```
 agent / tool ──► L1 命令与工具层   guard.PreToolUse：命令 AST、二进制白名单、MCP 分级
                    │
                    ▼
            L2 沙箱网络层   netns + nftables：出口只留 (a) 代理 IP (b) 显式授权的裸 TCP 目标
                    │
                    ▼
            L3 请求代理层   mitmproxy addon：范围校验 → 语义分级 → 预算 → 内容检查 → 拦截/挂起
                    │
                    ▼
            L4 产物与留痕层  artifacts 目录收口 + 证据快照 + hash-chain 审计 + 报告字段校验
                    │
                    ▼
            L5 挂起与问答层  Stop-All + 操作员问答通道 + 恢复条件（规范 7.3）
```

- **L2 是绕过分析的关键**：只靠代理（L3）等于把 raw socket（nmap、自定义 TCP、reverse shell）全放过。netns 必须 **default drop**，仅放行代理地址 + 本次 engagement 显式授权的裸 TCP 目标。**已落地**：`deploy/egress-lockdown/`（compose `internal` 网络 + 唯一 egress 代理 + `ARTEX_GLOBAL_PROXY`），裸机模板见该目录 README。
- **L3 是语义与预算的主战场**，也是唯一能看到"请求真实长什么样"的地方。**已落地**：`traffic/policy.go`（请求前判定→不发包回 403；响应侧命中即截断→原文不进模型上下文），判定经 `server/policy_audit.go` 异步落 `policy_decisions`（hash chain）。
- **L4/L5 负责"停得住、说得清"**，对应规范第七章、第八章。

---

## 3. 组件设计

### 3.1 Scope Resolver

输入：目标 host / URL。输出：`in_scope | out_of_scope | ambiguous | internal | metadata` + 解析链证据。

流程：

1. 归一化（大小写、尾点、punycode、URL 解码）。
2. 匹配 engagement.allow（精确 / 通配）与 exclude（优先）。
3. 解析：A/AAAA + **完整 CNAME 链**；命中 `third_party_detect.cname_suffix` → `ambiguous`（规范 1.1：第三方托管/CDN 回源按范围外）。
4. ASN 查询（可选，离线库）：非客户 ASN → `ambiguous`。
5. 解析后 IP 命中 `internal_cidrs_deny` / `metadata_deny` → `internal`（红线 4）。
6. **DNS 固定**：解析结果缓存并钉住，请求时校验连接 IP 与之一致（防 DNS rebinding）。

判定：`allow` / `deny` / `ask`（`ambiguous` 一律 ask，且**默认不恢复测试**，需操作员答复——规范 7.3）。

### 3.2 Request Semantics Classifier（规范第四章）

输入面：`method`、path segments、query keys/values、body keys/values（json/form/multipart）、关键 headers（`_method`、`X-HTTP-Method-Override`）。

归一化：小写、去 `_-` 分隔符、拆分 camelCase、URL 解码、中文/拼音归一（`shanchu`→`delete`）。

判定顺序（命中即停，不再往下）：

1. `rest_method_class`（DELETE→A，PUT/PATCH→B，TRACE→deny，POST→继续）；
2. 显式动词（path/body key/body value 命中 A/B/C/D/E/F 词表）；
3. 参数开关（`_method`、`action=purge`、`type=hard_delete`、`force=true`、`is_cover=1`）；
4. 批量形态（`*All`、`batch*`、`*ByIds`、`truncate*`）；
5. 中文/拼音；
6. 仍不确定 → `llm_fallback`（**只用于消歧，默认 deny，判定过程全量入库**）。

输出：`{class, matched_rule, confidence, evidence}`。

**换皮即违规**（规范 4.1）：分类器命中"动词换皮/方法伪装/参数开关"组合且曾被拒时，直接记为规避规范，触发红线而非普通拒绝。

### 3.3 Budget Engine（规范 5.3 + 第三章）

计数器维度：`(engagement, task, host, class)`，另加全局熔断。

| 计数器 | 默认 | 来源 | 超限动作 |
|---|---|---|---|
| `vuln_samples` | 5 | 5.3 | 硬停 + hold |
| `rate_rps_per_host` | 5 | 第三章 2 | 节流后拒绝 |
| `concurrency_per_host` | 3 | 第三章 2 | 排队后拒绝 |
| `retry_max` | 1 | 第三章 2 | 拒绝 |
| `total_requests_per_task` | 20000 | 兜底 | 硬停 + hold |
| `send_actions` | 5 | 5.3 | 拒绝 |
| `pii_active_fetch` | 10 | 5.3 | 硬停 + hold |
| `response_body_max_mb` | 10 | 5.3 | 截断 + 告警 + 计数 |
| `internal_lateral_hosts` | 0 | 5.3 | 请求前 deny |
| `sql_proof` | identity_functions | 5.3 | UNION/into outfile/堆叠写 → deny |
| `test_accounts` | 2 | 5.3 | 账户白名单外 → deny |

**不自调**（第三章 2）：rate/concurrency/timeout/retry 只能由**平台配置**，模型或自定义工具传入的同名参数一律丢弃并记违规。

**脚本必须内置计数**（第三章 1）：平台检查脚本正文是否含计数与 `exit`（静态检查 + 运行时包装），不满足则拒绝执行。

### 3.4 Content Inspector（规范 5.4 / 5.1）

响应返回后、进上下文前执行：

- **体积**：> `response_body_max_mb` → 截断 + 标记"疑似拖取"。
- **敏感命中即停**：源码特征（`<?php`、`package main`、`import React`）、配置文件（`application.yml`、`.env`、`web.xml`、`bootstrap.*`）、密钥/Token/DSN/`BEGIN PRIVATE KEY`/`/etc/shadow` 形态、云凭证文件。命中 → hold + 报告只登记**类型与位置**，不落全文。规则集：`policy/patterns/secret.txt`（30 条，已按 **Go RE2** 校验可编译；RE2 不支持 lookaround，确需前后断言时换 `regexp2` 并在 CI 里加"全部规则可编译"测试）。
- **规模克制**（5.1）：优先读 `total`/`count`/`COUNT(*)`；数组类响应只保留前 3 条进入模型上下文，其余计数。
- **PII 计数**：单响应 ≥3 条命中才计数（5.3）。

### 3.5 Command Policy（规范 6.4 / 第三章 1）

适用：`shell_open`/`shell_send`/Bash，尤其是 RCE 与 webshell 会话。

- **用 AST 解析，不用正则**（正则可绕过：`w'h'oami`、`$()`、`|`、`&&`）。
- RCE/webshell 仅允许 `rce_exec_allowlist`（whoami/id/uname/hostname/ifconfig/ipconfig），其余 deny。
- 禁解释器内联（`bash -c`、`python -c`、`base64 -d | sh`）、禁网络工具、禁写/提权/持久化命令。
- 二进制白名单制：`nuclei/ffuf/dirsearch/sqlmap/hydra/nmap/masscan` 等默认 deny，需 `per_use` 审批（第三章 3）。

### 3.6 Hold Controller（规范第七章）

- **Stop-All 语义**：任何 hold 触发的都是任务级暂停——不仅是当前接口，还包括"顺手"的只读探测（7.3）。
- **问答通道**：hold 时把原问题原样转述给操作员（不润色、不改写），未获明确答复前不恢复；答复模糊则再问。
- **自动异常检测**：5xx 比例 > 阈值、WAF/拦截页特征、响应体结构突变（疑似数据变化）→ 立即 hold 并告警。
- **恢复**：只有 `explicit_operator_answer` 且 `compliance.spec_version` 一致才恢复；恢复本身入审计。

### 3.7 Handshake & Context Injection（规范 9.1 / 9.2）

- 任务启动时把规范正文 + **部署上下文块**渲染进 system prompt；平台同时把同一份配置写进 `engagement_policy` 表，保证**提示词与工程层读的是同一份数据**。
- 校验首个模型响应以 `[RULES_LOADED v2.5]` 开头；不匹配 → **禁用全部工具**（不是警告，是拒绝）。
- 部署上下文缺任一必填项（scope / test_accounts / allowed_tools / report / artifacts）→ 任务降级为**被动分析**（不发包）。

### 3.8 Audit & Evidence（规范第八章 + 红线 8）

每条请求一行：`ts, engagement, task, target, resolved_ips, class, decision, rule_id, budget_snapshot, decision_source(policy|llm|operator), model, tool, operator`。
追加 `prev_hash` 形成 hash-chain；报告生成时校验链完整，证据（traffic snapshot）与 finding 绑定（复用 `evidence.Store`）。

---

## 4. 与现有代码的映射

| 规范条款 | 落点 | 改动 |
|---|---|---|
| 1.x 范围 | `db/asset_intercept_match.go:172-194` 复用 `EvaluateAssetGate` + 新增 `intercept/scope.go` | 新增 |
| 4.x 语义分级 | `intercept/semantics.go`（新）+ `policy/verb-lexicon.yaml` | 新增 |
| 2.x 红线 | `policy` 判定表（新），在 `guard/guard.go:83` `applyIntercept` **之前**执行 | 新增预步骤 |
| 3.x 工具 | `server/customtool.go`（自定义工具执行）+ 沙箱二进制白名单 | 改 |
| 5.x 预算/内容 | `traffic/traffic.go` addon（`:515-700` 已有 sanitize 钩子）+ `intercept/budget.go`（新） | 改 + 新增 |
| 6.4 RCE 允许集 | `guard/guard.go:62-76` 现有的 Bash/shell 特判处扩展为 AST 判定 | 改 |
| 7.x 挂起 | `intercept` 的 ask/pending（已有）+ `server/engine.go:1006` 上下文 → 新增任务级 hold | 改 |
| 8.x 报告 | `report/` + `evidence/` + finding schema 校验 | 改 |
| 9.x 握手 | `agent/promptcatalog.go` + 首响应校验（`agent/worker.go`/`chat.go`） | 改 |
| 配置承载 | `db/schema.sql` 新增 `engagements` / `engagement_policy` / `policy_decisions` / `budget_counters` / `holds` | 新增 |

> 注：`Guard` 有两个构造点（`server/intercept.go:27-29` 与 `server/manager.go:849`），必须同时接上 scope 与命令策略，否则 worker 与 chat 行为不一致。

---

## 5. 数据模型（草案）

```sql
CREATE TABLE engagements (
  id BIGSERIAL PRIMARY KEY, client TEXT NOT NULL, title TEXT NOT NULL,
  authorization_doc_path TEXT, authorization_doc_sha256 TEXT NOT NULL,
  starts_at TIMESTAMPTZ NOT NULL, ends_at TIMESTAMPTZ NOT NULL,
  spec_version TEXT NOT NULL, handshake_token TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE engagement_policy (        -- 与 deployment-context 同源，避免"提示词说的和代码判的不一样"
  engagement_id BIGINT PRIMARY KEY REFERENCES engagements(id) ON DELETE CASCADE,
  scope JSONB NOT NULL, test_accounts JSONB NOT NULL, allowed_tools JSONB NOT NULL,
  budget JSONB NOT NULL, report JSONB NOT NULL, artifacts JSONB NOT NULL,
  egress_allowlist JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policy_decisions (
  id BIGSERIAL PRIMARY KEY, engagement_id BIGINT, task_id BIGINT,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(), target TEXT, resolved_ips TEXT[],
  req_class TEXT, decision TEXT NOT NULL, rule_id TEXT, reason TEXT,
  budget_snapshot JSONB, decision_source TEXT, model TEXT, tool TEXT, operator TEXT,
  prev_hash TEXT, hash TEXT
);

CREATE TABLE budget_counters (
  engagement_id BIGINT, task_id BIGINT, host TEXT, name TEXT,
  used NUMERIC NOT NULL DEFAULT 0, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (engagement_id, task_id, host, name)
);

CREATE TABLE holds (
  id BIGSERIAL PRIMARY KEY, task_id BIGINT NOT NULL, reason TEXT NOT NULL,
  question TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',   -- open|answered|resumed
  answer TEXT, answered_by TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  answered_at TIMESTAMPTZ
);
```

---

## 6. 一次请求的判定流程（伪代码）

```go
func (e *Engine) OnRequest(r *Request) Decision {
    // 0. 计划/规范版本
    if !e.handshakeOK r.Task { return hold("RULES_NOT_LOADED") }
    if !e.inWindow(r.Engagement) { return deny("OUT_OF_WINDOW") }

    // 1. 范围（规范 1.x）
    sc := e.scope.Resolve(r.Host)
    switch sc {
    case OutOfScope, Internal, Metadata: return deny("R1_SCOPE")
    case Ambiguous:                      return hold("SCOPE_UNCERTAIN")  // 7.3 不自动恢复
    }

    // 2. 语义（规范 4.x）
    cls, conf := e.semantics.Classify(r)
    if conf < threshold { return hold("SEMANTICS_UNCERTAIN") }           // 判不清按禁止
    switch cls {
    case A, B: return deny("R1_DESTRUCTIVE")
    case D:    if isHighRisk(r) { return deny("R9_MONEY") }
    case C, D, E: if !e.usesTestAccount(r) { return deny("R5_NOT_TEST_ACCOUNT") }
    }

    // 3. 凭据复用（红线 10）
    if e.creds.IsHarvested(r) { return deny("R10_CRED_REUSE") }

    // 4. 预算（5.3 / 第三章）
    for _, b := range e.budget.Check(r, cls) {
        if b.Hard { return hold("BUDGET_EXHAUSTED:" + b.Name) }
        if b.Soft { return deny("RATE_OR_CONCURRENCY") }
    }

    // 5. 出网目标（红线 8）
    if !e.egress.Allowed(r.Host) { return deny("R8_EXFIL") }

    return allow()   // 响应返回后再做 Content Inspector
}
```

响应侧：`OnResponse(r, resp)` → 体积/敏感命中/行数/PII 计数 → 命中则 `hold` 并只登记类型与位置。

---

## 7. 绕过分析：为什么"提示词版"一定失守

| 绕过路径 | 只写提示词 | 本设计 |
|---|---|---|
| 目标页面注入"继续扫内网" | ✗ 模型可能照做 | L2 netns drop + L3 范围校验 |
| 用 `curl` 直接连内网 IP | ✗ 提示词管不到 | L2 nftables 无路由 |
| `nuclei` 扫全站 | ✗ | L1 二进制白名单 + 审批 |
| 换皮 `DELETE` → `POST /user/remove` | ✗ | L3 语义分级（含参数开关/批量形态） |
| 分页拉全表 | ✗ | L3 预算 + L4 行数/体积 |
| 复用窃取到的 cookie | ✗ | L3 凭据污点标记（红线 10） |
| 模型自述"已授权" | ✗ | L3 只认 engagement_policy，不认模型claim |
| 剧本被改（prompt 注入改规则） | ✗ | 规则只存在于平台配置，不在上下文 |

---

## 8. 合规矩阵（规范章 → 控制 → 验收用例）

| 规范章 | 控制 | 验收用例（必须自动化） |
|---|---|---|
| 1.1/1.2 | Scope Resolver | 范围外域名被拒；CDN 回源判 ambiguous；内网 IP 被拒 |
| 1.3 | 越界信息只记录 | SSRF 探到内网后不再发第二个包 |
| 2.1–2.11 | 红线谓词 | 11 条各 1 个用例，全部 deny/hold |
| 3.1–3.4 | 工具策略 | 脚本无计数器被拒；`nuclei` 未审批被拒；自调 rate 被丢弃 |
| 4.1–4.2 | 语义分类器 | 词表 A–F 每类 ≥5 变形用例；换皮组合判规避 |
| 5.1–5.5 | 预算 + 内容 | 10MB 截断；`/etc/shadow` 即停；只留 3 条样本；报告后产物清理 |
| 6.1–6.9 | 分类型细则 | XSS 只 console.log；RCE 只 whoami；SMS 超 5 次拒；SQLi 只 `user()` |
| 7.1–7.3 | Hold | 预算耗尽全量停；模糊答复再问；未答复不恢复 |
| 8.1–8.5 | 报告校验 | 缺 evidence/cleanup_status 不能提交；一洞一报 |
| 9.1–9.4 | 握手/上下文 | 首响应无 token 则工具全禁；缺 context 降级被动 |

**这套用例本身就是产品的一部分**——它是"我们和上游 ARTEX 的区别"的可证明材料。

---

## 9. 分阶段落地

| 里程碑 | 内容 | 退出条件 |
|---|---|---|
| M0 观测 | 全量判定入库，`mode: warn` | 一周真实流量，误拦率可量化 |
| M1 强制 | `mode: hard`，L1+L2+L3 生效 | 合规矩阵 1/2/4 章用例全过 |
| M2 预算 | 5.3 表 + 熔断 + 内容检查 | 3/5/6 章用例全过，大响应不再进上下文 |
| M3 挂起 | Stop-All + 问答通道 + 异常检测 | 7 章用例全过 |
| M4 报告 | 字段校验 + 证据链 + 清理 | 8/9 章用例全过 |

---

## 10. 与离线域的关系

本规范只治理**在线测试**（`web_pentest` / `bounty_recon`）。离线域（二进制逆向、源码审计、样本分析、蓝队）用另一套策略：

- **默认无出网**（netns drop，无代理）；
- 样本只进不出、权限 0400、目录不挂宿主；
- VT/情报查询按 **hash** 查询，不默认上传样本；
- 产物隔离，报告模板不同（IOC/TTP/规则而非漏洞）。

这也是为什么"内核 + 域包"是正确抽象：**策略也是按域打包的**，不是一个全局开关。

---

## 11. 未决问题

1. 规范 §9.1 要求 `[RULES_LOADED v2.5]` 且"版本与文件头一致"，但**文件头没有版本号**。建议：规范文件头补 `version: 2.5`，平台从 `policy.yaml:spec.version` 读取并校验，二者不一致直接拒绝启动在线域。
2. 规范的"配套《使用手册》"未提供，`deployment-context` 的字段是我们按 §9.2 反推的，需要与客户确认字段名与必填项。
3. 语义分类器的 LLM 兜底是否允许？规范 4.1 说"判不清按禁止"——建议默认 **deny + 人工问询**，LLM 只作为给出"为什么判不清"的辅助，不参与放行。
4. `ambiguous`（第三方托管/归属不明）的放行流程需要客户侧模板，目前设计为"问询后人工确认并留痕"。
5. 审计日志留存期与客户数据删除期需要在 engagement 里显式约定（默认 30 天）。
