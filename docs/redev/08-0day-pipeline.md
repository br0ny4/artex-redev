# 0day 流水线与三道准入门的工程设计

> 状态：门一（反例验证）、门二（撞车比对）、门三（触发验证/PoC）已实现并强制在导出
> 出口；门二支持平台代执行检索（NVD / CISA KEV），门三支持平台代执行重放（`kind=http`），
> 证据由机器产生；流水线其余环节逐步接入。代码：`vulngate/`（判定）、`db/finding_gate.go`（存取）、
> `server/finding_gate.go`（接口与导出拦截）。

## 1. 目标

把一个"看起来可疑"的观察变成**可以提交的 0day 结论**。这条链上最容易出问题的地方
不是"找不到漏洞"，而是**找到的其实是误报、或者早就被人报了**：

- 误报：把正常业务行为当成漏洞（比如"接口返回 401 但内容包含用户 id"），
  交付给客户后被打回，报告可信度归零；
- 撞车：把一个已公开的 CVE 当作新发现提交，浪费客户时间，还可能被判定抄袭。

所以流水线的准入不是"模型说它验证过了"，而是**两条可逐条核对的门**。

## 2. 流水线

| 阶段 | 产出 | 平台能力 | 状态 |
|---|---|---|---|
| 1. 攻击面提取 | 入口清单（路由/参数/文件格式/二进制入口） | `source-audit` 域包（semgrep/joern/ast-grep）、`binary-re`（radare2/Ghidra） | ✅ 域包就绪 |
| 2. 候选生成 | 可疑点（sink 未过滤、危险解析、逻辑缺陷） | `add_candidate` 工具 → `vuln_candidates` 表；`GET/POST /api/exploration/candidates` | ✅ 结构化工件 |
| 3. 可达性确认 | 触发路径（从外部输入到 sink 的真实路径） | 平台逐跳核对：在线域 `traffic` id 必须真实存在、离线域 `source` 必须在 `scope.local_paths` 内且行号有效 | ✅ 平台核对（agent 自述不算） |
| 4. 触发验证 | 可复现的 PoC（请求/命令/样本），无 PoC 不算 finding | guard 放行条件下的真实执行 + `PUT …/gate/poc` 落库 | ✅ 强制 |
| **5. 门一：反例验证** | ≥5 条反例记录 | `POST /api/exploration/findings/{id}/gate/counterexamples` | ✅ 强制 |
| **6. 门二：撞车比对** | ≥3 次跨源检索记录 | `POST /api/exploration/findings/{id}/gate/novelty` | ✅ 强制 |
| **5b. 门三：触发验证** | 1 份 PoC（kind/input/observed/evidence + ≥2 次复现） | `PUT /api/exploration/findings/{id}/gate/poc`、`POST …/gate/poc/replay` | ✅ 强制 |
| 7. 报告与提交 | 交付物 | 导出接口（门未过则 409） | ✅ 强制 |

### 阶段 2–3：候选与可达性（不是第四道门）

门回答"能不能交付"，阶段 2–3 回答"结论从哪来"。候选**不阻断导出**——它是证据链的起点，
用来让报告里的每条结论都能回溯到"谁在什么位置发现了什么、这条路径核对过没有"。

- 数据：`vuln_candidates`（title/kind/location/entry/sink/rationale/status/reachability）+
  `vuln_candidate_hops`（ordinal/ref_kind/ref/claim/verified/verified_detail）。
- 登记：agent 用 `add_candidate`（worker/planner/mainagent/auto/pentest 默认绑定），
  或 `POST /api/exploration/candidates`。`title`、`location` 必填；`entry`/`sink` 允许空，
  那正是阶段 3 要补的。
- 核对：每次**读取**候选（列表/详情/准入页）都会重做一遍逐跳核对，因为流量索引会被清理、
  源码文件会被移走。核对结果写回 `verified`/`verified_detail`，再由 `vulnpipe.Reachability`
  算出 `unknown / claimed / partial / verified`。
  - `traffic` 跳：`traffic.Get(ref)` 必须命中，detail 带 `<id> · <请求行>`；未开启录制或
    id 不存在都判未通过（"编的 id 或已被清理"）。
  - `source` 跳：`ref` 形如 `path/to/file.go:123`。相对路径逐个拼到
    `policy.Default().Engagement().Scope.LocalPaths` 的授权根下；不在任何根内 → "不在授权目录"；
    文件不存在/行号越界（上限 20 万行）→ 明确报错。没有目录清单授权时一律"无法核对"。
  - `command`/`other` 跳：平台不代跑，标"需人工复核"。
- 转结论：`report_finding` 新增 `candidate_id`（或 `POST …/candidates/{id}/link`），
  关联后候选 `status=converted`，`get gate` 响应带出 `candidates` 列表。
- 为什么不做第四道门：离线域没有流量、有些结论只有人工命令证据；把候选设成阻断会让
  流水线退化成"必须先造一条路径才能报漏洞"。三道门（反例/撞车/PoC）仍是唯一准入标准。

## 3. 为什么三道门必须在工程层

提示词是软约束。模型完全可以没做任何验证，就在报告里写"已用 5 个反例验证，未发现
重复"。所以门**只认结构化记录**，且判定逻辑不接受"我验证过了"这种自由文本：

### 门一：反例验证（`vulngate.MinCounterexamples = 5`）

每条反例必须填齐并**通过**（`passed=true` 表示漏洞在该反例条件下没有出现）：

| 字段 | 含义 |
|---|---|
| `claim` | 这条反例要排除的误报路径（越具体越好） |
| `method` | 验证手法（变体输入 / 降级条件 / 对照环境） |
| `expected` | 正常情况下应观察到什么 |
| `observed` | 实际观察到什么 |
| `evidence` | 可核对凭据（流量 id / 命令输出摘要） |
| `traffic_ids`（可选） | 引用的真实流量 id；录入时服务端逐个核对存在性，编造的 id 直接 400 |

两条额外的硬规则：

- **必须覆盖不同路径**：`method|claim` 归一化后去重，5 条不能是同一手法的 5 个副本
  （否则等于只测了一次）。这条规则来自真实教训：模型很擅长把一个测试复制五遍。
- **有任一条未通过即阻断**：如果反例条件下漏洞仍然出现，要么降级为误报，
  要么补充证据说明差异（这通常意味着原来的判定条件写错了）。

### 门三：触发验证（`MinReproductions = 2`）

**无 PoC 不算 finding。** 一条 finding 只保留一份 PoC（写了新的覆盖旧的——"能复现的
触发方式"应当是收敛结论，一堆互相矛盾的 PoC 在报告里没有价值）：

| 字段 | 含义 |
|---|---|
| `kind` | 触发方式：`http` / `command` / `file` / `sample` |
| `input` | 可复制粘贴的复现步骤（别人照着做就该看到同样结果） |
| `expected` | 预期表现（漏洞存在的样子） |
| `observed` | 实际观察到的结果 |
| `reproduced` | 连续复现成功次数，**至少 2**：一次成功可能是缓存、上游偶发、时序或上一次请求的残留状态 |
| `evidence` | 流量 id / 命令输出摘要 |
| `expect_status`（可选） | 机器可判的预期状态码；给了它平台才能代跑重放并自动判定是否复现 |
| `expect_body_contains`（可选） | 机器可判的响应体片段（大小写不敏感包含；只写能证明漏洞存在的最短片段） |

#### 平台代执行重放（`POST /api/exploration/findings/{id}/gate/poc/replay`）

`reproduced` 由人/agent 填写，本身可以造假。重放把"真的跑过"从声明变成机器事实：

- 只支持 `kind=http`：命令/文件/样本涉及在宿主机执行目标代码，平台不代跑（要动态
  行为请换沙箱 + `binary-re` 域包）。
- 必须经过录制代理：录制关闭时直接 409。这样重放也会落进流量索引，形成证据链，
  而且范围/语义/预算仍由 L3 判定（判不过的请求不会到达目标，`X-ArtEx-Policy` 会被
  记录为"被规范执行层拦下"，不算复现）。
- 判定用 `expect_status` + `expect_body_contains`；没填 `expect_status` 直接 400
  （无法机器判定），不给"看起来像复现"的模糊空间。
- 一致的重放：`reproduced` 抬到"机器实测一致次数"（只增不减），`observed` 回填
  `平台重放 METHOD URL -> HTTP n`，`evidence` 回填真实流量 id；每次重放都落
  `finding_poc_replays` 历史（客户端可用 `poc_replays` 查看到底跑过几次、结果如何）。
- 不一致的重放只进历史，**不覆盖**人写的 `observed`：失败结果盖掉人的判断，
  等于把"这次没复现"洗成"复现了"。
- 门本身仍只看 `reproduced >= 2`；重放情况通过 `gate.notes` 提示（"平台重放已验证 N 次"
  /"目前只有人工录入证据"），不额外阻断——离线域无法重放，改成阻断要按域包配置，
  留给后续。

### 门二：撞车比对（`MinNoveltyQueries = 3`、`MinSourceClasses = 2`）

每次检索记录：`query`（实际关键词）、`source_class`（`cve|vendor|github|advisory|search|other`）、
`hits`（命中的标题/链接）、`same_vuln`（是否命中同一致命漏洞）、
`origin`（`manual|platform`）、`reviewed_by` / `reviewed_at` / `review_note`（复核留痕）。

- 至少 **3 次不同检索**（大小写/空白归一化后去重）；
- 至少覆盖 **2 类信息源**——只查 CVE 库不算比对完，厂商公告、代码托管平台上的 issue、
  漏洞库检索都要看；
- 任何 `same_vuln=true` **直接阻断**并带上命中编号（如 `CVE-2026-99999`），
  因为重复提交是负资产。

#### 平台代执行检索（`POST /api/exploration/findings/{id}/gate/novelty/probe`）

人工登记的 query/hits 只能证明"agent 说它查过"。平台代检把这一步也变成机器事实：

- 内置两个免鉴权源：**NVD**（`source_class=cve`，`keywordSearch` 全文检索）与
  **CISA KEV**（`source_class=advisory`，已知被利用漏洞目录，进程内缓存 6 小时）。
  两者恰好覆盖门二要求的"≥2 类信息源"。
- 词形差异要兜住：NVD 的 `keywordSearch` 是整词 AND，直接查 "apache httpd path
  traversal" 会得到 0 条；所以无命中时**自动退一步**只用产品/版本词重查（去掉
  path/traversal/rce 等通用词），命中的标题带 `[下发日期]` 前缀——NVD 结果按时间升序，
  不标日期的话 1999 年的条目和上个月的看起来一样像撞车。KEV 目录不写版本号，所以按
  关键词覆盖度计分（多词查询至少命中 2 个词，`httpd↔HTTP Server`、`rce↔Remote Code
  Execution` 做同义词展开），命中标题写明"匹配 N/M 关键词"，阈值内取覆盖度最高的 5 条。
- 平台**只负责查与记**：命中条目（编号 + 标题 + 可核对链接）原样落库，标记
  `origin=platform`；"是不是同一个漏洞"**故意不自动判定**——机器猜错会放过重复项，
  也可能把真 0day 判成重复。操作员复核后手动标记 `same_vuln`。
- **查不动 ≠ 没撞车**：某个源失败时不落"干净"记录，失败原因在响应的 `errors` 里带出；
  全部源都失败直接 502。把超时写成"未命中"是最危险的假证据。
- 一次最多 5 条查询、每条至少 3 个字符：撞车比对靠准确关键词，不是把产品名丢给库。
- `gate.notes` 会注明"撞车比对已由平台代执行 N 次检索"或"目前只有人工登记记录"，
  不额外阻断（离线域/内网环境检索不到公网），但报告评审时一眼能看出证据成色。

#### 复核留痕（`POST /api/exploration/findings/{id}/gate/novelty/{nid}/review`）

平台代检解决"谁去查的"，复核留痕解决"谁看过的"。机器只认"查到了哪些条目"，
**不替人判"是不是同一个漏洞"**（猜错两个方向都危险：把无关 CVE 当撞车=放弃真 0day；
把同一漏洞当无关=重复提交）。所以有命中的平台代检记录必须人工复核：

- 入参：`reviewed_by`（复核人，必填）、`same_vuln`（是否撞车）、`note`（依据；
  **判撞车时必填**——要写清依据哪条命中、为什么是同一个漏洞）。
- 复核结论写回同一条记录（`same_vuln` / `reviewed_by` / `reviewed_at` / `review_note`），
  可改判，留的是最新判断；`GET …/gate` 会带出留痕。
- **未复核的平台代检记录阻断门二**：原因写明"平台代检记录尚未复核（N 条）"，
  `gate.novelty_unreviewed` 给出数量。机器查了但没人看，不算撞车比对完成。
- 人工登记（`origin=manual`）的记录天然是人写的，不需要再复核一遍。

## 4. 接口

```bash
# 登记一个候选可疑点（在线域用真实 traffic id 做跳，离线域用源码位置）
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"task_id":7,"title":"订单查询 id 直接拼 SQL","kind":"sink","location":"https://shop.example.com/api/order/detail","rationale":"id 未做参数化","hops":[{"ref_kind":"traffic","ref":"a1b2c3","claim":"入口请求把 id 原样传入"}]}' \
  http://127.0.0.1:8787/api/exploration/candidates

# 候选列表（每次读取都会重做逐跳核对，reachability 是平台算的）
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8787/api/exploration/candidates?task=7&limit=50"

# 把候选转成结论（也可在 report_finding 里带 candidate_id）
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"finding_id":12}' \
  http://127.0.0.1:8787/api/exploration/candidates/3/link

# 查看当前门状态与还差什么
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8787/api/exploration/findings/12/gate

# 记一条反例
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"claim":"未登录访问同一接口","method":"去掉会话 Cookie 重放","expected":"返回 401 且不含用户数据","observed":"返回 401，body 为空","passed":true,"evidence":"traffic: a1b2c3"}' \
  http://127.0.0.1:8787/api/exploration/findings/12/gate/counterexamples

# 记一次撞车比对（人工登记）
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"ACME Gateway 4.2 RCE","source_class":"cve","hits":[],"same_vuln":false}' \
  http://127.0.0.1:8787/api/exploration/findings/12/gate/novelty

# 复核一条平台代检命中（撞车时 note 必填，写清依据哪条命中）
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"reviewed_by":"alice","same_vuln":false,"note":"命中是另一产品线，不构成撞车"}' \
  http://127.0.0.1:8787/api/exploration/findings/12/gate/novelty/7/review

# 平台代执行撞车检索：真的请求 NVD / CISA KEV，命中条目落库（origin=platform）
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"queries":["acme gateway 4.2 rce","acme gateway authentication bypass"]}' \
  http://127.0.0.1:8787/api/exploration/findings/12/gate/novelty/probe

# 写触发验证（PoC），reproduced 至少 2；带 expect_status 的 http PoC 可让平台代跑重放
curl -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind":"http","input":"GET /api/order?id=2 HTTP/1.1\nHost: target.example.com\nCookie: sid=...\n","expected":"返回他人订单","observed":"返回了他人的订单内容","reproduced":2,"evidence":"traffic: a1b2c3","expect_status":200,"expect_body_contains":["user_id"]}' \
  http://127.0.0.1:8787/api/exploration/findings/12/gate/poc

# 平台代跑重放：经录制代理真实发包，一致则复现次数按机器实测抬高
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8787/api/exploration/findings/12/gate/poc/replay
```

写错可撤回：`DELETE .../gate/counterexamples/{ceid}`、`DELETE .../gate/novelty/{nid}`、
`DELETE .../gate/poc`。

## 5. 导出出口的强制点

`GET /api/exploration/findings/export` 在打包前逐条评估，任何一条未过门：

```json
HTTP 409
{
  "error": "导出被 0day 准入拦下：每条结论都需要一条可复现的 PoC（≥2 次连续复现）、≥5 条反例验证与 ≥3 次跨源撞车比对。补齐后可重试；确需跳过用 force=1&reason=…（会记日志）。",
  "blocked": [
    {"finding_id": "12", "name": "订单接口越权", "verdict": "blocked",
     "reasons": ["触发验证缺失：没有 PoC 不算 finding", "反例验证不足：需至少 5 条通过的反例，当前 2 条", "撞车比对不足：需至少 3 次不同检索，当前 0 次"]}
  ],
  "requirements": {"min_counterexamples": 5, "min_novelty_queries": 3, "min_source_classes": 2, "min_reproductions": 2}
}
```

确认要跳过时：`?force=1&reason=客户明确要求在报告中保留此条`（服务端记日志）。
迁移旧数据/特殊流程可整体关闭：`ARTEX_FINDING_GATE=off`——**这是逃生口，不是默认**。

## 6. 已知缺口（诚实记录）

1. **凭据核对只覆盖显式 `traffic_ids`**：反例可以引用 `traffic_ids`，服务端会核对它们
   确实存在于流量索引（编造的 id 返回 400）；但 `evidence` 自由文本里的 id 不做解析，
   且尚未**强制**在线域必须引用真实流量。
2. **平台代检只覆盖两个免鉴权源**：NVD + CISA KEV 已能证明"查过、结果是这样"，但
   GitHub issue、厂商公告、搜索引擎仍需人工登记（这些源要么要 token，要么防抓取）。
   覆盖面上限取决于接入的源；下一步是接可配置的检索 MCP，并让"是否同一个漏洞"的
   复核结果也留痕（谁复核的、依据哪条命中）。
3. **候选的可达性是"核对证据"，不是"证明可达"**：平台只能确认跳里引用的流量/源码确实存在，
   不能证明这些跳串起来真的构成一条从外部输入到 sink 的完整路径——那要靠阶段 4 的 PoC
   去证明。所以 `verified` 只表示"引用的东西是真的"，不等于"漏洞成立"。
4. **重放只覆盖 `kind=http`**：平台已能代跑 HTTP PoC 并逐次判定、回填真实流量，但
   `command`/`file`/`sample` 类 PoC 仍在宿主机由人/agent 执行（平台刻意不代跑）。
   代价是这几类"真的跑过吗"仍靠自觉；下一步是把沙箱执行结果也纳入机器证据
   （沙箱回执 + 样本哈希），或按域包声明哪些 kind 可以阻断。
