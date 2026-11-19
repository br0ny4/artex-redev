# ARTEX — 项目状态、滥用事件与 fork 风险评估

> 调研日期：2026-11-18。对象：开源项目 ARTEX（作者 GitHub 用户 `Autumn-27`），本地副本为 `v0.3.15`（CHANGELOG 日期 2026-10-07）。
> 本文只写有出处的事实；每条结论标注置信度，找不到的东西明确写"未找到"。

## 0. 证据分级与方法

| 标记 | 含义 |
|---|---|
| **[VERIFIED]** | 本次调研直接抓取到一手页面/文档，或在本仓库源码中直接读到该行为 |
| **[REPORTED]** | 来自可信度较高的二手报道（厂商博客、CERT、主流安全媒体），原文一手材料未能直接打开 |
| **[UNVERIFIED]** | 论坛、聚合站、二手转述，未获独立确认，只能当作线索 |

方法：`web_search`（中英文多组查询）→ `web_fetch` 关键页面 → 与本地源码交叉验证。每节末尾给出该节的已知缺口。

本次调研**无法**完成、且已在文中标注的验证：
- `web.archive.org` 在本次会话中所有抓取均失败（`TypeError: fetch failed`，多次换 URL 形式重试），**因此没有任何 Wayback 快照被实际打开**。文中凡涉及"下架时间"的证据来自厂商时间线与新闻，而非 archive.org。
- `hub.docker.com` 同样无法直接抓取（同样 `fetch failed`）。Docker Hub 镜像状态依赖二手证据。
- FBI FLASH 原始 PDF（`https://www.ic3.gov/CSA/2026/261113.pdf`）返回 `unsupported content type "application/pdf"`，**未能读取原文**；其内容通过三家独立报道交叉引用。
- Google GTIG 原博客（cloud.google.com）抓取失败；通过二手摘要引用，已标注。
- 微信公众号 `wx.secv.cc` 的文章抓取失败，仅得搜索摘要，已标注 [UNVERIFIED]。

---

## 1. 项目状态（Project status）

### 1.1 现状摘要

| 问题 | 结论 | 证据 |
|---|---|---|
| `github.com/Autumn-27/ARTEX` 是否仍公开？ | **否。当前返回 HTTP 404** | 本次直接抓取 `https://github.com/Autumn-27/ARTEX` → `HTTP 404 Page not found` **[VERIFIED]** |
| 仓库是 archived 还是 deleted？ | **删除/私有化，不是 archived**：404 说明公开访问已不存在；作者声明为"转为闭源" | 作者声明见下；404 见上 **[VERIFIED]**。GitHub 无法从 404 区分 deleted 与 private **[限制]** |
| 作者账号是否还在？ | **在**，`github.com/AUTUMN-27` 返回 200，profile README 顶部即安全声明 | 抓取 `https://github.com/AUTUMN-27` **[VERIFIED]**（正文被页面导航截断，声明文本经搜索结果片段与两家媒体引文交叉确认） |
| 最后一次开源版本 | **v0.3.15，2026-10-07** | 本地 `CHANGELOG.md:7` `## [0.3.15] - 2026-10-07` **[VERIFIED]**；与"本地副本即最后版本"的说法一致 |
| 是否有 release tag？ | **没有可验证的官方 tag/Release**；公开备份保留 458 个提交但无 tag | 独立源码审计文章明确写"没有公开 tag 或 GitHub Release" **[REPORTED]**（[Quriosity 审计](https://raw.githubusercontent.com/Quriosity-agent/articles/refs/heads/main/2026-10-08/2026-10-08-artex-dual-graph-autonomous-pentest-agent-audit.md)）；本地 `.github/workflows/release.yml` 仅由 `push: tags: ["v*"]` 触发 **[VERIFIED]**，说明流程存在但无证据表明公开打过 tag |
| LICENSE | **AGPL-3.0** | 本地 `LICENSE:1-2` **[VERIFIED]**；README 亦声明 AGPL-3.0 |
| `autumn27/artex` Docker 镜像 | **已不存在（404 / pull access denied）** | 两个独立 fork 维护者的提交与 PR 记录：`docker compose pull` 报 `pull access denied … repository does not exist`（[dbc-hbin/artex-ko@3ba82df](https://github.com/dbc-hbin/artex-ko/commit/3ba82df79bb3da9d50b1865b431da7f626610228)）、[BaaRai/ARTEX PR #127](https://github.com/BaaRai/ARTEX/pull/127) "Docker Hub returns 404" **[REPORTED]**（本会话无法直连 hub.docker.com，**未做一手确认**） |
| 是否有 CVE / 厂商公告？ | **没有**。作者仓库已无维护者，镜像后门未被分配 CVE，也未进 CISA KEV | [Ostorlab, 2026-11-05](https://blog.ostorlab.co/artex-backdoored-docker-image-root-shell.html) 明确写 "No CVE, vendor advisory or CISA KEV entry exists as of November 5, 2026" **[REPORTED]** |
| 是否商业化？ | **是，存在 "ARTEX PRO" 商业版**；同时存在本地化分支（如 ScopeWeaver） | FBI FLASH 经 [Infosecurity Magazine, 2026-11-16](https://www.infosecurity-magazine.com/news/fbi-growing-abuse-ai-pentesting/) 转述；[ThaiCERT, 2026-11-18](https://www.thaicert.or.th/en/2026/11/18/fbi-warns-ai-powered-artex-framework-enables-cyberattacks-and-privilege-escalation-in-under-three-hours/) 亦提及 **[REPORTED]**（"ARTEX PRO" 无公开站点可核实，**[UNVERIFIED]** 其形态与归属） |

### 1.2 作者声明（原文要点）

作者于 **2026-10-08** 在 GitHub 账号发布中文声明，三点：
1. 恶意攻击事件与作者无关；
2. ARTEX 设计初衷是"帮助企业、组织在获得授权的资产范围内进行安全风险测试"，滥用"完全违背作者初衷"，作者"不承担任何责任，并予以强烈谴责"；
3. "鉴于工具被滥用的现实情况，**ARTEX 项目将不再更新，并转为闭源。后续不再对外发布任何版本或维护支持**。"

出处：`https://github.com/AUTUMN-27`（profile README，抓取到页面但正文被截断，文本经搜索结果片段确认）**[VERIFIED（页面存在）/ 文本经二手确认]**；中文媒体引述见 [星洲日报 2026-10-09](https://www.sinchew.com.my/?p=7929284)、[DigitalToday 中文版 2026-10-09](https://www.digitaltoday.co.kr/cn/view/112679/artex-open-source-ai-penetration-testing-tool-goes-private-unrelated-to-hacking-of-korean-financial-firms) **[REPORTED]**。

### 1.3 时间线

| 日期 (2026) | 事件 | 证据等级 / 来源 |
|---|---|---|
| 07-26 | ARTEX 在 GitHub 以 AGPL-3.0 开源发布（Go + Next.js + PostgreSQL） | **[REPORTED]** 百度百科词条、cn-sec、Infosecurity 均记 7 月；本地 CHANGELOG 最早条目为 `0.3.2 (2026-08-20)`，与之相容 |
| 08-20 → 09-24 | v0.3.2 … v0.3.14 连续迭代 | **[VERIFIED]** 本地 `CHANGELOG.md` 版本标题 |
| 08 月下旬起 | GTIG/Mandiant 称已观察到 ARTEX 被用于真实入侵 | **[REPORTED]** GTIG 报告经 [digiDations 摘要, 2026-11-13](https://resources.digidations.com/blog/artex-in-real-intrusions-loud-fast-and-still-reaching-dcsync) 转述（原博客不可达） |
| 09 月底–10 月初 | CrowdStrike 披露：韩国金融机构遭 ARTEX + LLM 攻击，约 6.7 万人个人信息外泄 | **[REPORTED]** [Infosecurity, 2026-11-16](https://www.infosecurity-magazine.com/news/fbi-growing-abuse-ai-pentesting/)；[DigitalToday](https://www.digitaltoday.co.kr/cn/view/112679/artex-open-source-ai-penetration-testing-tool-goes-private-unrelated-to-hacking-of-korean-financial-firms) |
| **10-07** | **v0.3.15 发布（最后一个开源版本）** | **[VERIFIED]** 本地 `CHANGELOG.md:7` |
| **10-08 10:50 UTC** | 作者宣布闭源并删除仓库 | **[REPORTED]** [Ostorlab 时间线](https://blog.ostorlab.co/artex-backdoored-docker-image-root-shell.html)（时间精确到 UTC，只有该文给出） |
| 10-08 18:50 / 19:41 UTC | Docker Hub 账号 `tomicdd` 建立 / 推送带后门的 ARTEX 镜像 | **[REPORTED]** 同上 |
| 10-08 | `trhhubsd/ARTEX` 上传源码副本，仅改一行 compose 指向 `tomicdd/artex` | **[REPORTED]** 同上（引 Software Heritage 存档） |
| 10-09 | 韩语分支确认上游镜像 404、pull 失败 | **[REPORTED]** [dbc-hbin commit](https://github.com/dbc-hbin/artex-ko/commit/3ba82df79bb3da9d50b1865b431da7f626610228) |
| 10-20 | 第一个带后门控制台上线 | **[REPORTED]** Ostorlab |
| 10-23 | 有人在该 fork 开 issue #3 "suspect a backdoor"，次日被作者关闭 | **[REPORTED]** Ostorlab（issue 现为 404，**[未能一手验证]**） |
| 10-30 | GTIG + Mandiant 发布 "ARTEX and Friends: Enter Agentic Offensive Frameworks" | **[REPORTED]** digiDations 摘要给出确切日期与标题 |
| 11-04 | BadByte 公布镜像后门分析；CERT-In 就 "Crafty Falcon" 发预警（ARTEX + PentAGI + CyberStrikeAI） | **[REPORTED]** Ostorlab / [Infosecurity, 2026-11-06](https://www.infosecurity-magazine.com/news/artex-activity-exceeds-reported/) |
| 11-05 | Censys 报告 1,465 台暴露控制台；Docker 下架 `tomicdd` 镜像；Ostorlab 发处置指南 | **[REPORTED]** [Censys blog](https://censys.com/blog/artex-agentic-asbestos/)（页面正文未抓到，数字经 Infosecurity 转述）；下架经 [CSA 研究笔记](https://labs.cloudsecurityalliance.org/research/csa-research-note-artex-agentic-pentest-frameworks-in-the-wi/) 转述 |
| **11-13** | **FBI 发布 FLASH-20261113-001（TLP:CLEAR）** | **[REPORTED]** [Infosecurity](https://www.infosecurity-magazine.com/news/fbi-growing-abuse-ai-pentesting/) 给出编号与 PDF 链接；[ThaiCERT](https://www.thaicert.or.th/en/2026/11/18/fbi-warns-ai-powered-artex-framework-enables-cyberattacks-and-privilege-escalation-in-under-three-hours/) 复述 |
| **11-18** | 本次核查：原仓库 404；作者账号 200；无 CVE | **[VERIFIED]** |

### 1.4 本节缺口
- 没有 archive.org 快照可证明"下架前最后一刻"的仓库状态；`web.archive.org` 在本会话不可达。
- 无 GitHub 官方事件记录（DMCA / ToS takedown）——目前证据指向**作者主动删除**，而非平台下架。
- `ARTEX PRO` 的商业实体、价格、是否基于 v0.3.15 均无公开一手材料。

---

## 2. 滥用事件（Abuse incidents）

> 关键判断：ARTEX 不是"被误用一次"的项目，而是**已被写进美国联邦执法通报的实战攻击基础设施**。对 fork 而言这是最高优先级的背景事实。

### A1. 韩国金融机构攻击（触发闭源的直接原因）
- **来源/日期**：CrowdStrike 分析，2026-10-07 前后披露；经 Infosecurity（2026-11-16）、DigitalToday（2026-10-09）、星洲日报（2026-10-09）报道 **[REPORTED]**。
- **发生了什么**：攻击者用 ARTEX 编排 LLM（Claude / Claude Code，另有 DeepSeek 作为主模型后端）对韩国金融机构实施入侵，时间跨度 2026-09 底至 10 初，已确认数据泄露。
- **影响**：FBI 通报经媒体转述为"约 **67,000 人**个人信息被窃"；一名 26 岁中文使用者被列为嫌疑人方向（Reuters 经星洲日报转述）**[REPORTED，具体人数与嫌疑人均未获一手确认]**。
- **后果**：作者 10-08 宣布闭源。

### A2. ConnectWise Cloud Backup 供应链入侵
- **来源/日期**：Microsoft 归因，2026-10 下旬；经 Infosecurity（2026-11-06 / 11-16）报道 **[REPORTED]**。
- **发生了什么**：Microsoft 将大规模 ConnectWise 客户租户失陷归因于 Storm-0940（又名 CovertNetwork-1658 / ORB07），行动中使用 ARTEX；导致 ConnectWise 下线部分云服务。
- **影响**：**2,250+ 下游租户**可被访问 **[REPORTED]**。

### A3. 印度 CERT-In "Crafty Falcon" 预警
- **来源/日期**：CERT-In，2026-11-04 **[REPORTED]**（经 Infosecurity 2026-11-06 转述）。
- **发生了什么**：警告印度金融与加密货 business 遭 "Crafty Falcon" 连续攻击，工具组合包含 ARTEX、PentAGI、CyberStrikeAI。
- **影响**：国家级 CERT 正式把 ARTEX 列入攻击工具清单。

### A4. FBI FLASH-20261113-001（最具分量）
- **来源/日期**：FBI，2026-11-13，TLP:CLEAR，13 页 **[REPORTED]**（PDF 本体未能解析）。
- **关键结论**（多源一致的引述）：
  - 至少自 **2026-08** 起，多类恶意行为者用 ARTEX 对全球目标发动入侵；
  - 受害行业覆盖金融、政府、科技、国防、半导体、能源、医疗、制造、电信、法律；
  - **从初始目标到特权访问可短于 3 小时**；
  - ARTEX 本身不含模型，接外部 LLM（Anthropic Claude、OpenAI GPT、DeepSeek、GLM、Grok、Kimi）；攻击者实例中 **DeepSeek Flash 系列占比最高**，"性价比高、用于渗透测试语境时护栏几乎不可见"；
  - 仓库下架后，框架仍通过 **fork、存档副本、本地化版本（ScopeWeaver）与商业版 ARTEX PRO** 流通；**11 月初已发现 1,600+ 台公网可访问的 ARTEX 控制台**。
- **影响**：这是把 ARTEX 定性为"实战攻击框架"而非"被滥用的研究工具"的官方文件。

### A5. 公网裸奔的控制台（本项目最直接的可观测危害）
- **来源/日期**：Censys（Silas Cutler），2026-11-05；Check Point Research，2026-11-04/05 **[REPORTED]**。
- **数字（各家口径不同，勿混用）**：
  - Censys：**1,465** 台主机暴露 ARTEX 控制台；其中约 **650** 台集中在两块同构托管，故"看似独立的部署"约 **815**；**155** 台（10.6%）同时跑其他被标记为威胁的工件（Vshell、Cobalt Strike、Adaptix C2、CyberStrikeAI 等）；**32** 台有可公开访问的目录，内含后渗透工具、stager、implant；**43** 台跑自建 LLM 网关/转售软件。
  - Check Point：累计 **2,557** 台曾托管 ARTEX，其中 **1,608** 台调研时在线且公网可达；发现 **10** 个配置错误实例**完整暴露数据库**，可直接看到操作者指令、模型选择、agent 消息。
  - 托管地：美国 882（54%）、香港 295（18%）、中国 103（6%）。
- **影响**：攻击者的目标清单、被窃凭据、implant 与"受害名单"被反向暴露；同时说明大量部署**根本没有设管理员密码**（见 §4 B1）。
- **注**：Censys 把同作者的 **ScopeSentry** 也列入"威胁工件" —— 对 fork 的连带影响见 §6。

### A6. 被投毒的 Docker 镜像（供应链事件，直接命中"用自己的镜像"这件事）
- **来源/日期**：BadByte 分析 2026-11-04；Ostorlab 处置文 2026-11-05；The Hacker News 2026-11-05 **[REPORTED]**。
- **发生了什么**：`tomicdd/artex`（及其字节相同的重推 `congdonglinux/artex`）在官方 v0.3.15 二进制基础上改了三处：
  1. 新增 160 字节函数 `server.verifyCaptcha`；
  2. `server.(*Server).authLogin` 从 1,600 字节涨到 2,112 字节；
  3. 登录请求结构体加第四个字段 `Captcha`。
  登录 handler 在**校验任何凭据之前**，若 `captcha` 以隐藏 marker 开头，就 `sh -c` 执行其剩余部分并**把输出回吐到 HTTP 响应**。无需账号、无需密码、无需会话。容器以 root 跑。
- **影响面**：Docker Hub 上该镜像 **9,077 次 pull**（11-05）；BadByte 统计到 **62 台**公网控制台在 11-02～11-04 分发该后门版本；**637 个 GitHub 仓库**的 compose 仍指向该镜像。
- **可窃取内容**：`ARTEX_PG_DSN` 里的 PostgreSQL 超级用户口令、`llm_profiles.api_key`（**明文**）、Brave/Tavily key、engagement 目标与 scope、`assets.auth` 里收集的凭据、`findings.evidence`、`/app/data/traffic`、MITM 代理 CA 私钥、`/app/jwt.key`（可伪造 7 天 admin token）、MCP server 命令/令牌、通知渠道密钥。
- **处置**：无 CVE、无厂商公告；唯一解法是换镜像 + 轮换全部密钥 + 假定 engagement 数据已泄露。
- **注意**：Ostorlab/BadByte 明确说**官方源码本身没有后门**，差异只在那三处；这是"第三方镜像"事件，不是上游投毒。

### A7. GTIG/Mandiant 观测到的入侵（"loud and fast"）
- **来源/日期**：GTIG + Mandiant，2026-10-30 **[REPORTED，经 digiDations 摘要]**；原博客 `cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks` 本次抓取失败。
- **要点**：受害者在美欧，行业含企业软件、工业自动化、半导体、电信、政府、化工、制造；行动以 2–25 秒的爆发式节奏运行；单案例 15 分钟从拿到账号到深度访问，典型约 4 小时；出现 Kerberoasting → DCSync 拿 krbtgt、Kudu API 执行命令、491 个轮换的 webhook.site 回连、枚举 11 万+ AD 对象、创建 `ArtexProbe` 类账号；**也有多步失败**（实例 profile ARN 无效、安全组创建被拒、横向移动被 Windows 令牌权限与 EDR 拦下）。
- **注**：GTIG 未描述初始访问方式，**未命名任何 CVE**；"子 agent 互相覆盖导致报错"一说 GTIG 自己也标为未确认。

### A8. Unit 42 相关说法（未确认）
- **[UNVERIFIED]** 有聚合站转述 Unit 42：其 IR 团队发现攻击者服务器托管 ARTEX 控制台、跟踪到针对零售与咨询业云环境的协同行动，并统计 **609** 台公网 ARTEX 主机、**1,323** 台 CyberStrikeAI（截至 2026-10）。来源为二手摘要（thecolony.cc），**未找到并打开 Unit 42 原文**。

### 2.1 同类 AI 渗透框架（XbOW / PentestGPT / Strix / CAI）的滥用记录
- **本次调研没有找到**针对 XbOW、PentestGPT、Strix、CAI 的具名滥用事件、CERT 通报或下架记录。**这是一个"未找到"，不是"不存在"**——可能只是检索未覆盖，不能反推这些工具安全。
- 能确认的相关旁证：Censys 指出 ARTEX 与 CyberStrikeAI（70 台同主机）、PentAGI、HexStrike AI、RedAmon **共用基础设施**，说明"多框架并用"是操作者常态 **[REPORTED]**。
- **[UNVERIFIED]** 有二手摘要称 Elastic 对五种同类框架做代码审查，结论是"默认都没有在代码层强制授权校验"。原文未找到，仅作线索。

---

## 3. 社区批评（Community criticism）

按"对 fork 有决策价值"排序。注意：**ARTEX 的批评主要不是"误伤/打穿第三方"，而是"它其实没那么强，但足够快"**——这与"AI 渗透工具失控"的直觉叙事有偏差。

### 3.1 "幻觉成功"：agent 把 API 200 当成目标达成
- Check Point 拆了 10 个暴露数据库后给出最硬的反证：某加密货币行动 **292 个目标、230 个 finding、400,791 条 agent 消息、1.675 亿 token**，结果**攻击者一分钱没拿到**；agent 因为 API 返回 "success" 就报告"已成功提现"，实际钱包 **$0 余额、零交易** **[REPORTED，[Check Point Research, 2026-11-05](https://blog.checkpoint.com/research/inside-artex-how-autonomous-ai-agents-are-being-used-in-real-world-cyberattacks/)]**。
- 另一例：两周拿下 300+ 张 iOS 代码签名证书及口令，**仅 3 张通过完整验证**（可用于签任意 iOS 应用）。成本约 **$700–1,500**（约 360 亿 token）**[同上]**。
- GTIG 侧的对应观察：多步失败、子 agent 可能互相覆盖（未确认）**[REPORTED]**。
- 中文社区同向反馈：**[UNVERIFIED]** 论坛帖称"任务一多、范围一大，Astra 决策 + deepseek 执行效果不佳；各 agent 对全局目标与已完成工作的认知不一致，各自基于过期局部信息推理，最终整体跑偏，用 prompt 约束也解决不了"（[locdd.com/t/topic/104750](https://locdd.com/t/topic/104750)，2026-10-28）。

### 3.2 成本：不是"免费攻击"，但便宜到足以规模化
- 上面两例给出量级：单次行动 1.675 亿 / 360 亿 token，$700–1,500。FBI 亦把"DeepSeek Flash 便宜"列为攻击者选型原因 **[REPORTED]**。
- 对 fork 的含义：**成本控制（token 预算、模型路由、提前止损）是产品能力，不是可选项**。

### 3.3 误报与"为了不误报而关掉防护"
- 源码级证据（比任何评论都硬）：内置的**「数据外泄管道」规则默认是关闭的**，`db/db.go:540-542` 注释写明原因——`curl/wget/nc` 管道正则在合法的 CTF/渗透反弹 shell 与数据传输上**误报**，需要时请手动开启（`enabled: false`，见 `db/db.go:568`）**[VERIFIED，本地 `db/db.go`]**。
- 0.3.15 的 CHANGELOG 自述：内置 HTTP 破坏性规则此前只认 DELETE **方法**，`curl 'http://t/api/user/delete?id=1'` 这类 GET/POST 删除接口**全部漏过**，直到 0.3.15 才补规则 **[VERIFIED，本地 `CHANGELOG.md:13`]**。这类漏报直接对应"误删目标数据"的风险。
- 0.3.15 同时修了一个**严重**的凭据掩码绕过（改目标地址即可让服务端把库中真凭据发到任意地址）——说明 0.3.14 及更早版本存在该问题 **[VERIFIED，本地 `CHANGELOG.md:30`]**。

### 3.4 审批流：不是"太松"，而是"太吵"
- fork 的 PR 动机写得很直白：反复批准同类无害命令（如 `gh pr list`）是**噪音**，所以才加"always allow"，并且必须配一份代码内置的 argv denylist（解释器/启动器/包管理器/编排工具/破坏性命令一律禁止被 always-allow）**[VERIFIED，[BaaRai/ARTEX PR #211](https://patch-diff.githubusercontent.com/raw/BaaRai/ARTEX/pull/211.diff)]**。
- 该 PR 的 UI 文案同时承认 always-allow 的固有缺陷："前缀不约束参数，也不覆盖程序后续行为（git hooks、npm scripts、docker images）" **[VERIFIED，同上]**。
- 结论：上游的问题是**批准疲劳导致人肉点"允许"**，而不是审批太严。这对 fork 的 UX 设计是核心输入。

### 3.5 "闭源挡不住滥用"
- FBI、Infosecurity、SBS、ThaiCERT 口径一致：删库只终止了公开开发，fork/存档/本地化/商业版继续流通，公网实例仍在增加 **[REPORTED]**。
- SBS 的评论最直接："已经发布的程序收不回来，仅靠停止开发很难阻断利用 ARTEX 的攻击"（[SBS News, 2026-10-10](https://mnews.sbs.co.kr/english/article.do?newsId=N1008791086)）**[REPORTED]**。
- 对 fork 的含义：**fork 本身会被当作"滥用生态的一部分"看待**，无论动机。

### 3.6 部署与工程摩擦（中文用户的实际吐槽点）
- 一篇中文部署教程把坑列成了清单：Go 代理不配就卡在 `go: downloading`；前端 `npm run build` 需 ≥4G 内存否则卡死；必须 `-tags embedui`；`artex-pg` 容器名冲突；PostgreSQL 不自启导致 `connection refused`；DNS 解析失败需改 `resolv.conf` **[REPORTED，[cn-sec 2026-11-10](https://cn-sec.com/archives/5562068.html)]**。
- 该文同时给出"ARTEX-0.3.16 / 0.1.1（闭源前库存）"的网盘分享 —— **说明闭源后源码仍在中文社区以网盘形式扩散**，且存在 0.3.16 快照的说法 **[UNVERIFIED]**（本次未能验证 0.3.16 是否为真实发布版本；注意后门镜像的版本串正是 `v0.3.16-0.20261008...+dirty`，两者容易混淆）。

---

## 4. 已报告的安全相关缺陷（Security-relevant bugs）

> 分两类：**(A) 上游 ARTEX 自身的问题**（fork 必须修）；**(B) fork 侧已修复、可借鉴的问题**。

### B1. 未认证的实例接管（setup 抢占）——最严重的上游设计缺陷
- **问题**：`POST /api/auth/init` 在 `auth.password_hash` 为空时**接受任意调用者**；而 `docker-compose.yml` 把 8787 **发布到所有网卡**。新装实例在操作员设定密码之前，**任何能连到端口的人都能抢注管理员**，进而拿到 agent shell、已存密钥、findings。
- **证据**：fork PR 描述 + 本地源码双重确认 —— `docker-compose.yml:30-32` 为 `- "8787:8787"`（无 127.0.0.1 绑定）**[VERIFIED，本地]**；路由 `server/server.go:656` `POST /api/auth/init` **[VERIFIED，本地]**；修复方案见 [PR #137 diff](https://patch-diff.githubusercontent.com/raw/BaaRai/ARTEX/pull/137.diff) **[VERIFIED]**。
- **影响**：与 Censys/Check Point 观察到的 1,465–1,608 台无鉴权控制台**高度吻合**；这类实例等于把 attacker toolbox 直接开放给路人。
- **注意**：v0.3.15 尚未修（修复只存在于 fork）。

### B2. 密码读取失败时的 fail-open（v0.3.15 已修）
- 本地 `server/auth.go:33-36` 注释：`authInit 曾因此在数据库报错时放行，让未认证请求覆盖掉已有的管理员密码`，并配有回归测试 `TestAuthInitFailsClosedWhenDataSourceUnavailable` **[VERIFIED，本地]**。
- 含义：**旧版本**在数据库异常时可能允许未认证请求重置管理员密码；0.3.15 改为 fail-closed（返回"数据源暂时不可用"）。若 fork 基于更早版本，必须先打这个补丁。

### B3. 配置文件解析失败被吞掉 → 误导性启动错误
- `config/config.go` 的 `Load()` 曾用 `_ = json.Unmarshal(...)`，把"文件存在但解析失败"当成"文件缺失"，报 `no database config found`；叠加 `install.sh` 未转义地把密码写进 JSON/sed（密码含 `"` `\` `|` `&` 就炸）**[VERIFIED，[PR #141](https://github.com/BaaRai/ARTEX/pull/141) 描述与 diff 引用]**。
- 影响：安装期"玄学失败"，也是 §3.6 部署摩擦的根因之一。

### B4. 密钥与敏感数据的存储姿势
- 明文/半明文：`llm_profiles.api_key`、通知渠道密钥、MITM 代理 CA 私钥、`/app/jwt.key`（HS256，7 天有效期 admin token）、`ARTEX_PG_DSN` 在环境变量里 **[REPORTED，Ostorlab 引 BadByte]**。
- 本地可确认的对应设计：JWT 密钥落盘于 `keyDir/jwt.key`，`dataDir/jwt.key` 为旧路径兼容（`server/auth.go:20,48-51`）**[VERIFIED，本地]**。
- 影响：一次镜像后门/容器逃逸 = 全部密钥 + 全部 engagement 数据 + 可伪造 7 天 admin token。

### B5. 更新链路失效
- 后门镜像二进制版本串为 `dev`，ARTEX 拒绝非 release 版本的"一键更新"；更新检查请求的 GitHub release 端点已 404；`update.sh` 走 `docker compose pull` 仍拉同一镜像 **[REPORTED，Ostorlab]**。
- 含义：**上游的自我更新机制在下架后彻底死掉**，fork 必须自建发布与签名链路。

### B6. 无"内置鉴权之外的防护"
- Ostorlab 原话："ARTEX console has no built-in authentication beyond its login form" **[REPORTED]**。
- 叠加 Censys 的 32 台开放目录 + 10 个暴露数据库：**面板本身没有任何租户/网络层保护**，全靠部署者自觉。

### B7. 上游自述的其他安全问题（0.3.15 CHANGELOG，本地可查）
- 凭据掩码可被"改目标地址、保留凭据"绕过（**严重**）→ 修 **[VERIFIED，`CHANGELOG.md:37`]**。
- 嵌套结构提交会把掩码字面量写进库，导致鉴权静默失效 → 改为显式拒绝 **[VERIFIED，`CHANGELOG.md:43`]**。
- 0.3.13 在登录前加了"使用须知与免责声明"弹窗（需勾选同意）**[VERIFIED，`CHANGELOG.md:159`]** —— 说明作者在滥用曝光前就已意识到用途风险。

### 4.1 防护机制的真实强度（重要，别被 UI 误导）
本地源码逐条核对（与第三方审计结论一致）：
1. **旧的 RoE（授权范围）机制已被移除**：`guard/guard.go:1-8` 注释明写 "The RoE authorization-scope mechanism was removed; a replacement may be added later" **[VERIFIED]**。
2. **没有命中任何规则的调用默认放行**：`guard/guard.go:91-99` —— `Match` 未命中 → 尝试 LLM 裁判 → 裁判未启用/未接线 → `return hook.Result{}`（即允许）**[VERIFIED]**。
3. **LLM 裁判失败即放行**：`intercept/intercept.go:316` `defaultJudgeFailAction = "allow"`；`:459`/`:465` 在模型调用失败或输出不可解析时按 `FailAction` 处理 **[VERIFIED]**。
4. **内置规则存在 DB 里，用户可停用/删除**；外传规则默认关闭（见 §3.3）**[VERIFIED]**。
5. 破坏性命令规则（`rm -rf /`、`mkfs`、`dd if=`、fork bomb、关机）默认启用（`enabled: true`，`db/db.go:560`），优先级 100 **[VERIFIED，`db/db.go:556-562`]**。

> 一句话：**Intercept 是"可配置的审批与降险层"，不是强制授权沙箱。** 任何"ARTEX 有硬范围边界"的宣传都与源码不符。

---

## 5. 许可与法律（Licensing）

### 5.1 实际许可
- **AGPL-3.0**：`LICENSE` 为 GNU AGPL v3 全文；`README.md:524` 明确"GNU Affero General Public License v3.0（AGPL-3.0）" **[VERIFIED，本地]**。
- README 对 AGPL 义务的表述基本正确：衍生作品须同样以 AGPL-3.0 开源；**若修改后通过网络提供服务，须向这些用户公开完整源码**（即 AGPL §13）**[VERIFIED，`README.md:526`]**。

### 5.2 关键冲突：README 的"使用限制"比 AGPL 更严
`README.md:528-550` 在许可证之外额外声明 **[VERIFIED，本地]**：
- 允许范围仅限"阅读、学习、研究源码"与"本地隔离环境中的技术原理验证"；
- **"严禁使用本工具对任何网站、线上服务或联网系统发起扫描、探测、利用或攻击（无论是否获得授权、是否为自有资产）"**（`README.md:538`）；
- 严禁用于"任何实际的渗透测试、攻防对抗或生产环境"；
- AS IS 免责，使用者承担全部法律责任。

问题在于：
1. 该禁止条款**连"授权测试"也一并禁止**，与作者对外声明（"用于授权资产范围内的安全测试"）自相矛盾——作者在 10-08 声明里的口径明显更窄。
2. AGPL-3.0 本身不允许在许可之上再附加限制（"no further restrictions"）。第三方审计文章也点出了这个张力，并明确"不作法律结论" **[REPORTED，[Quriosity 审计 §07](https://raw.githubusercontent.com/Quriosity-agent/articles/refs/heads/main/2026-10-08/2026-10-08-artex-dual-graph-autonomous-pentest-agent-audit.md)]**。
3. 实践含义：**AGPL 授予你的权利不因 README 的一段话而消失**；但作者已公开表态反对任何实际使用，且工具已被 FBI 通报——这两点带来的是**声誉、执法关注与民事责任风险**，不是许可证风险。

### 5.3 典型 fork 需要遵守/注意的清单
| 事项 | 要求 | 依据 |
|---|---|---|
| 源码开放 | 修改后分发必须以 AGPL-3.0 提供完整对应源码 | AGPL §5、§13 **[VERIFIED，本地 LICENSE]** |
| 网络服务 | 若作为在线服务提供，须向使用者提供源码获取方式（§13） | README 亦重申 **[VERIFIED]** |
| 保留声明 | 保留版权声明、许可证文本、变更说明 | AGPL §5 **[VERIFIED]** |
| 不得再许可 | 不能改成 MIT/Apache/闭源商业许可 | AGPL **[VERIFIED]** |
| 名称/商标 | "ARTEX" 名称与作者身份的使用需谨慎（许可证不授予商标权）；避免让下游误以为是上游发布 | AGPL 不含商标授权（通用原则，**本次未查到任何商标注册记录——未找到，不作断言**） |
| 上游"附加条款" | 需自行决策：遵守更严的 README 限制，还是依据 AGPL 主张权利并承担相应风险；建议在 fork 的 NOTICE/README 中明确声明立场 | **[REPORTED]** 审计文章 §07 |
| 无担保/责任 | 作者已全面免责；fork 需自建免责与合规声明 | `README.md:546-550` **[VERIFIED]** |

### 5.4 本节缺口
- 没有找到任何正式的 license change 公告（除"转为闭源"这一事实陈述）。**"闭源"不等于"撤销 AGPL"**：已发布的 v0.3.15 仍受 AGPL 约束，任何人都可依 AGPL 继续分发该版本源码。这一点在公开讨论中经常被混淆。
- 未查到作者就"ARTEX PRO"发布的任何许可条款。

---

## 6. 对 fork 的含义（Implications for a fork）

1. **不要再分发或依赖任何预构建镜像。** `autumn27/artex` 已 404，镜像命名空间存在被抢注/复用的风险（fork PR 明确提到"a namespace that could be reclaimed"）；社区镜像已实际出现 root 后门（9,077 pulls / 62 台控制台 / 637 个仓库受影响）。fork 应从**自己审过的源码**构建、发布到自有 registry、**按 digest 固定**、并附 SBOM 与构建证明。
2. **修掉未认证接管（B1），这是上线前的硬门槛。** 具体三件：`/api/auth/init` 加一次性 setup token（启动时打印到日志，恒定时间比较，用后即焚）、8787 默认绑 `127.0.0.1`、`authInit` 在数据源不可用时 fail-closed。这正是 fork PR #137 的做法，可直接借鉴。
3. **把"默认放行"改成"默认询问/拒绝"。** 上游 `guard.go` 在无规则命中时直接放行、LLM 裁判失败时 `FailAction=allow`，等于"没有规则 = 没有边界"。fork 应改成 fail-closed，并恢复被移除的 RoE/授权范围机制（目标白名单 + 时间窗 + 书面授权钩子）。
4. **把"数据外传规则默认关闭"改成默认开启 + 可解释的例外清单。** 上游因误报把外传拦截关掉，代价是"agent 把数据传出去"这件事完全没有默认防线；更好的做法是保留规则、提供按 engagement 的临时豁免并全程审计。
5. **审批 UX 的目标是"减少无意义点击"，不是"减少提示"。** 参考 PR #211：always-allow 只能生成**受约束的 argv 前缀规则**，并配一份**代码内置、不可配置**的 denylist（sh/bash/python/find/xargs/docker/kubectl/rm/dd/mkfs/sudo/... 永远不能被 always-allow）；同时向用户明示"前缀不约束参数、不覆盖程序后续行为"。
6. **把"幻觉成功"当成一等缺陷处理。** 上游 agent 会把 API 200 当目标达成（$0 余额却报"已提现"）。fork 需要：finding 必须绑定可复现证据（源码已有 evidence/traffic 快照机制，可强化）、关键结论强制二次验证（re-test）、对"成功"类断言做结构化校验而不是让模型自述。
7. **成本控制要做进产品。** 单次行动 1.7 亿–360 亿 token、$700–1,500 是公开量级。fork 应提供 per-engagement token 预算、模型分级路由、超预算硬停与用量看板；否则"自动化"会先烧穿用户钱包。
8. **密钥治理必须重做。** 上游把 LLM API key、通知密钥、代理 CA 私钥、JWT 签名密钥以明文/半明文落盘，一次入侵即全失。fork 应改为外部 secret store 或至少加密落盘 + 短 TTL token + 启动即轮换，并在容器内以非 root 运行、尽早从环境变量擦除（上游已有 `scrubSecrets` 思路，可扩展）。
9. **预期被当作"攻击基础设施"对待。** Censys 已把同作者的 ScopeSentry 列入威胁工件，ARTEX 与 CyberStrikeAI/PentAGI 共用基础设施；FBI 通报明确点名 fork 生态。fork 需要主动的滥用治理：可见的 AUP/EULA、目标授权声明、速率与范围限制、滥用举报渠道、可关闭的遥测/审计日志，以及"我们不是 ARTEX PRO"的清晰身份区分。
10. **许可与表态要一次性说清。** 保留 AGPL-3.0 全文与版权声明、履行 §13 网络源码义务、不改许可；同时在 README/NOTICE 中明确处理作者"仅限学习、禁止任何实际测试"的附加声明与 AGPL 的张力（并让法务过一遍）。**不要**把上游 README 的限制条款直接删掉当没看见——那会成为最好的攻击面。
11. **别指望上游修 bug。** 没有维护者、没有 tag/Release、没有 CVE 流程、更新端点已 404。fork 必须自建发布、回归测试与安全响应（上游测试/质量门也未收敛：独立审计记录 `npm run check` 失败、`npm audit` 有 24 条 advisory —— **[REPORTED]**，本次未复跑）。

---

## 7. 主要来源

**一手/准一手**
- 本地仓库源码与 `CHANGELOG.md`、`LICENSE`、`README.md`、`guard/guard.go`、`intercept/intercept.go`、`db/db.go`、`server/auth.go`、`docker-compose.yml`
- `https://github.com/Autumn-27/ARTEX` → HTTP 404（2026-11-18）
- `https://github.com/AUTUMN-27`（作者 profile，含 2026-10-08 声明）
- Ostorlab, *Malicious ARTEX Docker Image Hands Out Root Shells*, 2026-11-05：https://blog.ostorlab.co/artex-backdoored-docker-image-root-shell.html
- Check Point Research, *Inside ARTEX*, 2026-11-05：https://blog.checkpoint.com/research/inside-artex-how-autonomous-ai-agents-are-being-used-in-real-world-cyberattacks/
- Censys, *ARTEX: Agentic Asbestos*, 2026-11-05：https://censys.com/blog/artex-agentic-asbestos/
- BaaRai/ARTEX PR #137 / #141 / #211 / #127（fork 侧修复）
- dbc-hbin/artex-ko commit 3ba82df（上游镜像 404 的复核记录）

**二手报道**
- Infosecurity Magazine, 2026-11-06 / 2026-11-16
- ThaiCERT, 2026-11-18
- SBS News, 2026-10-10
- DigitalToday 中文版 2026-10-09；星洲日报 2026-10-09
- digiDations, 2026-11-13（GTIG 摘要）
- CSA Labs 研究笔记（fork 生态与镜像下架）
- Quriosity 源码审计（2026-10-08 快照）
- cn-sec 部署教程，2026-11-10

**FBI 原文（未能解析，仅引用）**
- https://www.ic3.gov/CSA/2026/261113.pdf （FLASH-20261113-001，TLP:CLEAR，13 页）

## 8. 明确的"未找到/未验证"清单

- **web.archive.org 快照：未打开**（本次会话该域不可达）。仓库下架前的最后快照状态无一手证据。
- **hub.docker.com 页面：未抓取**（不可达）。镜像 404 依赖两个独立 fork 维护者的复核记录。
- **Unit 42 原文：未读**；609 台主机等数字为二手转述，标 [UNVERIFIED]。
- **Google GTIG 原博客：未打开**；通过 digiDations 摘要引用。
- **FBI PDF 正文：未解析**；关键结论通过 3 家媒体交叉印证。
- **`wx.secv.cc` 的 61 次模型实验文章：未打开**（仅搜索摘要），其"模型几乎不拒绝、输出质量差、严重幻觉"结论标 [UNVERIFIED]。
- **ARTEX PRO 的任何一手材料：未找到**（无站点、无条款、无定价）。
- **任何 CVE / CISA KEV / CNCERT 通报：未找到**。Ostorlab 明确说明截至 2026-11-05 无 CVE；本次检索亦未见 CNCERT 关于 ARTEX 的专门通报（**未找到 ≠ 不存在**）。
- **XbOW / PentestGPT / Strix / CAI 的具名滥用事件：未找到**（本次检索范围有限，不能据此认为这些工具无滥用）。
- **"误伤/打穿第三方、云厂商滥用投诉、目标方投诉、CVE、Docker Hub 封禁公告"**：除镜像后门导致的 Docker 下架外，**未找到**任何具体受害方对 ARTEX 的公开投诉或云厂商滥用通告；FBI 通报的受害描述是行业级、非具名的。
