<div align="center">

# ARTEX-redev

**ARTEX 的二次开发版（fork）** · 授权范围内的 AI 安全作业台

从「一条指令打到穿」走向「有硬边界的作业台 + 离线分析域」：在线授权测试、二进制逆向、
源码审计、恶意样本分析、蓝队检测，共用一套策略执行层与证据链。

[![ci](https://github.com/br0ny4/artex-redev/actions/workflows/ci.yml/badge.svg)](https://github.com/br0ny4/artex-redev/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8.svg)](go.mod)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](docs/redev/05-decisions.md)

</div>

---

## 这是什么

本仓库是开源项目 **ARTEX v0.3.15**（作者 [Autumn-27](https://github.com/AUTUMN-27)）的
**二次开发（fork）版本**，依 **AGPL-3.0** 继续开源。

- **上游已于 2026-10-08 闭源并删除仓库**，本仓库基于其最后一个开源版本（v0.3.15，2026-10-07）；
- 本仓库与原作者、版权方**无关**，不代表其立场，也不提供任何商业版本；
- 上游 README 原文存档在 [`README.upstream.md`](README.upstream.md)，改动说明见 [`NOTICE`](NOTICE)。

> ⚠️ **不要使用任何第三方预构建镜像。** 上游下线后已出现带 root 后门的镜像
> （`tomicdd/artex`，9000+ 次拉取），详见 [`docs/redev/01-abuse-and-status.md`](docs/redev/01-abuse-and-status.md)。
> 本仓库的镜像只从本仓库源码构建，并走 GHCR。

## 为什么做这个 fork

ARTEX 自 2026-08 起被多个威胁行为者当作攻击基础设施使用：FBI 于 2026-11-13 发布
FLASH 通报，全球金融/政府/科技/国防等行业受影响；公网上有 1400+ 台无鉴权控制台可被接管。
这件事本身说明两件事：

1. **自主 Agent 的能力是真的**（正因如此才需要它）；
2. **上游的安全边界是假的**——授权范围校验已被移除、无规则命中即放行、LLM 裁判失败即允许、
   默认监听所有网卡、未认证即可抢占实例。

所以这个 fork 不做"更强的攻击工具"，而是把**边界做成真的**，并把能力从"在线打点"扩展到
安全从业者真正的工作面（挖洞、逆向、审计、样本、蓝队）。

## 与上游的差异

| 方面 | 上游 v0.3.15 | 本仓库 |
|---|---|---|
| 模块路径 | `github.com/Autumn-27/artex` | `github.com/br0ny4/artex-redev` |
| 授权范围（RoE） | **已移除**，无范围校验 | `engagement` 数据模型 + 网络层强制（L2）+ 代理层语义判定（L3） |
| 默认放行 | 无规则命中 → 放行；裁判失败 → allow | 启用策略后**默认拒绝**；判不清 → 挂起问询 |
| 监听地址 | `:8787` 全网卡 | **`127.0.0.1:8787`**（compose 同样只绑回环） |
| 登录爆破 | 无限制 | 同 IP 10 分钟失败 5 次 → 锁 15 分钟 |
| 流量录制 | 可关闭（关掉即绕过一切代理层判定） | 启用策略后**强制开启且不可关闭**；无代理则拒绝启动 |
| 响应内容 | 原样交给模型 | 命中源码/配置/密钥 → **截断，原文不进上下文** |
| 审计 | 工具调用审计环 | 判定全量落 `policy_decisions`（hash chain），可校验完整性 |
| 文档 | — | `docs/redev/`：滥用态势、代码地图、工具选型、策略引擎设计、决策记录 |

更细的差异见 [`docs/redev/05-decisions.md`](docs/redev/05-decisions.md)。

## 计划与进展

> 状态：✅ 已完成 · 🚧 进行中 · 📋 计划中

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 安全硬化：默认回环、登录限速、fail-closed 开关、镜像自建 | ✅ |
| P1 | 内核：engagement 数据模型、域包（domain pack）抽象、产物模型扩展 | 🚧 |
| P1.5 | **规范执行层**：L1 命令/工具、L3 请求与响应、L2 出网强制、判定审计链 | ✅ |
| P1.6 | hold 生命周期（全量停止 → 操作员答复 → 恢复）、审批 UI | 🚧 |
| P1.7 | `/api/auth/init` 一次性 setup token + 前端配合 | 📋 |
| P2 | 离线域包：`binary_re`（radare2-mcp / Ghidra headless）、`malware_triage`（capa/YARA/FLOSS）、`source_audit`（Semgrep CE/Joern） | 📋 |
| P2.5 | 0day 流水线：攻击面提取 → 候选 → 可达性 → **触发验证**（无 PoC 不算 finding） | 📋 |
| P3 | 在线域包：`web_pentest`（继承 ARTEX）+ `bounty_recon` + CDP 浏览器分析 | 🚧 |
| P4 | 蓝队域包（检测工程 + agentic 攻击者检测规则）、多域报告、测评台（XBOW 104） | 📋 |

已落地的实现与"为什么这么定"记录在 [`docs/redev/05-decisions.md`](docs/redev/05-decisions.md)；
设计细节见 [`docs/redev/04-policy-engine.md`](docs/redev/04-policy-engine.md)。

## 快速开始

### 1. 源码运行

```bash
git clone https://github.com/br0ny4/artex-redev.git
cd artex-redev
go build -o artex ./cmd/artex        # 需要 Go 1.26+
./artex                              # 默认只监听 127.0.0.1:8787
```

需要 PostgreSQL（`ARTEX_PG_DSN` 或 `config.json`）；首次打开 `/setup` 设置管理员密码。

启动日志会打印一行初始化口令，`/setup` 要求填入——没有它任何人都能在设密码前抢占实例
（公网裸奔控制台最常见的失陷路径）。也可用 `ARTEX_SETUP_TOKEN` 固定。

### 2. Docker Compose

```bash
cp .env.example .env                 # 填 POSTGRES_PASSWORD
docker compose up -d                 # 镜像来自 ghcr.io/br0ny4/artex-redev
```

镜像按 tag 发布（`ghcr.io/br0ny4/artex-redev:v0.2.0`，`latest` 指向最新版本）。
需要自己改工具链时用源码构建：

```bash
./build-image.sh                     # 内部走 Dockerfile.local，构建后启动
```

### 3. 启用规范执行层（在线测试必做）

只填一个部署上下文文件，平台就会在三个出口强制判定：

```bash
cp policy/web-pentest/deployment-context.example.yaml policy/web-pentest/deployment-context.yaml
# 填写：授权范围、测试账号、允许工具、报告出口、产物目录、授权时间窗
export ARTEX_ENGAGEMENT_FILE=./policy/web-pentest/deployment-context.yaml
./artex
```

启用后：

| 出口 | 行为 |
|---|---|
| **L1** 命令/工具 | 扫描器未审批、内联解释器、RCE 只读白名单、敏感文件读取、命令目标越界 → 拦截 |
| **L3** 请求 | 范围外 / 删除类 / 覆盖类 / 资金类 / 未标注测试账号 → **不发包**，回平台管控 403 |
| **L3** 响应 | 源码、配置、密钥、超限响应 → 截断，原文不进模型上下文 |

查看判定与证据链：`GET /api/policy/status`、`/api/policy/decisions`、`/api/policy/chain`。

**需要人确认时全量停止**（规范 7.3）：范围归属不明 / 接口语义判不清 / 预算耗尽时，平台会挂起整个
engagement，把问题原样转给操作员；未获明确答复前所有请求与命令都被挡下。挂起时平台还会**暂停正在运
行的任务**（等待答复可能几小时，不暂停就是空烧 token），答复并恢复后自动续跑——只续跑因挂起被暂停的
任务，操作员自己暂停的不动。

页面入口：**系统 → 规范执行**（`/system/policy`），可直接答复挂起、看判定流水、校验审计链。

```bash
curl /api/policy/holds                        # 看当前挂起与问题
curl -X POST /api/policy/holds/{id}/answer \
     -d '{"answer":"已确认在授权范围内","resume":true}'   # 明确答复后才恢复
```

### 4. 锁定出网（L2，强烈建议）

只靠代理挡不住 `nmap`/裸 TCP。把容器出口收口到唯一代理：

```bash
docker compose -f docker-compose.yml -f deploy/egress-lockdown/docker-compose.egress.yml up -d
```

验收命令与原理见 [`deploy/egress-lockdown/README.md`](deploy/egress-lockdown/README.md)。

## 目录结构

```
agent/       Agent 运行时：目标拆解 → 规划 → 执行 → 复测
policy/      规范执行层：范围/语义分级/预算/命令/响应检查/审计（纯 Go，可单测）
             web-pentest/{policy.yaml, verb-lexicon.yaml, deployment-context.example.yaml}
             patterns/secret.txt   敏感特征（RE2）
traffic/     录制代理（mitmproxy）+ L3 判定出口
guard/       工具调用前置钩子（L1）
intercept/   可配置拦截规则 + 人工审批
db/          PostgreSQL（schema.sql 幂等迁移）
server/      HTTP API / 任务引擎 / MCP 编排 / 通知 / 策略 API
web/         Next.js 前端
deploy/      部署补充（egress-lockdown = L2 出网强制）
docs/redev/  设计与决策文档（必读）
skills/      内置 skill
```

## 合规与边界

- **许可证**：AGPL-3.0（见 [`LICENSE`](LICENSE)）。修改后分发、或通过网络提供服务，须按 §5/§13
  提供完整对应源码并保留版权声明；本仓库不提供闭源商用授权。
- **允许用途**：**仅限获得明确书面授权的资产**，或本地隔离环境中的研究与样本分析。
- **明确不做**：免杀/规避检测、反取证、无人工确认的自动化利用、"输入目标列表即自动出洞"、
  大规模凭据窃取与数据外传。这些既是上游被滥用的核心机制，也会让项目无法辩护。
- **不提供担保**：按现状提供，使用者自负全部法律责任。
- **上游附加条款**：上游 README 声明"禁止任何实际测试（含授权资产）"，与本 fork 的授权测试定位
  存在张力；AGPL 本身不限制用途，但请在动手前自行完成法律评估。

## 维护

- 分支：`main` 保持可构建、可测试；功能在 `feat/*` 分支开发后合入。
- 提交规范：`type(scope): summary`（feat/fix/refactor/docs/test/chore/security）。
- 每个安全相关改动**必须带回归测试**；策略层改动还要补合规矩阵用例。
- 提交前跑：`go build ./... && go vet ./... && go test ./...`（需要 PostgreSQL；CI 的串行策略与
  已知 flake 清单见 [`docs/redev/06-ci.md`](docs/redev/06-ci.md)）。
- 安全问题请走私密渠道（见 [`SECURITY.md`](SECURITY.md)），不要公开提 issue。

## 致谢

上游 [ARTEX](https://github.com/Autumn-27/ARTEX) 作者 Autumn-27，以及 ScopeSentry、norma 等
上游组件；设计参考了 AIxCC 参赛系统、Strix、Google Big Sleep / Naptime 等公开工作（见
[`docs/redev/02-tooling-survey.md`](docs/redev/02-tooling-survey.md)）。
