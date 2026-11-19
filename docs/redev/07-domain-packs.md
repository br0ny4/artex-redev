# 07 · 域包（domain pack）：同一套执行层，不同域策略

> 状态：web-pentest ✅ / binary-re ✅ / source-audit ✅ / malware-triage 📋
> 代码：`policy/embed.go`、`policy/{web-pentest,binary-re}/`、`policy/packs_test.go`

## 1. 为什么要域包

平台的红队、赏金、蓝队、病毒分析作业共享的是**同一套执行层契约**：

- 判不清就禁止（fail-closed），不靠模型自觉；
- 需要人确认时**全量停止**并暂停任务；
- 判定留痕、hash chain 可校验；
- 预算熔断、内容截断、出网收口。

但"什么是目标、什么算越界、什么是一票否决"在每个域里不一样：

| | 在线测试（web-pentest） | 离线二进制分析（binary-re） |
|---|---|---|
| 目标 | HTTP 资产（域名/IP/APP/API） | 本地产物（样本、固件、软件包）与情报源 |
| 越界 | 打到范围外的域名/IP、内网、云元数据 | 产物出网（上传第三方）、样本在宿主机执行 |
| 账号体系 | 需要测试账号兜住 C/D/E 类操作 | 没有登录/通知/资金动作，不要求 |
| 出网 | 报告通道 + dnslog/collaborator | 情报回源白名单（VT/MB/OTX），其余全禁 |
| 关键红线 | R1 破坏性、R8 外传、R10 凭据复用 | R8 产物出网、R12 未授权上传、R13 宿主机执行 |
| 预算重点 | 请求数/速率/样本数/PII 条数 | 情报查询次数（默认 200/任务，1 rps） |

第三个包 `source-audit` 面向源码审计与 0day 挖掘（semgrep / Joern / ast-grep / tree-sitter）：

| | 源码审计（source-audit） |
|---|---|
| 目标 | 本地源码目录清单（`scope.local_paths`），没有网络目标 |
| 越界 | 源码/片段/凭据出网；git push / 上传代码到远端 |
| 出网 | 默认**零出网**，只有部署上下文声明的报告通道 |
| 红线 | R8 源码外发、R14 原地改被审计源码、R15 发布代码到远端 |
| 工具 | 审计工具默认可用；`ssh`/`scp`/`rsync`/`nc`/`curl`/`wget` 默认禁用 |

把这些差异写进同一份 yaml 会得到互相矛盾的默认值（例如"测试账号 2 个"对病毒分析毫无意义），
所以按域分包，各自一份 `policy.yaml` + `verb-lexicon.yaml`。

## 2. 包的选择与失败方式

部署上下文里声明：

```yaml
engagement:
  pack: binary-re        # 不填 = web-pentest
```

- 选择逻辑在 `policy/install.go:InstallFromFile`：`engagement.pack` 优先，
  环境变量 `ARTEX_POLICY_PACK` 可覆盖（同一份上下文在评测环境换包跑时用）。
- **未知包名直接报错**（`policy.PackConfig`），不静默回退默认包：静默回退会让人以为在跑
  A 域策略，实际跑的是 B 域，而两边红线不同。
- 域包还能声明部署上下文的必填项（`engagement_requirements`）。离线域不要求
  `test_accounts`，在线域要求——校验从"一份通用清单"变成"域包说了算"。
  漏写该字段按在线域（最严）处理，漏声明不该把校验放松。

## 3. binary-re 包落地了什么

可被平台**强制**的部分（有判定谓词、有测试）：

- 出网白名单：只有 VT / MalwareBazaar / OTX 与部署上下文声明的地址可出网；
  内网段、云元数据一律拒绝；子域归属不明按范围外（不出网）。
- 工具黑名单：`wine` / `qemu-system-*` / `box64` 等"能在宿主机跑样本"的工具默认禁用。
- 语义分级：情报查询（GET/读）放行，`submit`/`upload`/`detonate` 归 D 类需显式授权，
  对产物/报告的改写归 A/B 类红线。
- 预算：情报查询 200 次/任务、1 rps、响应体 50MB 截断、敏感特征拦截仍生效。
- 全量停止条件增加 `sample_upload_attempt`、`host_execution_attempt`。

**还没有硬判定谓词的部分**（诚实说明，别当保证）：

- "样本在宿主机执行"。平台能拦已知模拟器，但 `./sample`、`python exploit.py` 这类
  任意执行不在现有命令判定谓词里；当前靠 deployment-context 的沙箱声明 +
  L2 出网收口（`deploy/egress-lockdown/`）+ guard 审批来兜。
- "经脚本/编码把产物外传"同理：出网白名单能挡住目的地，但挡不住先压缩再走允许域名的
  通道（这属于通道判定，规划在 P2.5 的触发验证切片里一并做）。

## 3.5 source-audit 包额外说明

- 授权范围从"域名清单"换成"目录清单"：`scope.local_paths`（`policy/config.go:EngScope.LocalPaths`）。
  离线域没有网络目标，用 `scope.allow` 硬填域名只会让人误以为在测网络服务。
- 被审计源码是证据：修补丁必须写进 `artifacts.dir`，原地改源码命中 A/B 类红线。
- 报告通道之外的出网一律拒绝；`semgrep --config r/...` 这类需要联网拉规则的用法要先
  在上下文里显式加白名单，否则判定会挡住（这是有意的）。
- 同样诚实说明：已有谓词覆盖"已知外传工具 + 已知目的地"，但"把代码片段贴进允许域名"这类
  通道判定尚无谓词，靠出网白名单 + L2 出网收口兜底。

## 4. 新增一个域包

1. `policy/<pack>/policy.yaml`（字段 schema 见 `policy/config.go` 的 `Config`）
   + `verb-lexicon.yaml`（schema 见 `policy/lexicon.go`）。
2. 在 `policy/embed.go` 的 `//go:embed` 里加目录（`web-pentest binary-re` 之后追加）。
3. 需要不同必填项时，在 yaml 写 `engagement_requirements`（默认最严）。
4. 加 `deployment-context.example.yaml`，并在 `policy/packs_test.go` 补两条：
   包能被加载 + 关键差异真的进了判定（不是只躺在 yaml 里）。
5. 文档更新本文件与 README 的计划表。

## 5. 验收

```bash
go test ./policy/ -run 'TestAvailablePacks|TestPackConfig|TestInstallFromFileSelectsPack' -v
# 端到端（用离线域模板，窗口改成当前时间）
ARTEX_ENGAGEMENT_FILE=./policy/binary-re/deployment-context.yaml ./artex
# 启动日志会打印：[policy] 执行层已启用 … pack=binary-re
```

`GET /api/policy/status` 的 `pack` 字段会告诉你这批判定用的是哪套域策略，
`/system/policy` 页面也展示同一值——把"我以为在用哪套策略"变成可核对的事实。
