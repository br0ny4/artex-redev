# 07 · 域包（domain pack）：同一套执行层，不同域策略

> 状态：web-pentest ✅ / binary-re ✅ / source-audit ✅ / malware-triage ✅
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

### 2.1 运行时要求：录制代理

域包用 `runtime.requires_traffic_capture` 声明"没有录制代理能不能启动"：

| 域包 | 要求 | 理由 |
|---|---|---|
| `web-pentest` | **必须有**（true） | L3 范围/语义/预算判定就发生在录制代理里，没有代理等于判定被绕过 |
| `binary-re`、`source-audit`、`malware-triage` | 不必须（false） | 目标是本地产物，不产生目标侧 HTTP 流量；情报回源由 L2 出网白名单兜住 |

效果：

- 在线域：`-proxy` 起不来时**拒绝启动**；策略启用后录制**不可关闭**（`SetTrafficEnabled(false)` 报错）。
- 离线域：没有代理也能启动，录制默认关、可随时开（`server/manager.go`、`policy/engine.go`）。
- 漏写 `runtime` 按在线域（最严）处理：漏声明不该把强制录制放松。

这不是给离线域"开后门"：离线域本来就不该有目标侧流量，代理对它只是环境负担。

### 2.2 宿主机边界：离线域只守"打坏本机"，不守作业边界

在线测试域的判断是"会不会打坏客户业务"（范围/语义/预算/红线）；离线分析域的判断只有一条：
**会不会打坏自己的机器、或把不可信代码放到宿主机上跑起来**。两条轴分开后，离线分析
才不会因为"python -c 做一次计算"或"样本里出现 shadow 字样"被频繁打断。

`policy/hostguard.go` 这一层**始终启用**（在线域也拦，操作者的机器一样会被 `rm -rf /` 打坏）：

| 始终拒绝（不可配置） | 规则 |
|---|---|
| `rm -rf /`、`rm -rf /etc`、`rm -rf ~` | `H:host_destructive` |
| `dd if=… of=/dev/sda`、`mkfs.*`、`wipefs /dev/…` | `H:host_destructive` |
| `shutdown` / `reboot` / `poweroff` / fork bomb | `H:host_destructive` |
| `chmod -R 777 /`、`chown -R … /` | `H:host_destructive` |
| 内联解释器载荷里的上述动作（`python -c 'os.system("rm -rf /")'`） | `H:host_destructive` |
| 直接执行 `scope.local_paths` 内的文件（样本 / 被审计脚本） | `H:host_exec_scoped` |
| 读宿主机凭据（`~/.ssh/id_rsa`、`/etc/shadow`、`/etc/sudoers`） | `R5_sensitive_read` |

离线域相对在线域放宽的（`runtime.host_boundary`，默认已对齐下表）：

| 配置项 | 离线默认 | 在线默认 | 含义 |
|---|---|---|---|
| `allow_loopback` | true | false | 命令里的 `127.0.0.1` / `::1` / `localhost` 视为本地环境，不算横向 |
| `allow_inline_interpreters` | true | false | `python -c` / `bash -c` 放行（规范 6.4 只约束打到目标上的命令），载荷仍扫宿主机破坏动作 |
| `allow_executing_scoped_files` | false | false | 是否允许直接执行 `local_paths` 内的文件；默认不——"可读清单"不是"可执行清单" |

另外两处随此收紧/放宽的判定：

- 敏感文件判定只对**路径形态**的参数生效：`grep -i shadow sample.bin` 里的 `shadow`
  是搜索词，不再误拦；`strings sample.bin | grep -i shadow` 是样本分析常态，放行。
- 授权目录内的文件不按敏感文件判（样本是分析对象，里面出现 `.env`、`shadow` 字样很正常）。

域包 yaml 写法（`binary-re` / `source-audit` / `malware-triage` 已内置）：

```yaml
runtime:
  environment: offline                  # 显式声明；留空时按 requires_traffic_capture 推断
  host_boundary:
    allow_loopback: true
    allow_inline_interpreters: true
    allow_executing_scoped_files: false
```

验收：`go test ./policy/ -run 'TestHostBoundary|TestEngineHostBoundary'`。
## 3. binary-re 包落地了什么

可被平台**强制**的部分（有判定谓词、有测试）：

- 出网白名单：只有 VT / MalwareBazaar / OTX 与部署上下文声明的地址可出网；
  内网段、云元数据一律拒绝；子域归属不明按范围外（不出网）。
- 工具黑名单：`wine` / `qemu-system-*` / `box64` 等"能在宿主机跑样本"的工具默认禁用。
- 语义分级：情报查询（GET/读）放行，`submit`/`upload`/`detonate` 归 D 类需显式授权，
  对产物/报告的改写归 A/B 类红线。
- 预算：情报查询 200 次/任务、1 rps、响应体 50MB 截断、敏感特征拦截仍生效。
- 宿主机边界：`rm -rf /`、块设备写入、格式化、关机、递归改根权限始终拒；直接执行
  `scope.local_paths` 内的样本默认拒（见 §2.2）。

**还没有硬判定谓词的部分**（诚实说明，别当保证）：

- "样本在宿主机执行"：已有**词法级**判定——绝对路径、`cd <授权目录> && ./sample`、以及
  `bash`/`python` 解释器执行授权目录内文件都会被拒（`H:host_exec_scoped`）。判定层不做 IO，
  所以**解析不到的相对路径**（当前工作目录不在授权目录、符号链接指向样本、`./sample` 未经 `cd`）
  仍可能漏判；那部分靠 deployment-context 的沙箱声明 + L2 出网收口 + guard 审批兜。
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

## 3.6 malware-triage 包额外说明

和 binary_re 的分工是**深度**而不是领域：

| | binary-re | malware-triage |
|---|---|---|
| 目标 | 反汇编/反编译、算法还原、漏洞定位 | 是什么、什么家族、有什么能力、IOC 清单 |
| 样本执行 | 允许，但只能在声明过的沙箱（R13 沙箱外执行） | **一律不执行**（R13 `execute_sample_at_all`：`wine`/`qemu`/`gdb`/`strace` 等默认禁用 + `H:host_exec_scoped` 拒直接执行；命中的是"拒这一次命令"，不是全量停止） |
| 工具 | radare2/Ghidra/objdump/capa/YARA/FLOSS | file/hash/strings/exiftool/olevba/capa/YARA/FLOSS/diec |
| 预算 | 情报查询 200 次/任务 | 100 次/任务（批量分诊时每个样本都要省） |

应急响应前一小时用分诊包批量分类，需要动手挖的时候换 binary_re（并走沙箱审批）。
两个包都支持同一套判定、审计与全量停止，切换只改部署上下文的 `engagement.pack`。

**已知缺口（诚实说明）**：`stop.immediate_on` 目前只解析、没有消费者——yaml 里声明的
"立即停止条件"（`sample_upload_attempt` / `host_execution_attempt` / `execution_attempt_any` 等）
不会把任务升级为全量停止；实际生效的是对**该次动作**的硬拒绝（拒命令 / 出网白名单 / 范围判定）。
要不要让这类红线升级为全量停止是可配置的运营决策，接线前文档不把它当保证。

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
