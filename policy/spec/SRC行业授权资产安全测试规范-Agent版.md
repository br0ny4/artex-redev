# 规范原文未随本仓库分发

本目录留给你放置**自己有权使用的**《SRC 行业授权资产安全测试规范 · Agent 版》。

## 为什么是空的

平台执行层（`policy/`）的**判定逻辑不依赖规范正文**：范围、语义分级、预算、红线全部已
落成 `policy/web-pentest/policy.yaml` 与 `policy/web-pentest/verb-lexicon.yaml` 这两份
机器可读配置。规范正文只用于**注入 Agent 的 system prompt**（行为基线），因此它是可替换的
输入，而不是代码依赖。

规范原文属于第三方资料，本仓库未获再分发授权，故不随仓库发布。

## 怎么用

1. 把你方持有的规范（UTF-8）放到本目录，文件名任意 `.md`；
2. 若文件名不同，改 `policy/embed.go` 里的 `//go:embed` 指向（或直接覆盖本文件）；
3. 确认 `policy/web-pentest/policy.yaml` 的 `spec.version` 与规范的版本号一致
   （规范第九章要求二者一致，不一致时平台应拒绝启动在线域）。

## 参考哈希（用于确认你手上的版本与我们开发时一致）

| 项 | 值 |
|---|---|
| 开发基线版本 | v2.5（规范 §9.1 的握手串 `[RULES_LOADED v2.5]`） |
| 原始文件 SHA-256（GB18030 编码） | `5111bc1e2cf7b471e0621dbd0e1d2a2671b712ccd1267d4e1ca325101aa35020` |
| 转 UTF-8 后 SHA-256 | `1355c218edf0affbdcbeecd96d51d6c7a47effa5bf9f68542eaf21fedb2d5a84` |
| 转换方式 | `iconv -f GB18030 -t UTF-8`，CRLF→LF，正文未做任何内容改动 |

> 提示：原始文件是 GB18030 编码。直接放进 Go 的 `//go:embed` 或 prompt 会乱码，
> 放进来之前先转成 UTF-8。
