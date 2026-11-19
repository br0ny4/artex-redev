# L2 出网强制：把容器出口收口到唯一代理

> 对应 `docs/redev/04-policy-engine.md` §2 的 L2，以及规范"红线 8（数据只能进报告通道）"。
> 目的：**让 raw socket 也出不去**。只靠 L3（mitmproxy addon）有一个致命缺口——
> `nmap`、自定义 TCP、reverse shell 这类不认 `HTTP_PROXY` 的连接会直接绕过判定。
> 这里用 Docker `internal` 网络让容器**没有默认路由**，唯一出口是 egress 代理容器。

## 结构

```
┌────────────── internal（internal: true，无外网）──────────────┐
│  artex  ──HTTP_PROXY──►  traffic 录制代理 ──上游──►  egress │
│    │                                              │        │
│    └──► postgres                                  │        └──► 互联网（唯一出口）
└───────────────────────────────────────────────────┘
```

- `artex` 与 `postgres` 只接 `internal`，没有默认路由 → `nmap`/裸 TCP/直连 IP 全部不可达；
- 所有 HTTP(S) 走 ARTEX 自己的录制代理（L3 判定），代理再把上游指到 `egress`；
- LLM 调用走 `ARTEX_LLM_PROXY` 指向同一个 `egress`。

## 用法

```bash
# 在仓库根目录（与 docker-compose.yml 同级）
docker compose -f docker-compose.yml -f deploy/egress-lockdown/docker-compose.egress.yml up -d
```

配套环境变量（`.env`）：

```bash
ARTEX_GLOBAL_PROXY=http://egress:3128
ARTEX_LLM_PROXY=http://egress:3128
```

## 验收

```bash
# 1) 容器内不应有默认路由（只应看到 internal 网段的 route）
docker compose exec artex ip route

# 2) raw socket 直连必须失败
docker compose exec artex sh -c 'timeout 5 sh -c "echo > /dev/tcp/1.1.1.1/443" && echo LEAK || echo BLOCKED'
# 期望：BLOCKED

# 3) HTTP 走代理应成功（且出现在流量录制里）
docker compose exec artex curl -sS -o /dev/null -w '%{http_code}\n' https://example.com
```

## 限制（必须知道）

1. **代理容器本身不做范围判定**。它只是"唯一出口"，范围/语义/预算仍在 ARTEX 的 L3
   与 guard 的 L1 上执行。若有人绕过 L3 直接配了 `ARTEX_GLOBAL_PROXY` 之外的出口，
   `internal` 网络会拦住。
2. **DNS**：`internal` 网络下外部域名仍可解析（Docker 内嵌 DNS 转发），所以"能解析但连不上"
   是预期现象；不要把它误当成放行。
3. **不走 compose 的部署**（裸机二进制）需要等价手段：单独的网络命名空间 + nftables
   `default drop`，只放行代理地址。见下方模板。
4. `egress` 容器建议加出站白名单（只放行目标 ASN/域名），否则它就是一个开放代理。

## 裸机 / 非 compose 的等价做法

```bash
# 1) 建 netns，只给 veth，不给默认路由
ip netns add artex-task
ip link add veth-a type veth peer name veth-b
ip link set veth-b netns artex-task

# 2) 唯一出口：代理地址（示例 10.200.0.1:3128）
ip netns exec artex-task ip route add default via 10.200.0.1
# 3) 其余一律拒绝（nftables 默认 drop 策略）
ip netns exec artex-task nft 'add table inet art; add chain inet art out { type filter hook output priority 0; policy drop; }'
ip netns exec artex-task nft 'add rule inet art out ip daddr 10.200.0.1 tcp dport 3128 accept'
ip netns exec artex-task nft 'add rule inet art out oif lo accept'
```

> 这一步是"L2"，必须在**容器/命名空间层**做；写在提示词或应用层都不算数。
