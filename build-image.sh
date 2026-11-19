#!/usr/bin/env bash
# 远程镜像（autumn27/artex）不可用时，从源码重建镜像并启动。
#
# 思路：直接把镜像打成 docker-compose.yml 里 image: 期望的名字（autumn27/artex:<tag>），
# 原 compose 一个字都不用改 —— compose 发现本地已有该 tag 就不会再去 pull。
#
#   ./build-image.sh                      # 常态
#   MIRROR=1 ./build-image.sh             # 慢网/国内（Kali 直连 npm、proxy.golang.org 会卡死）
#   HTTPS_PROXY=http://192.168.1.10:7890 ./build-image.sh   # 有代理（BuildKit 自动透传）
#   SKIP_PLAYWRIGHT=1 ./build-image.sh    # 不要 browser MCP，镜像小很多
#   BUILD_ONLY=1 ./build-image.sh         # 只出镜像不启动
#
# MIRROR=1 展开为：APT_MIRROR=mirrors.tuna.tsinghua.edu.cn
#                  NPM_REGISTRY=https://registry.npmmirror.com
#                  GOPROXY=https://goproxy.cn,direct
#                  PLAYWRIGHT_DOWNLOAD_HOST=https://npmmirror.com/mirrors/playwright
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
ARTEX_VERSION="${ARTEX_VERSION:-dev}"
SKIP_PLAYWRIGHT="${SKIP_PLAYWRIGHT:-0}"
PLATFORM="${PLATFORM:-}"

if [ "${MIRROR:-0}" = "1" ]; then
  APT_MIRROR="${APT_MIRROR:-mirrors.tuna.tsinghua.edu.cn}"
  NPM_REGISTRY="${NPM_REGISTRY:-https://registry.npmmirror.com}"
  GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
  PLAYWRIGHT_DOWNLOAD_HOST="${PLAYWRIGHT_DOWNLOAD_HOST:-https://npmmirror.com/mirrors/playwright}"
fi
APT_MIRROR="${APT_MIRROR:-}"
NPM_REGISTRY="${NPM_REGISTRY:-}"
GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
PLAYWRIGHT_DOWNLOAD_HOST="${PLAYWRIGHT_DOWNLOAD_HOST:-}"

command -v docker >/dev/null 2>&1 || die "未检测到 docker"
[ -f Dockerfile.local ] || die "缺少 Dockerfile.local"
HAVE_BUILDX=0
docker buildx version >/dev/null 2>&1 && HAVE_BUILDX=1

[ -f .env ] || { cp .env.example .env; ok "已生成 .env（记得改 POSTGRES_PASSWORD）"; }
grep -q '^POSTGRES_PASSWORD=change-me-please' .env && die "请先把 .env 里的 POSTGRES_PASSWORD 改掉"

tag_env="$(sed -n 's/^ARTEX_TAG=//p' .env | tail -n1)"
IMAGE="${IMAGE:-ghcr.io/br0ny4/artex-redev:${ARTEX_TAG:-${tag_env:-latest}}}"

mkdir -p logs
LOG="${BUILD_LOG:-logs/build.log}"
args=(docker build -f Dockerfile.local -t "$IMAGE")
[ "$HAVE_BUILDX" = "1" ] && args+=(--progress=plain)
[ -n "$APT_MIRROR" ]               && args+=(--build-arg "APT_MIRROR=$APT_MIRROR")
[ -n "$NPM_REGISTRY" ]             && args+=(--build-arg "NPM_REGISTRY=$NPM_REGISTRY")
[ -n "$GOPROXY" ]                  && args+=(--build-arg "GOPROXY=$GOPROXY")
[ -n "$PLAYWRIGHT_DOWNLOAD_HOST" ] && args+=(--build-arg "PLAYWRIGHT_DOWNLOAD_HOST=$PLAYWRIGHT_DOWNLOAD_HOST")
args+=(--build-arg "SKIP_PLAYWRIGHT=$SKIP_PLAYWRIGHT" --build-arg "ARTEX_VERSION=$ARTEX_VERSION")
[ -n "$PLATFORM" ] && args+=(--platform "$PLATFORM")
[ "${NO_CACHE:-0}" = "1" ] && args+=(--no-cache)
args+=(.)

info "构建镜像 $IMAGE"
info "  NPM_REGISTRY=${NPM_REGISTRY:-<默认 registry.npmjs.org>}"
info "  GOPROXY=${GOPROXY}"
info "  APT_MIRROR=${APT_MIRROR:-<默认 deb.debian.org>}   SKIP_PLAYWRIGHT=$SKIP_PLAYWRIGHT"
info "  日志：$LOG（另开终端 tail -f $LOG 可看实时进度）"

set -o pipefail
if ! "${args[@]}" 2>&1 | tee "$LOG"; then
  echo >&2
  die "构建失败，先看日志末尾：tail -n 80 $LOG
  拉包超时/卡住  -> MIRROR=1 ./build-image.sh
  基础镜像拉不动 -> 配 /etc/docker/daemon.json 的 registry-mirrors
  apt 卡住       -> APT_MIRROR=mirrors.aliyun.com MIRROR=1 ./build-image.sh"
fi
ok "镜像已生成：$IMAGE"

[ "${BUILD_ONLY:-0}" = "1" ] && { info "BUILD_ONLY=1，跳过启动"; exit 0; }
[ -f "$COMPOSE_FILE" ] || die "镜像已就绪，但没找到 $COMPOSE_FILE，请手动 docker run"

info "启动（compose 会直接用本地这个 tag，不再 pull）…"
docker compose -f "$COMPOSE_FILE" up -d
docker compose -f "$COMPOSE_FILE" ps
ok "完成 → http://localhost:8787"
info "日志：docker compose -f $COMPOSE_FILE logs -f artex"
