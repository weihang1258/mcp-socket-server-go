#!/usr/bin/env bash
# 发版流程（v1.9.13 事故后固化，2026-11-01）：
#   动态链接二进制发上旧 glibc 靶机 = 服务起不来（GLIBC_2.34 not found，
#   crash-loop 直到手工切回旧版本）。构建必须 CGO_ENABLED=0 且发版前 file
#   验证 statically linked——两道检查都在本脚本里，绕不过。
#
# 用法: scripts/release.sh vX.Y.Z
set -euo pipefail
cd "$(dirname "$0")/.."

tag="${1:?用法: $0 vX.Y.Z}"
ver="${tag#v}"

# 版本号必须一致：tag 与代码内 Version
code_ver=$(grep -oP '(?<=^var Version = ")[^"]+' internal/agent/handlers.go)
[ "$code_ver" = "$ver" ] || { echo "版本不一致: tag=$tag 代码=$code_ver（先改 internal/agent/handlers.go）"; exit 1; }

# 未提交改动不许发
[ -z "$(git status --porcelain)" ] || { echo "工作区不干净，先提交"; git status --short; exit 1; }

out="/tmp/socket_server_release"
CGO_ENABLED=0 go build -trimpath -o "$out" ./cmd/socketstack

# 第一道闸：必须静态链接（旧 glibc 靶机保命）
if ! file "$out" | grep -q 'statically linked'; then
    echo "FATAL: 产物不是静态链接——CGO_ENABLED=0 失效？"; exit 1
fi
[ "$("$out" version)" = "socketstack v$ver" ] || { echo "FATAL: 产物版本不符"; exit 1; }

sha=$(sha256sum "$out" | awk '{print $1}')
echo "构建 OK: $out sha256=$sha"

# 发 release（资产名必须 socket_server——README 一键安装靠 releases/latest）
cp "$out" /tmp/socket_server
gh release create "$tag" /tmp/socket_server \
    --title "$tag" --notes "${2:-socketstack $tag}"

# 镜像回源验证：sha 必须一致且仍是静态
sleep 5
for m in gh-proxy.com ghfast.top; do
    curl -sL -m 120 "https://$m/https://github.com/weihang1258/mcp-socket-server-go/releases/download/$tag/socket_server" -o /tmp/dl_verify || continue
    got=$(sha256sum /tmp/dl_verify | awk '{print $1}')
    if [ "$got" = "$sha" ] && file /tmp/dl_verify | grep -q 'statically linked'; then
        echo "镜像验证 OK: $m"; exit 0
    fi
done
echo "FATAL: 镜像回源验证失败（sha 或链接形态不符），检查 release 资产"; exit 1
