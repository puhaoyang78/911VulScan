#!/bin/bash
# Managed by 911VulScan CentOS 7 installer
# docker stop can return before a --rm container has released its name.
set -euo pipefail
docker=$1
name=$2
id=$("$docker" container ls --all --quiet --no-trunc --filter "name=^/$name$") || exit 1
[ -n "$id" ] || exit 0
remaining() {
    "$docker" container ls --all --quiet --no-trunc --filter "id=$id"
}
if ! label=$("$docker" inspect --format '{{index .Config.Labels "org.911vulscan.deployment"}}' "$id"); then
    # A previous --rm removal can finish between the list and inspect calls.
    current=$(remaining) || exit 1
    [ -z "$current" ] && exit 0
    exit 1
fi
[ "$label" = centos7 ] || { printf '拒绝停止非本服务容器：%s\n' "$name" >&2; exit 1; }
if ! "$docker" stop --time 120 "$id"; then
    current=$(remaining) || exit 1
    [ -z "$current" ] && exit 0
    exit 1
fi
for ((waited=0; waited<30; waited++)); do
    current=$(remaining) || exit 1
    [ -z "$current" ] && exit 0
    sleep 1
done
printf '容器尚未完成删除，未启动新程序：%s\n' "$name" >&2
exit 1
