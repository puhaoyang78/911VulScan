#!/bin/sh
# Minimal Ubuntu images may not have Python or CA certificates yet.
# APT's existing Ubuntu signatures and package hashes remain mandatory.
set -eu
apt_dir=${1:-/etc/apt}
set -- "$apt_dir/sources.list" "$apt_dir/sources.list.d/"*.list "$apt_dir/sources.list.d/"*.sources
for source do
    if [ -e "$source" ] || [ -L "$source" ]; then
        [ -f "$source" ] && [ ! -L "$source" ] || { printf 'Refusing non-regular APT source: %s\n' "$source" >&2; exit 1; }
    fi
done
pattern='https?://(([a-z]{2}\.)?archive|security|ports)\.ubuntu\.com/(ubuntu(-ports)?)([/[:space:]]|$)'
for source do
    [ -f "$source" ] || continue
    if grep -Eiq "$pattern" "$source"; then
        # GNU sed replaces atomically and preserves ownership, mode and ACLs.
        # Replace only official URI tokens, keeping suites/components/Signed-By.
        sed -i -E "s#$pattern#http://mirrors.aliyun.com/\3\5#gI" "$source"
        printf 'Ubuntu mirror updated: %s\n' "$source"
    fi
done
