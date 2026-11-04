#!/bin/bash
# CentOS 7 host: frozen Docker RPMs; supported userspace in an application image.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail() { printf '错误：%s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
用法：bash scripts/install-centos7.sh [--dry-run | --check]
  无参数      安装所需 Docker，构建应用，验证并启动开机自启服务。
  --dry-run   仅显示部署计划，不安装、不下载、不停止服务。
  --check     检查已部署服务、实际程序、全部解析器及 Docker 构建/运行/清理。
  --help      显示帮助。
适用 CentOS Linux 7 / x86_64 / systemd / 内核 >=3.10.0-514.el7；需 root。
CentOS 7 与 Docker 26.1.4 均已停止维护。容器不升级宿主机内核；旧内核的
运行兼容性由部署检查验证，不等同于 Node.js 官方支持或完整扫描验收。
不替换系统 Python、OpenSSL、glibc，不关闭 SELinux、防火墙或容器安全限制。
CentOS 7 网页监听 0.0.0.0:8080，可通过服务器内网 IP 访问；新用户直接注册，已有账号登录。
EOF
}
MODE=deploy
if [ "$#" -gt 0 ]; then
    [ "$#" = 1 ] || fail '只接受一个选项；参见 --help。'
    case "$1" in --dry-run) MODE=plan;; --check) MODE=check;; --help|-h) usage; exit 0;; *) fail "未知选项：$1";; esac
fi
os_release=${VULSCAN_OS_RELEASE:-/etc/os-release}
os_id=$(sed -n 's/^ID=//p' "$os_release" | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' "$os_release" | tr -d '"')
[ "$os_id:$os_version" = centos:7 ] || fail "此入口仅适用 CentOS Linux 7；检测到 $os_id $os_version。"
[ "$(uname -m)" = x86_64 ] || fail '此入口仅适用 x86_64。'
kernel=$(uname -r)
if ! [[ "$kernel" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9]+))? ]]; then fail "无法识别内核：$kernel"; fi
major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}; release=${BASH_REMATCH[5]:-0}
if (( major < 3 || (major == 3 && minor < 10) || (major == 3 && minor == 10 && patch == 0 && release < 514) )); then
    fail "内核 $kernel 不满足部署要求（CentOS 7 至少 3.10.0-514.el7）；脚本不会升级内核或自动重启。"
fi
UNIT_DIR=${VULSCAN_SYSTEMD_DIR:-/etc/systemd/system}
UNIT="$UNIT_DIR/vulscan.service"
MARKER='# Managed by 911VulScan CentOS 7 installer'
HOME_DIR=/var/lib/vulscan
APP_ROOT=/opt/911VulScan
CONTAINER=911vulscan
LABEL=org.911vulscan.deployment
LIBEXEC_DIR=${VULSCAN_LIBEXEC_DIR:-/usr/local/libexec}
STOPPER="$LIBEXEC_DIR/vulscan-centos7-stop"
[[ "$STOPPER" =~ ^/[a-zA-Z0-9_./-]+$ ]] || fail '服务辅助脚本需要无空白的绝对路径。'
DOCKER_SOCKET=${VULSCAN_DOCKER_SOCKET:-/var/run/docker.sock}
[[ "$DOCKER_SOCKET" =~ ^/[a-zA-Z0-9_./-]+$ ]] || fail 'Docker socket 路径需要无空白的绝对路径。'
if [ -L "$UNIT" ] || { [ -e "$UNIT" ] && ! grep -qxF "$MARKER" "$UNIT"; }; then
    fail "已有 $UNIT 不属于此入口；未覆盖服务或迁移数据。"
fi
if [ -L "$STOPPER" ] || { [ -e "$STOPPER" ] && ! grep -qxF "$MARKER" "$STOPPER"; }; then
    fail "已有 $STOPPER 不属于此入口，未覆盖文件。"
fi
if [ "$MODE" = plan ]; then
    cat <<EOF
CentOS 7 部署计划：内核 $kernel
  1. 复用已有 Docker（至少 20.10）；缺失时从阿里云归档镜像安装 Engine/CLI 26.1.4、containerd 1.6.33。
     CentOS/Docker RPM 使用阿里云镜像，仅为本次 yum 调用启用，不改写现有源。
  2. 构建 scripts/centos7.Dockerfile：Ubuntu 24.04 用户空间、Python 3.12、Go 1.26、Node 22、Compose、Buildx。
  3. 创建/复用非 root 的 vulscan 服务账号；配置在 $HOME_DIR/.config/vulscan，扫描数据在 $HOME_DIR/.vulscan。
     Docker 配置保存在 $HOME_DIR/.docker，保留已有内容与权限。
  4. 验证全部解析器、Docker 构建/运行/清理；有活动扫描时拒绝更新。
  5. 启用并重启 vulscan.service，校验镜像、实际进程与监听端口；地址 http://服务器内网IP:8080。
不升级内核/系统 Python/glibc，不删除已有镜像/容器，不改 Docker socket 权限。
应用容器使用宿主网络（服务绑定内网 IPv4）与 Docker socket，二阶段测试仍由原实现执行。
注意：CentOS 7 与 Docker 26.1.4 已停止维护；容器仍使用宿主机内核。
EOF
    exit 0
fi
[ "$(id -u)" = 0 ] || fail '请使用 root 或 sudo bash scripts/install-centos7.sh 执行。'
command -v systemctl >/dev/null && systemctl show-environment >/dev/null || fail '需要以 systemd 启动的 CentOS 7；容器内不能执行宿主部署。'
command -v flock >/dev/null || fail '缺少 util-linux/flock，请先修复系统基础工具。'
exec 9>"$UNIT_DIR/.vulscan-centos7.lock"
flock -n 9 || fail '另一个 CentOS 7 部署/检查进程正在运行。'
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
printf '注意：CentOS 7 与归档 Docker 已停止维护；本次部署不升级宿主机内核。\n'
[ "${DOCKER_HOST:-unix://$DOCKER_SOCKET}" = "unix://$DOCKER_SOCKET" ] || fail 'DOCKER_HOST 需要指向本机 Docker socket；配置未改变。'
[ -z "${DOCKER_CONTEXT:-}" ] || fail '请取消 DOCKER_CONTEXT 后使用本机 Docker；不会修改已有 context。'
export DOCKER_HOST="unix://$DOCKER_SOCKET"

fetch() {
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 20 --max-time 600 --retry 3 --output "$2" "$1"
}
install_docker() {
    # Refuse to replace an existing/incomplete installation or Podman shim.
    for executable in docker dockerd containerd podman; do
        ! command -v "$executable" >/dev/null || fail "检测到已有 $executable，未替换；请先检查原有 Docker 安装。"
    done
    for package in docker docker-common docker-client docker-ce docker-ce-cli containerd.io podman-docker; do
        ! rpm -q "$package" >/dev/null 2>&1 || fail "检测到已有 $package，未移除或降级；请完成原有 Docker 安装。"
    done
    [ ! -e /etc/docker/daemon.json ] || fail '已有 Docker daemon.json，但缺少可用 Docker；请先修复原有安装，配置未改变。'
    mkdir "$TMP/repos"
    centos_key=/etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
    printf '%s  %s\n' 8b48b04b336bd725b9e611c441c65456a4168083c4febc28e88828d8ec14827f "$centos_key" | sha256sum --check --status || fail '系统 CentOS 7 RPM 签名密钥不符；未安装软件。'
    for section in os updates extras; do
        cat >> "$TMP/repos/vulscan.repo" <<EOF
[vulscan-centos-$section]
name=CentOS 7.9.2009 archive $section (911VulScan deployment only)
baseurl=https://mirrors.aliyun.com/centos-vault/7.9.2009/$section/x86_64/
enabled=1
gpgcheck=1
gpgkey=file://$centos_key
sslverify=1
EOF
    done
    # Minimal installations can lack curl; yum and the OS signing key are part
    # of CentOS itself. Bootstrap downloads without executing a remote script.
    yum --assumeyes --setopt="reposdir=$TMP/repos" --setopt=obsoletes=0 \
        --disablerepo='*' --enablerepo='vulscan-*' install ca-certificates curl \
        || fail '基础下载工具安装失败；请检查阿里云 CentOS Vault 连接及 yum 输出。'
    fetch https://mirrors.aliyun.com/docker-ce/linux/centos/gpg "$TMP/docker.key"
    printf '%s  %s\n' e6c650e0700b1bf4868b693b30761b926844befc8a0acb7ac0dd9b1faf1b7423 "$TMP/docker.key" | sha256sum --check --status || fail 'Docker 官方 RPM 签名密钥校验失败，未安装 Docker。'
    cat >> "$TMP/repos/vulscan.repo" <<EOF
[vulscan-docker]
name=Docker official CentOS 7 archive (911VulScan deployment only)
baseurl=https://mirrors.aliyun.com/docker-ce/linux/centos/7/x86_64/stable
enabled=1
gpgcheck=1
gpgkey=file://$TMP/docker.key
sslverify=1
EOF
    yum --assumeyes --setopt="reposdir=$TMP/repos" --setopt=obsoletes=0 \
        --disablerepo='*' --enablerepo='vulscan-*' install \
        docker-ce-26.1.4-1.el7.x86_64 docker-ce-cli-26.1.4-1.el7.x86_64 \
        containerd.io-1.6.33-3.1.el7.x86_64 \
        || fail '归档 Docker 安装失败，请检查阿里云镜像连接和 yum 输出；未修改现有源或系统 Python。修复后可重试原命令。'
}
if ! command -v docker >/dev/null || ! command -v dockerd >/dev/null; then
    [ "$MODE" = deploy ] || fail 'Docker 尚未安装，无法检查已部署服务。'
    install_docker
fi
DOCKER=$(command -v docker)
case "$DOCKER" in /*) :;; *) fail 'Docker 命令需要绝对路径。';; esac
[[ "$DOCKER" =~ ^/[a-zA-Z0-9_./-]+$ ]] || fail 'Docker 命令路径不能包含空白或 shell/systemd 特殊字符。'
if [ "$MODE" = deploy ]; then systemctl start docker || fail 'Docker 启动失败；请检查 journalctl -u docker。'; fi
version=$(docker version --format '{{.Server.Version}}') || fail '无法访问本机 Docker；未修改 socket 权限。'
if ! [[ "$version" =~ ^([0-9]+)\.([0-9]+)\. ]]; then fail "无法识别 Docker 版本：$version"; fi
(( BASH_REMATCH[1] > 20 || (BASH_REMATCH[1] == 20 && BASH_REMATCH[2] >= 10) )) || fail '已有 Docker 低于 20.10，请通过原安装方式更新；未自动替换。'
[ -S "$DOCKER_SOCKET" ] || fail "需要本机 $DOCKER_SOCKET；不支持远程 Docker。"
socket_gid=$(stat -c %g "$DOCKER_SOCKET")
getent group docker >/dev/null || fail 'Docker 安装缺少 docker 组；未修改 socket 权限。'
[ "$socket_gid" = "$(getent group docker | cut -d: -f3)" ] || fail 'Docker socket 组与 docker 组不符；请检查原安装权限，脚本不会放宽权限。'
# Host SELinux stays enabled. A daemon with container SELinux confinement needs
# an administrator-owned policy for socket access; do not silently disable it.
security=$(docker info --format '{{json .SecurityOptions}}')
[[ "$security" != *name=selinux* ]] || fail 'Docker 已启用容器 SELinux 隔离；需管理员配置应用访问 Docker socket 的专用策略。脚本不会关闭 SELinux 或给容器特权。'

if getent passwd vulscan >/dev/null; then
    uid=$(id -u vulscan); gid=$(id -g vulscan)
    [ "$uid" != 0 ] && [ "$(getent passwd vulscan | cut -d: -f6)" = "$HOME_DIR" ] || fail '已有 vulscan 账号的 UID/主目录不符，未改变账号或数据。'
elif [ "$MODE" = deploy ]; then
    [ ! -e "$HOME_DIR" ] || fail "$HOME_DIR 已存在但没有对应账号；请先核实数据所有权。"
    useradd --system --user-group --create-home --home-dir "$HOME_DIR" --shell /sbin/nologin vulscan
    uid=$(id -u vulscan); gid=$(id -g vulscan)
else fail 'vulscan 服务账号不存在。'; fi
if [ "$MODE" = deploy ]; then
    for directory in "$HOME_DIR" "$HOME_DIR/.vulscan" "$HOME_DIR/.docker" "$HOME_DIR/tmp"; do
        [ ! -L "$directory" ] || fail "拒绝通过符号链接修改服务目录：$directory。"
        if [ ! -e "$directory" ]; then install -d -o vulscan -g "$(id -gn vulscan)" -m 0700 "$directory"; fi
        runuser -u vulscan -- test -r "$directory" && runuser -u vulscan -- test -w "$directory" && runuser -u vulscan -- test -x "$directory" || fail "$directory 无法被服务账号访问；未改变已有权限或数据。"
    done
fi
runtime=(--network host --user "$uid:$gid" --group-add "$socket_gid"
    --env "HOME=$HOME_DIR" --env USER=vulscan --env "DOCKER_CONFIG=$HOME_DIR/.docker" --env "TMPDIR=$HOME_DIR/tmp"
    --volume "$HOME_DIR:$HOME_DIR" --volume "$DOCKER_SOCKET:/var/run/docker.sock")
checker=("$APP_ROOT/.venv/bin/python" "$APP_ROOT/scripts/check-deployment.py" --root "$APP_ROOT")
old_image=''
if [ -f "$UNIT" ]; then
    old_image=$(sed -n 's/^Environment=VULSCAN_IMAGE=//p' "$UNIT")
    [[ "$old_image" =~ ^sha256:[0-9a-f]{64}$ ]] || fail '已有服务缺少有效镜像 ID；未覆盖服务。'
fi
container_id=$(docker container ls --all --filter "name=^/$CONTAINER$" --format '{{.ID}}') || fail '无法列出本机 Docker 容器。'
inspect=''
if [ -n "$container_id" ]; then
    inspect=$(docker container inspect --format '{{index .Config.Labels "org.911vulscan.deployment"}} {{.State.Running}} {{.Image}}' "$CONTAINER") || fail '无法检查已有应用容器。'
fi
if [ -n "$inspect" ]; then
    [ "$inspect" = "centos7 true $old_image" ] || fail "容器名 $CONTAINER 已被占用或原服务状态异常；未删除容器。"
    systemctl is-active --quiet vulscan || fail '应用容器仍在运行但 systemd 服务未运行；请检查原服务，未停止容器。'
elif systemctl is-active --quiet vulscan; then
    fail '原服务正在运行，但未发现对应容器；请检查原服务状态。'
fi
idle() {
    if [ -n "$inspect" ]; then
        docker exec --user "$uid:$gid" "$CONTAINER" "${checker[@]}" --idle-url http://127.0.0.1:8080 --service-pid 1 --service-uid "$uid" \
            || fail '仍有活动扫描或无法确认原服务状态；未停止旧服务。'
    fi
}
verify() {
    expected=$1
    [ "$(docker inspect --format '{{.State.Running}} {{.Image}}' "$CONTAINER")" = "true $expected" ] || fail '实际运行容器与本次构建镜像不一致。'
    docker exec --user "$uid:$gid" "$CONTAINER" "${checker[@]}" --url http://127.0.0.1:8080 --service-pid 1 --service-uid "$uid" || fail '网页、实际程序或监听端口校验失败。'
    systemctl is-active --quiet vulscan || fail 'vulscan.service 未处于运行状态。'
}
if [ "$MODE" = check ]; then
    [ -n "$old_image" ] && [ -n "$inspect" ] || fail '未找到运行中的已部署服务。'
    verify "$old_image"
    docker exec --user "$uid:$gid" "$CONTAINER" "${checker[@]}"
    docker exec --user "$uid:$gid" "$CONTAINER" "${checker[@]}" --docker
    exit 0
fi
idle
build_sources=(apps/vulscan-cli libs/vulscan-core config/languages.json config/models.json
    scripts/install-deployment.sh scripts/check-deployment.py scripts/configure-ubuntu-mirrors.sh
    scripts/select-docker-packages.py scripts/centos7.Dockerfile)
for source in "${build_sources[@]}" scripts/stop-centos7.sh; do
    [ -e "$ROOT/$source" ] || fail "缺少 $source；请解压完整源码部署包后执行。"
done
mkdir "$TMP/context"
# Only build inputs; never send repository credentials, user data or local tools
# to Docker. Separate the producer so a tar failure cannot look like success.
tar -C "$ROOT" --exclude=.git --exclude='.env*' --exclude=.venv --exclude=.tools \
    --exclude=node_modules --exclude=__pycache__ --exclude=tests --exclude=testdata \
    --exclude=test_output --exclude=test_data --exclude='*_test.go' --exclude='*.pyc' \
    --exclude='*.log' --exclude=apps/vulscan-cli/vulscan-cli --exclude=apps/vulscan-cli/vulscan \
    --exclude=libs/vulscan-core/parsers/go/go_parser/go_parser \
    -cf "$TMP/source.tar" "${build_sources[@]}"
tar -xf "$TMP/source.tar" -C "$TMP/context"
# Engine 26 retains the legacy builder, avoiding a new host BuildKit runtime on
# the old kernel. The application still uses its existing Buildx validation.
DOCKER_BUILDKIT=0 docker build --network host --iidfile "$TMP/image-id" \
    --build-arg HTTP_PROXY --build-arg HTTPS_PROXY --build-arg NO_PROXY \
    --build-arg http_proxy --build-arg https_proxy --build-arg no_proxy \
    -f "$TMP/context/scripts/centos7.Dockerfile" "$TMP/context" \
    || fail '应用镜像构建失败；请检查镜像源、构建日志及内核兼容性。旧服务未停止，修复后可重试。'
image=$(cat "$TMP/image-id")
[[ "$image" =~ ^sha256:[0-9a-f]{64}$ ]] || fail '构建未返回有效镜像 ID。'
docker run --rm "${runtime[@]}" --entrypoint "${checker[0]}" "$image" "${checker[@]:1}" \
    || fail '非 root 账号的解析器验证失败；旧服务未停止。'
docker run --rm "${runtime[@]}" --entrypoint "${checker[0]}" "$image" "${checker[@]:1}" --docker \
    || fail '二阶段所需 Docker 验证失败；旧服务未停止。'
# Scans could have started while the image was building. Check again at the
# last possible point; stopping uses the application's normal drain handler.
idle
[ -d "$LIBEXEC_DIR" ] || install -d -m 0755 "$LIBEXEC_DIR"
install -m 0755 "$ROOT/scripts/stop-centos7.sh" "$STOPPER"
if [ -f "$UNIT" ]; then
    state=$(systemctl show -p ActiveState vulscan | sed -n 's/^ActiveState=//p')
    case "$state" in active|inactive|failed) :;; *) fail '原服务正在启动/停止，未覆盖服务；待状态稳定后重试。';; esac
    systemctl stop vulscan || fail '原服务未能正常停止，未替换服务配置。'
    [ "$(systemctl show -p ActiveState vulscan | sed -n 's/^ActiveState=//p')" = inactive ] || fail '原服务尚未停止。'
    "$STOPPER" "$DOCKER" "$CONTAINER" || fail '旧应用容器尚未完成清理，未替换服务配置。'
fi
cat > "$TMP/vulscan.service" <<EOF
$MARKER
[Unit]
Description=911VulScan on CentOS 7
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=vulscan
SupplementaryGroups=docker
Environment=HOME=$HOME_DIR
Environment=DOCKER_CONFIG=$HOME_DIR/.docker
Environment=DOCKER_HOST=unix://$DOCKER_SOCKET
Environment=DOCKER_CONTEXT=
Environment=VULSCAN_IMAGE=$image
ExecStartPre=$STOPPER $DOCKER $CONTAINER
ExecStartPre=$DOCKER run --rm --network host --user $uid:$gid --group-add $socket_gid --env HOME=$HOME_DIR --env USER=vulscan --env DOCKER_CONFIG=$HOME_DIR/.docker --env TMPDIR=$HOME_DIR/tmp --volume $HOME_DIR:$HOME_DIR --volume $DOCKER_SOCKET:/var/run/docker.sock --entrypoint ${checker[0]} \${VULSCAN_IMAGE} ${checker[1]} --root $APP_ROOT --docker
ExecStart=$DOCKER run --rm --name $CONTAINER --label $LABEL=centos7 --network host --user $uid:$gid --group-add $socket_gid --env HOME=$HOME_DIR --env USER=vulscan --env DOCKER_CONFIG=$HOME_DIR/.docker --env TMPDIR=$HOME_DIR/tmp --env VULSCAN_EXTERNAL_URL --volume $HOME_DIR:$HOME_DIR --volume $DOCKER_SOCKET:/var/run/docker.sock \${VULSCAN_IMAGE}
ExecStop=$STOPPER $DOCKER $CONTAINER
Restart=on-failure
RestartSec=3
StartLimitInterval=60
StartLimitBurst=3
TimeoutStartSec=360
TimeoutStopSec=165
KillMode=process
UMask=0027

[Install]
WantedBy=multi-user.target
EOF
install -d -m 0755 "$UNIT_DIR"
install -m 0644 "$TMP/vulscan.service" "$UNIT"
if command -v restorecon >/dev/null; then restorecon "$STOPPER" "$UNIT"; fi
systemctl daemon-reload
systemctl enable docker vulscan
systemctl reset-failed vulscan
systemctl restart vulscan || fail '服务启动失败，请检查 journalctl -u vulscan -n 80。配置与扫描数据保留。'
# Type=simple reports success before Docker has created the application. Poll a
# bounded interval, then use the existing byte/UID/listener/HTTP verification.
for ((waited=0; waited<60; waited++)); do
    if [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" = true ]; then break; fi
    sleep 1
done
verify "$image"
printf '\n部署完成：监听 0.0.0.0:8080，请通过 http://服务器内网IP:8080 访问\n服务：systemctl status vulscan\n日志：journalctl -u vulscan -f\n复查：bash %s/scripts/install-centos7.sh --check\n新用户直接注册账号，再在用户设置中填写模型 API Key；已有账号直接登录。\n' "$ROOT"
