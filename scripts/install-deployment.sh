#!/bin/sh
# Run from any directory; keep this installation tree together.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: scripts/install-deployment.sh [options]
  --deploy          Ubuntu one-command install, verify and start vulscan.service.
                    Includes Docker startup and frozen Docker on Ubuntu 20.04.
  --service-user USER  Account for --deploy (default: sudo caller/current user;
                    root-only installation creates the non-login vulscan user).
  (no options)       Install the application using existing dependencies, no sudo.
  --install-deps     Bootstrap missing dependencies on Ubuntu 20.04/22.04/24.04/26.04.
  --deps-only        With --install-deps, skip application installation.
  --check            Read-only dependency check; exit 1 if anything is missing.
  --dry-run          Read-only dependency/application plan; no downloads or sudo.
  --yes             Approve the displayed bootstrap plan noninteractively.
  --start-docker    Also consent to installing/starting local Docker services.
  --allow-unsupported-docker  Opt into frozen Docker packages on Ubuntu 20.04.
  --help            Show this help.
Python >=3.11 (venv/ensurepip), Go >=1.26, Node 20 or >=22, npm >=7 and Git >=2.32 required.
Docker Engine/CLI, Compose v2+ and Buildx are checked separately; Docker is optional
for application installation. --install-deps includes missing Docker components.
Docker package scripts may start/enable services; fresh installation therefore
requires --start-docker as well as plan approval. Missing CLI plugins on an
existing Engine install are user-local only; no --start-docker or frozen-engine
opt-in is needed. No Docker group membership, socket, daemon or credential edits.
EOF
}
BOOTSTRAP=0; DEPS_ONLY=0; CHECK=0; DRY=0; YES=0; START_DOCKER=0; ALLOW_OLD_DOCKER=0; DEPLOY=0
SERVICE_USER_OPTION=''
while [ "$#" -gt 0 ]; do
    arg=$1; shift
    case "$arg" in
        --deploy) DEPLOY=1; BOOTSTRAP=1; YES=1; START_DOCKER=1; ALLOW_OLD_DOCKER=1;;
        --install-deps) BOOTSTRAP=1;; --deps-only) DEPS_ONLY=1;;
        --check) CHECK=1;; --dry-run) DRY=1;; --yes) YES=1;;
        --allow-unsupported-docker) ALLOW_OLD_DOCKER=1;;
        --start-docker) START_DOCKER=1;; --help|-h) usage; exit 0;;
        --service-user) [ "$#" -gt 0 ] || fail '--service-user requires an account name'; SERVICE_USER_OPTION=$1; shift;;
        *) fail "Unknown option: $arg (see --help)";;
    esac
done
[ -z "$SERVICE_USER_OPTION" ] || [ "$DEPLOY" = 1 ] || fail '--service-user requires --deploy'
[ "$SERVICE_USER_OPTION" != root ] || fail '--service-user must name a non-root account'
[ "$DEPLOY" = 0 ] || [ "$DEPS_ONLY$CHECK" = 00 ] || fail '--deploy cannot be combined with --deps-only or --check'
[ "$DEPS_ONLY" = 0 ] || [ "$BOOTSTRAP" = 1 ] || fail '--deps-only requires --install-deps'
[ "$START_DOCKER" = 0 ] || [ "$BOOTSTRAP" = 1 ] || fail '--start-docker requires --install-deps'
[ "$YES" = 0 ] || [ "$BOOTSTRAP" = 1 ] || fail '--yes requires --install-deps'
[ "$ALLOW_OLD_DOCKER" = 0 ] || [ "$BOOTSTRAP" = 1 ] || fail '--allow-unsupported-docker requires --install-deps'
[ "$CHECK" = 0 ] || [ "$DRY" = 0 ] || fail 'Choose --check or --dry-run, not both'
# App-local tools never replace /usr/bin or /usr/local binaries.
PATH="$ROOT/.tools/git/bin:$ROOT/.tools/go/bin:$ROOT/.tools/node/bin:$PATH"
export PATH
privileged() {
    if [ "$(id -u)" = 0 ]; then "$@"; else sudo -- "$@"; fi
}
service_run() {
    if [ "$DEPLOY" = 1 ] && [ "$(id -u)" != "$service_uid" ]; then
        privileged runuser -u "$service_user" -- env HOME="$service_home" DOCKER_CONFIG="$DOCKER_CONFIG" PATH="$PATH" "$@"
    elif [ "$DEPLOY" = 1 ]; then
        env HOME="$service_home" DOCKER_CONFIG="$DOCKER_CONFIG" "$@"
    else
        "$@"
    fi
}
CREATE_SERVICE_USER=0
if [ "$DEPLOY" = 1 ]; then
    SYSTEMD_DIR=${VULSCAN_SYSTEMD_DIR:-/etc/systemd/system}
    unit="$SYSTEMD_DIR/vulscan.service"
    if [ -L "$unit" ] || { [ -e "$unit" ] && ! grep -q '^# Managed by 911VulScan installer$' "$unit"; }; then
        fail "Existing $unit is not managed by this installer; it was not overwritten."
    fi
    previous_user=''
    previous_home=''; previous_docker_config=''
    if [ -f "$unit" ]; then
        previous_user=$(sed -n 's/^User=//p' "$unit")
        previous_env=$(python3 - "$unit" <<'PYENV'
import shlex, sys
from pathlib import Path
values = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    if line.startswith("Environment="):
        for entry in shlex.split(line[len("Environment="):]):
            name, _, value = entry.partition("=")
            values[name] = value.replace("%%", "%")
print(values.get("HOME", ""))
print(values.get("DOCKER_CONFIG", ""))
PYENV
        )
        previous_home=$(printf '%s\n' "$previous_env" | sed -n '1p')
        previous_docker_config=$(printf '%s\n' "$previous_env" | sed -n '2p')
        [ -n "$previous_user" ] && [ -n "$previous_home" ] || fail 'Managed service is missing User/HOME; inspect the existing unit before updating.'
    fi
    service_user=$SERVICE_USER_OPTION
    if [ -z "$service_user" ]; then
        if [ -n "$previous_user" ] && [ "$previous_user" != root ]; then service_user=$previous_user
        elif [ "$(id -u)" = 0 ]; then service_user=${SUDO_USER:-vulscan}
        else service_user=$(id -un); fi
    fi
    [ "$service_user" != root ] || service_user=vulscan
    case "$service_user" in ''|*[!a-zA-Z0-9_-]*) fail 'Invalid service account name';; esac
    if getent passwd "$service_user" >/dev/null; then
        service_uid=$(id -u "$service_user")
        service_group=$(id -gn "$service_user")
        service_home=$(getent passwd "$service_user" | cut -d: -f6)
        if [ "$previous_user" = "$service_user" ]; then service_home=$previous_home; fi
        [ "$service_uid" != 0 ] || fail 'The service account must not have UID 0.'
    elif [ "$service_user" = vulscan ] && [ -z "$SERVICE_USER_OPTION" ] && [ "$(id -u)" = 0 ]; then
        CREATE_SERVICE_USER=1; service_uid=''; service_group=vulscan; service_home=/var/lib/vulscan
    else
        fail "Service account $service_user does not exist; create it or choose an existing non-root account with --service-user."
    fi
    case "$service_home" in /*) :;; *) fail 'The service account needs an absolute home directory.';; esac
    if [ "$previous_user" = "$service_user" ]; then
        DOCKER_CONFIG=${DOCKER_CONFIG:-${previous_docker_config:-$service_home/.docker}}
    else
        DOCKER_CONFIG=${DOCKER_CONFIG:-$service_home/.docker}
    fi
    case "$DOCKER_CONFIG" in /*) :;; *) DOCKER_CONFIG="$PWD/$DOCKER_CONFIG";; esac
    export DOCKER_CONFIG
    printf 'Service account: %s; HOME=%s; DOCKER_CONFIG=%s\n' "$service_user" "$service_home" "$DOCKER_CONFIG"
fi
PYTHON=${PYTHON:-python3}
if [ -x "$ROOT/.tools/python/bin/python3.12" ] && [ "$PYTHON" = python3 ]; then PYTHON="$ROOT/.tools/python/bin/python3.12"; fi
version_at_least() {
    printf '%s\n' "$1" | awk -F. -v maj="$2" -v min="$3" '
      /^[0-9]+\.[0-9]+(\.[0-9]+)?$/ {exit !(($1>maj)||($1==maj && $2>=min))}
      !/^[0-9]+\.[0-9]+(\.[0-9]+)?$/ {exit 1}'
}
python_ok() {
    "$PYTHON" -c '
import sys, ssl, sqlite3, bz2, lzma, ctypes, readline, venv, ensurepip, zipfile
from pathlib import Path
if sys.version_info < (3,11):
    sys.exit(1)
if Path(sys.prefix).resolve() == Path(sys.argv[1]).resolve():
    # A legacy interrupted altinstall may import ensurepip while its bundled
    # wheel is missing. System/Ubuntu Python uses distribution wheels instead.
    wheels = list((Path(ensurepip.__file__).parent / "_bundled").glob("pip-*.whl"))
    if not wheels or any(not zipfile.is_zipfile(p) for p in wheels):
        sys.exit(1)
' "$ROOT/.tools/python" >/dev/null 2>&1
}
go_ok() {
    gv=$(GOTOOLCHAIN=local go version 2>/dev/null | awk '{sub(/^go/, "", $3); print $3}') || return 1
    [ -n "$gv" ] && version_at_least "$gv" 1 26
}
node_ok() {
    nv=$(node --version 2>/dev/null) || return 1
    nv=${nv#v}; nm=${nv%%.*}
    version_at_least "$nv" 20 0 && { [ "$nm" = 20 ] || version_at_least "$nv" 22 0; }
}
npm_ok() { npmv=$(npm --version 2>/dev/null) && version_at_least "$npmv" 7 0; }
git_ok() { gitv=$(git --version 2>/dev/null | awk '{print $3}') && version_at_least "$gitv" 2 32; }
engine_ok() { dockerd --version >/dev/null 2>&1 && docker --version >/dev/null 2>&1; }
compose_ok() { docker compose version --short 2>/dev/null | grep -Eq '^v?([2-9]|[1-9][0-9]+)\.'; }
buildx_ok() { docker buildx version >/dev/null 2>&1; }
docker_ok() { engine_ok && compose_ok && buildx_ok; }
package_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed$'; }
NEED_PY=0; NEED_GO=0; NEED_NODE=0; NEED_DOCKER=0; NEED_GIT=0
NEED_ENGINE=0; NEED_COMPOSE=0; NEED_BUILDX=0; LOCAL_PLUGINS=0
python_ok || NEED_PY=1
if [ "$PYTHON" = "$ROOT/.tools/python/bin/python3.12" ] && [ -f "$ROOT/.tools/python/.911vulscan-installing" ]; then NEED_PY=1; fi
go_ok || NEED_GO=1
git_ok || NEED_GIT=1
if ! node_ok || ! npm_ok; then NEED_NODE=1; fi
if [ "$DEPLOY" = 1 ] && ! version_at_least "${nv:-0.0}" 22 0; then NEED_NODE=1; fi
engine_ok || NEED_ENGINE=1
compose_ok || NEED_COMPOSE=1
buildx_ok || NEED_BUILDX=1
if [ "$NEED_ENGINE$NEED_COMPOSE$NEED_BUILDX" != 000 ]; then NEED_DOCKER=1; fi
if [ "$NEED_ENGINE" = 0 ] && [ "$NEED_COMPOSE$NEED_BUILDX" != 00 ]; then LOCAL_PLUGINS=1; fi
printf 'Dependencies (0=ready, 1=missing/incompatible): Python=%s Go=%s Node/npm=%s Docker/Compose/Buildx=%s Git=%s\n' "$NEED_PY" "$NEED_GO" "$NEED_NODE" "$NEED_DOCKER" "$NEED_GIT"
printf 'Docker components: Engine/CLI=%s Compose=%s Buildx=%s\n' "$NEED_ENGINE" "$NEED_COMPOSE" "$NEED_BUILDX"
if [ "$CHECK" = 1 ]; then
    [ "$NEED_PY$NEED_GO$NEED_NODE$NEED_DOCKER$NEED_GIT" = 00000 ] || exit 1
    printf 'All dependency checks passed (Docker daemon access is checked only at runtime).\n'
    exit 0
fi
PACKAGES=''; PLATFORM_ERROR=''; DOCKER_CONFLICT=''; BUILD_PY=0; BUILD_GIT=0; FOCAL_DOCKER=0
if [ "$BOOTSTRAP" = 1 ]; then
    [ "$NEED_GIT" = 0 ] || PACKAGES="$PACKAGES git"
    # Parse only data, never execute os-release as shell code. Override is for fixtures.
    OS_RELEASE=${VULSCAN_OS_RELEASE:-/etc/os-release}
    os_id=$(sed -n 's/^ID=//p' "$OS_RELEASE" | tr -d '"')
    os_version=$(sed -n 's/^VERSION_ID=//p' "$OS_RELEASE" | tr -d '"')
    machine=$(uname -m)
    case "$machine" in x86_64) ARCH=amd64; NODE_ARCH=x64;; aarch64|arm64) ARCH=arm64; NODE_ARCH=arm64;; *) PLATFORM_ERROR="Unsupported architecture $machine; install dependencies manually.";; esac
    case "$os_id:$os_version" in
        ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) :;;
        *) PLATFORM_ERROR="Automatic bootstrap supports Ubuntu 20.04/22.04/24.04/26.04 only (found $os_id $os_version). On other systems, install Python >=3.11 with venv separately without changing system Python, plus Go >=1.26, Node 20 or >=22 and npm >=7; then run without --install-deps.";;
    esac
    printf 'Platform: %s %s / %s\n' "$os_id" "$os_version" "$machine"
    if [ "$DEPLOY" = 1 ]; then
        for pkg in ca-certificates curl build-essential pkg-config xz-utils; do
            package_installed "$pkg" || PACKAGES="$PACKAGES $pkg"
        done
    fi
    if [ "$NEED_GIT" = 1 ] && [ "$os_version" = 20.04 ]; then
        BUILD_GIT=1
        PACKAGES="$PACKAGES build-essential libcurl4-openssl-dev libexpat1-dev libssl-dev zlib1g-dev xz-utils perl"
    fi
    if [ "$NEED_PY" = 1 ]; then
        case "$os_version" in
            20.04|22.04) BUILD_PY=1; PACKAGES="$PACKAGES build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev liblzma-dev xz-utils";;
            *) PACKAGES="$PACKAGES python3 python3-venv python3-dev";;
        esac
    fi
    if [ "$NEED_GO" = 1 ] || [ "$NEED_NODE" = 1 ] || [ "$BUILD_PY" = 1 ] || [ "$BUILD_GIT" = 1 ] || { [ "$os_version" = 20.04 ] && [ "$NEED_ENGINE" = 1 ]; }; then
        PACKAGES="$PACKAGES ca-certificates"
        command -v curl >/dev/null 2>&1 || PACKAGES="$PACKAGES curl"
        command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is required before bootstrap'
    fi
    if [ "$NEED_ENGINE" = 1 ]; then
        # Never remove CE, Podman shims, containerd.io or an unmanaged Docker CLI.
        for pkg in docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin podman-docker; do
            if package_installed "$pkg"; then
                DOCKER_CONFLICT="Existing $pkg detected. Complete your existing Docker installation (Compose v2/Buildx) using its original provider; no packages were removed."
            fi
        done
        if command -v docker >/dev/null 2>&1 && ! package_installed docker.io; then
            DOCKER_CONFLICT='Existing non-Ubuntu/unmanaged Docker detected. Install missing Compose v2/Buildx with its original provider; refusing to replace it.'
        fi
        if [ "$os_version" = 20.04 ]; then
            FOCAL_DOCKER=1
            if command -v docker >/dev/null 2>&1; then DOCKER_CONFLICT='Existing incomplete Docker on Ubuntu 20.04: complete it using its original provider; refusing to replace or downgrade it.'; fi
        else
            PACKAGES="$PACKAGES docker.io"
            [ "$NEED_COMPOSE" = 0 ] || PACKAGES="$PACKAGES docker-compose-v2"
            [ "$NEED_BUILDX" = 0 ] || PACKAGES="$PACKAGES docker-buildx"
        fi
    fi
    if [ "$LOCAL_PLUGINS" = 1 ]; then
        command -v curl >/dev/null 2>&1 || fail 'curl is required for user-local Docker plugin downloads; install curl first.'
        command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is required for user-local Docker plugin downloads.'
        if [ -n "${DOCKER_CONFIG:-}" ]; then
            PLUGIN_DIR="$DOCKER_CONFIG/cli-plugins"
        else
            [ -n "${HOME:-}" ] || fail 'HOME or DOCKER_CONFIG is required for user-local Docker plugins.'
            PLUGIN_DIR="$HOME/.docker/cli-plugins"
        fi
        for plugin in compose buildx; do
            case "$plugin" in compose) needed=$NEED_COMPOSE;; buildx) needed=$NEED_BUILDX;; esac
            if [ "$needed" = 1 ] && { [ -e "$PLUGIN_DIR/docker-$plugin" ] || [ -L "$PLUGIN_DIR/docker-$plugin" ]; }; then
                fail "Existing $PLUGIN_DIR/docker-$plugin is not working. Inspect/move it aside manually; it will not be overwritten."
            fi
        done
        if package_installed docker.io && package_installed docker-ce; then
            printf 'Notice: both docker.io and docker-ce report installed; keeping Engine packages untouched and adding only missing user-local plugins.\n'
        fi
    fi
    printf '\nBootstrap plan:\n'
    [ -z "$PACKAGES" ] || printf '  sudo apt-get update; apt-get install --no-remove:%s\n  Uses configured APT repositories; ensure these are trusted Ubuntu repositories.\n' "$PACKAGES"
    [ "$BUILD_PY" = 0 ] || printf '  Build checksum-pinned Python 3.12.16 from python.org into .tools/python (make altinstall; system Python unchanged).\n'
    [ "$BUILD_GIT" = 0 ] || printf '  Build Git 2.56.x from kernel.org verified source into .tools/git using its supported NO_RUST build; system Git unchanged.\n'
    [ "$FOCAL_DOCKER" = 0 ] || printf '  WARNING: Docker no longer supports Ubuntu 20.04. Optional frozen official Focal packages: Engine/CLI 28.1.1, containerd 1.7.27, Compose 2.35.1, Buildx 0.23.0. No current security support; upgrade Ubuntu recommended. Requires --allow-unsupported-docker.\n'
    [ "$NEED_GO" = 0 ] || printf '  Download latest stable Go 1.26 patch from go.dev/dl metadata; verify SHA-256; install .tools/go.\n'
    [ "$NEED_NODE" = 0 ] || printf '  Download latest Node 22 LTS from nodejs.org; verify vendor SHA-256 manifest; install .tools/node (includes npm).\n'
    [ "$LOCAL_PLUGINS" = 0 ] || printf '  Add only missing Docker CLI plugins (Compose=%s Buildx=%s) to %s; verify official release SHA-256. Existing Engine and working plugins stay unchanged. No sudo/service changes for plugins.\n' "$NEED_COMPOSE" "$NEED_BUILDX" "$PLUGIN_DIR"
    [ "$NEED_ENGINE" = 0 ] || printf '  Docker package scripts may START/ENABLE Docker/containerd services (requires --start-docker).\n'
    [ "$START_DOCKER" = 0 ] || printf '  Start existing/local docker.service using systemctl (no explicit enable or daemon changes).\n'
    printf '  No system Python replacement, Docker group changes, daemon configuration or credential changes.\n'
    if [ "$DEPLOY" = 1 ]; then
        [ "$CREATE_SERVICE_USER" = 0 ] || printf '  Create non-login service account %s with home %s.\n' "$service_user" "$service_home"
        printf '  Deployment also enables official Ubuntu universe if required, validates all parsers and Docker build/run, and enables/restarts vulscan.service at http://127.0.0.1:8080.\n'
        printf '  Active scans block updates. The service runs as %s with the Docker supplementary group; no socket permissions are changed.\n' "$service_user"
    fi
fi
if [ "$DEPS_ONLY" = 0 ]; then printf 'Application plan: create .venv, pip install core, npm ci parser lock, build bin/vulscan-cli and launcher.\n'; fi
[ -z "$PLATFORM_ERROR" ] || fail "$PLATFORM_ERROR"
[ -z "$DOCKER_CONFLICT" ] || fail "$DOCKER_CONFLICT"
if [ "$BOOTSTRAP" = 1 ]; then
    for tool in python go node git; do
        case "$tool" in python) needed=$BUILD_PY;; go) needed=$NEED_GO;; node) needed=$NEED_NODE;; git) needed=$BUILD_GIT;; esac
        if [ "$needed" = 1 ] && [ "$tool" = python ] && [ -d "$ROOT/.tools/python" ] && [ ! -L "$ROOT/.tools/python" ] && { [ -f "$ROOT/.tools/python/.911vulscan-installing" ] || [ -f "$ROOT/.tools/python/bin/python3.12" ] || [ -d "$ROOT/.tools/python/lib/python3.12" ]; }; then
            printf '  Resume incomplete local Python installation; existing configuration and other files are retained.\n'
        elif [ "$needed" = 1 ] && { [ -e "$ROOT/.tools/$tool" ] || [ -L "$ROOT/.tools/$tool" ]; }; then
            fail "Existing .tools/$tool is incompatible; move it aside manually before retrying (not replaced automatically)."
        fi
    done
fi
[ "$DRY" = 0 ] || exit 0
if [ "$BOOTSTRAP" = 1 ]; then
    if [ "$FOCAL_DOCKER" = 1 ] && [ "$ALLOW_OLD_DOCKER" = 0 ]; then
        fail 'Docker on Ubuntu 20.04 is unsupported. Upgrade Ubuntu, prepare Docker independently, or explicitly accept frozen packages with --allow-unsupported-docker.'
    fi
    if [ "$NEED_ENGINE" = 1 ] && [ "$START_DOCKER" = 0 ]; then
        fail 'Installing Docker can start services. Review --dry-run, then explicitly add --start-docker to consent; or prepare Docker manually.'
    fi
    if [ "$YES" = 0 ]; then
        [ -t 0 ] || fail 'Noninteractive bootstrap requires --yes after reviewing --dry-run (Docker additionally requires --start-docker).'
        printf 'Apply this bootstrap plan? [y/N] '
        read -r answer
        case "$answer" in y|Y|yes|YES) :;; *) fail 'Cancelled; nothing was installed.';; esac
    fi
    if [ "$DEPLOY" = 1 ]; then
        command -v systemctl >/dev/null 2>&1 && privileged systemctl show-environment >/dev/null || fail '--deploy requires Ubuntu booted with systemd; use application-only installation in containers.'
        if [ "$CREATE_SERVICE_USER" = 1 ]; then
            privileged useradd --system --user-group --create-home --home-dir "$service_home" --shell /usr/sbin/nologin "$service_user"
            service_uid=$(id -u "$service_user")
        fi
        service_run test -r "$ROOT/libs/vulscan-core/requirements.txt" || fail 'Service account cannot read this installation. Extract it into a traversable directory such as /opt/911VulScan; do not loosen private home-directory permissions.'
        service_run mkdir -p "$DOCKER_CONFIG"
        service_run test -r "$DOCKER_CONFIG" && service_run test -x "$DOCKER_CONFIG" || fail 'DOCKER_CONFIG is not accessible to the service account.'
        if [ -f "$DOCKER_CONFIG/config.json" ]; then
            service_run test -r "$DOCKER_CONFIG/config.json" || fail 'Docker config.json is not readable by the service account; existing credentials and permissions were not changed.'
        fi
        if [ -n "$previous_user" ] && [ "$previous_user" != "$service_user" ]; then
            [ ! -e "$previous_home/.vulscan" ] || fail "Existing scan data belongs to $previous_user at $previous_home/.vulscan. Stop the old service and migrate this directory to $service_home with ownership $service_user:$service_group before changing the service account; no data was moved or removed."
        fi
        if [ -e "$service_home/.vulscan" ]; then
            service_run test -r "$service_home/.vulscan" && service_run test -w "$service_home/.vulscan" && service_run test -x "$service_home/.vulscan" || fail 'Existing scan data is not accessible to the service account; ownership and data were not changed.'
        fi
        stop_service=0
        if privileged systemctl is-active --quiet vulscan; then
            old_pid=$(privileged systemctl show --property=MainPID --value vulscan)
            old_uid=$(id -u "${previous_user:-$service_user}")
            privileged python3 "$ROOT/scripts/check-deployment.py" --root "$ROOT" --idle-url http://127.0.0.1:8080 --service-pid "$old_pid" --service-uid "$old_uid" || fail 'Update stopped before changing application files; wait for active scans or inspect the existing service.'
            stop_service=1
        elif [ -f "$unit" ]; then
            state=$(privileged systemctl show --property=ActiveState --value vulscan)
            case "$state" in
                inactive|failed) stop_service=1;;
                *) fail 'Existing service is starting/stopping or has an unknown state; wait for it to settle before deploying. Application files were not changed.';;
            esac
        fi
        if [ "$stop_service" = 1 ]; then
            printf 'Stopping the old service before updating application dependencies; scan results and settings are retained.\n'
            privileged systemctl stop vulscan || fail 'Old service did not stop cleanly; application files were not changed. Inspect journalctl -u vulscan.'
            state=$(privileged systemctl show --property=ActiveState --value vulscan)
            [ "$state" = inactive ] || fail 'Old service is not inactive; application files were not changed.'
        fi
    fi
    if [ -n "$PACKAGES" ]; then
        privileged apt-get update || fail 'APT update failed; check network and trusted Ubuntu repository configuration.'
        for pkg in $PACKAGES; do
            candidate=$(apt-cache policy "$pkg" | awk '/Candidate:/ {print $2}')
            if [ "$DEPLOY" = 1 ] && { [ -z "$candidate" ] || [ "$candidate" = '(none)' ]; }; then
                privileged env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-remove --no-install-recommends software-properties-common || fail 'Cannot prepare official Ubuntu universe repository.'
                privileged add-apt-repository --yes universe || fail 'Cannot enable official Ubuntu universe repository.'
                privileged apt-get update || fail 'APT update failed after enabling universe.'
                candidate=$(apt-cache policy "$pkg" | awk '/Candidate:/ {print $2}')
            fi
            [ -n "$candidate" ] && [ "$candidate" != '(none)' ] || fail "No APT candidate for $pkg. Enable the appropriate official Ubuntu universe/updates repositories yourself, then retry."
        done
        # --no-remove fails rather than silently removing conflicting packages.
        # shellcheck disable=SC2086
        privileged env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install --yes --no-remove --no-install-recommends $PACKAGES || fail 'APT install failed; check package availability/conflicts. No fallback repositories or PPAs are added.'
        if [ "$NEED_PY" = 1 ] && [ "$BUILD_PY" = 0 ]; then PYTHON=/usr/bin/python3; fi
    fi
    if [ "$NEED_GO" = 1 ] || [ "$NEED_NODE" = 1 ] || [ "$BUILD_PY" = 1 ] || [ "$BUILD_GIT" = 1 ] || [ "$FOCAL_DOCKER" = 1 ] || [ "$LOCAL_PLUGINS" = 1 ]; then
        mkdir -p "$ROOT/.tools"
        TMP=$(mktemp -d "$ROOT/.tools/.bootstrap.XXXXXXXX")
        trap 'rm -rf -- "$TMP"; if [ -n "${PLUGIN_TMP:-}" ]; then service_run rm -f -- "$PLUGIN_TMP"; fi' EXIT
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fetch() {
            fetch_url=$1; fetch_output=$2
            for fetch_try in 1 2 3; do
                set --
                case "$fetch_url" in
                    *.tar.gz|*.tar.xz|*.deb)
                        if [ "$fetch_try" -gt 1 ] && [ -s "$fetch_output" ]; then set -- --continue-at -; fi;;
                esac
                fetch_code=0
                fetch_http=$(curl "$@" --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 600 --write-out '%{http_code}' --output "$fetch_output" "$fetch_url") || fetch_code=$?
                case "$fetch_code:$fetch_http" in
                    0:*) return 0;;
                    6:*|7:*|18:*|28:*|52:*|55:*|56:*|92:*|22:408|22:429|22:500|22:502|22:503|22:504) :;;
                    *) fail "Download failed: $fetch_url; curl=$fetch_code HTTP=$fetch_http; no alternate mirror used.";;
                esac
                [ "$fetch_try" -lt 3 ] || fail "Download failed after 3 attempts: $fetch_url; no alternate mirror used."
                printf 'Transient download error; retry %s/3: %s\n' "$fetch_try" "$fetch_url" >&2
                sleep "$fetch_try"
            done
        }
        if [ "$BUILD_PY" = 1 ]; then
            [ ! -L "$ROOT/.tools/python" ] || fail 'Refusing to install Python through a symlink.'
            mkdir -p "$ROOT/.tools/python"
            : > "$ROOT/.tools/python/.911vulscan-installing"
            file=Python-3.12.16.tar.xz
            fetch "https://www.python.org/ftp/python/3.12.16/$file" "$TMP/$file"
            (cd "$TMP"; printf '%s  %s\n' b5796915dc45ff745cfb4e990a7e7c93d6f546328a102ce31448d69ebc37575c "$file" | sha256sum --check --status) || fail 'Python checksum mismatch; source not extracted.'
            tar -xJf "$TMP/$file" -C "$TMP"
            (cd "$TMP/Python-3.12.16" && ./configure --prefix="$ROOT/.tools/python" --with-ensurepip=install && make -j2 && make altinstall) || fail 'Python source build failed. No system Python was changed; review build dependencies.'
            PYTHON="$ROOT/.tools/python/bin/python3.12"
            "$PYTHON" -c 'import ssl, sqlite3, bz2, lzma, ctypes, readline, venv, ensurepip' || fail 'Built Python lacks required standard-library modules.'
            "$PYTHON" -m venv "$TMP/python-venv-check" && "$TMP/python-venv-check/bin/python" -m pip --version || fail 'Built Python could not create a working venv with pip.'
            rm -f "$ROOT/.tools/python/.911vulscan-installing"
        fi
        python_ok || fail 'Python >=3.11 with venv/ensurepip is still unavailable; check python3-venv or set PYTHON.'
        if [ "$BUILD_GIT" = 1 ]; then
            fetch 'https://www.kernel.org/pub/software/scm/git/sha256sums.asc' "$TMP/git-checksums"
            "$PYTHON" - "$TMP/git-checksums" > "$TMP/git-selection" <<'PYGIT'
import re, sys
from pathlib import Path
versions = []
for line in Path(sys.argv[1]).read_text().splitlines():
    m = re.fullmatch(r'([0-9a-f]{64})\s+(git-(2\.(\d+)\.(\d+))\.tar\.xz)', line)
    # Keep a tested build contract; a new Git minor can add toolchain dependencies.
    if m and int(m[4]) == 56:
        versions.append(((int(m[4]), int(m[5])), m[2], m[1]))
if not versions:
    sys.exit('No stable Git 2.56.x archive in official kernel.org metadata.')
_, filename, checksum = max(versions)
print(filename); print(checksum)
PYGIT
            file=$(sed -n '1p' "$TMP/git-selection"); sha=$(sed -n '2p' "$TMP/git-selection")
            fetch "https://www.kernel.org/pub/software/scm/git/$file" "$TMP/$file"
            (cd "$TMP"; printf '%s  %s\n' "$sha" "$file" | sha256sum --check --status) || fail 'Git checksum mismatch; source not extracted.'
            tar -xJf "$TMP/$file" -C "$TMP"
            git_source="$TMP/${file%.tar.xz}"
            (cd "$git_source" && make -j2 prefix="$ROOT/.tools/git" NO_TCLTK=YesPlease NO_GETTEXT=YesPlease NO_RUST=YesPlease all && make prefix="$ROOT/.tools/git" NO_TCLTK=YesPlease NO_GETTEXT=YesPlease NO_RUST=YesPlease install) || fail 'Git source build failed; system Git was not changed.'
        fi
        if [ "$FOCAL_DOCKER" = 1 ]; then
            # Official retained distribution metadata provides exact .deb SHA-256.
            # No APT repository, trust key, daemon config, or package hold is changed.
            fetch "https://download.docker.com/linux/ubuntu/dists/focal/stable/binary-$ARCH/Packages.gz" "$TMP/docker-Packages.gz"
            "$PYTHON" - "$TMP/docker-Packages.gz" "$ARCH" "$NEED_COMPOSE" "$NEED_BUILDX" > "$TMP/docker-selection" <<'PYDOCKER'
import gzip, re, sys
pins = {'docker-ce': '28.1.1', 'docker-ce-cli': '28.1.1', 'containerd.io': '1.7.27'}
if sys.argv[3] == '1': pins['docker-compose-plugin'] = '2.35.1'
if sys.argv[4] == '1': pins['docker-buildx-plugin'] = '0.23.0'
found = {}
for block in gzip.open(sys.argv[1], 'rt').read().split('\n\n'):
    fields = dict(line.split(': ', 1) for line in block.splitlines() if ': ' in line and not line.startswith(' '))
    name = fields.get('Package')
    if name not in pins or fields.get('Architecture') != sys.argv[2]: continue
    version = fields.get('Version', '').split(':')[-1]
    if not re.match(re.escape(pins[name]) + r'(?=[-~+]|$)', version): continue
    path, sha = fields.get('Filename', ''), fields.get('SHA256', '')
    if not re.fullmatch(r'dists/focal/pool/stable/' + sys.argv[2] + r'/[A-Za-z0-9_.+%~:-]+\.deb', path) or not re.fullmatch('[0-9a-f]{64}', sha):
        sys.exit('Invalid filename/checksum in official Docker metadata.')
    if not path.rsplit('/', 1)[-1].startswith(name + '_'):
        sys.exit('Unexpected package filename in official Docker metadata.')
    found[name] = (path, sha)
if set(found) != set(pins): sys.exit('Pinned unsupported Focal Docker packages unavailable; upgrade Ubuntu or install Docker manually.')
for name in pins: print(*found[name])
PYDOCKER
            mkdir "$TMP/debs"
            while read -r path sha; do
                file=${path##*/}
                fetch "https://download.docker.com/linux/ubuntu/$path" "$TMP/debs/$file"
                (cd "$TMP/debs"; printf '%s  %s\n' "$sha" "$file" | sha256sum --check --status) || fail 'Docker package checksum mismatch; package not installed.'
            done < "$TMP/docker-selection"
            privileged env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install --yes --no-remove --no-install-recommends "$TMP"/debs/*.deb || fail 'Frozen Docker package installation failed; no alternate repositories were added.'
        fi
        if [ "$LOCAL_PLUGINS" = 1 ]; then
            # Official standalone CLI plugins; do not touch engine packages or config.json.
            # Buildx documents Engine >=19.03; CLI validation below does not
            # claim daemon/build compatibility. Plugin updates are explicit.
            for plugin in compose buildx; do
                case "$plugin" in
                    compose)
                        [ "$NEED_COMPOSE" = 1 ] || continue
                        case "$ARCH" in amd64) plugin_arch=x86_64;; arm64) plugin_arch=aarch64;; esac
                        file="docker-compose-linux-$plugin_arch"
                        base='https://github.com/docker/compose/releases/download/v5.5.1'
                        manifest=checksums.txt;;
                    buildx)
                        [ "$NEED_BUILDX" = 1 ] || continue
                        file="buildx-v0.38.1.linux-$ARCH"
                        base='https://github.com/docker/buildx/releases/download/v0.38.1'
                        manifest=checksums.txt;;
                esac
                fetch "$base/$manifest" "$TMP/$plugin-checksums.txt"
                sha=$(awk -v name="$file" '$2 == name || $2 == "*" name {print $1}' "$TMP/$plugin-checksums.txt")
                [ "${#sha}" = 64 ] && printf '%s\n' "$sha" | grep -Eq '^[0-9a-f]{64}$' || fail "Missing or invalid $plugin SHA-256 in official release manifest."
                fetch "$base/$file" "$TMP/$file"
                (cd "$TMP"; printf '%s  %s\n' "$sha" "$file" | sha256sum --check --status) || fail "$plugin checksum mismatch; plugin not installed."
                service_run mkdir -p "$PLUGIN_DIR"
                # Stage in the same filesystem; hard-link publication refuses replacement
                # even if another process created the destination after our preflight.
                PLUGIN_TMP=$(service_run mktemp "$PLUGIN_DIR/.$plugin.XXXXXXXX")
                # The bootstrap directory is private to the installer; publish
                # only the verified executable to the service-owned temporary.
                service_run tee "$PLUGIN_TMP" < "$TMP/$file" >/dev/null
                service_run chmod 755 "$PLUGIN_TMP"
                if ! service_run ln -T "$PLUGIN_TMP" "$PLUGIN_DIR/docker-$plugin"; then
                    service_run rm -f "$PLUGIN_TMP"
                    fail "Could not install $PLUGIN_DIR/docker-$plugin without replacement."
                fi
                service_run rm -f "$PLUGIN_TMP"
                docker "$plugin" version >/dev/null 2>&1 || fail "Installed plugin $PLUGIN_DIR/docker-$plugin failed Docker CLI validation; inspect its platform compatibility and Docker plugin discovery. No Engine or working plugin was replaced."
            done
        fi
        if [ "$NEED_GO" = 1 ]; then
            [ ! -e "$ROOT/.tools/go" ] || fail 'Existing .tools/go is incompatible; move it aside manually before retrying (not replaced automatically).'
            fetch 'https://go.dev/dl/?mode=json' "$TMP/go.json"
            "$PYTHON" - "$TMP/go.json" "$ARCH" > "$TMP/go-selection" <<'PY'
import json, re, sys
releases = json.load(open(sys.argv[1]))
candidates = []
for r in releases:
    if r.get('stable') and re.fullmatch(r'go1\.26\.\d+', r.get('version', '')):
        for f in r['files']:
            if f.get('os') == 'linux' and f.get('arch') == sys.argv[2] and f.get('kind') == 'archive':
                name = f['filename']; sha = f['sha256']
                if name == r['version'] + '.linux-' + sys.argv[2] + '.tar.gz' and re.fullmatch('[0-9a-f]{64}', sha):
                    candidates.append((int(r['version'].split('.')[-1]), name, sha))
if not candidates:
    sys.exit('No stable Go 1.26 archive in official metadata; update installer or install Go >=1.26 manually.')
_, name, sha = max(candidates)
print(name); print(sha)
PY
            file=$(sed -n '1p' "$TMP/go-selection"); sha=$(sed -n '2p' "$TMP/go-selection")
            fetch "https://go.dev/dl/$file" "$TMP/$file"
            (cd "$TMP"; printf '%s  %s\n' "$sha" "$file" | sha256sum --check --status) || fail 'Go checksum mismatch; archive not extracted.'
            tar -xzf "$TMP/$file" -C "$TMP"
            mv "$TMP/go" "$ROOT/.tools/go"
        fi
        if [ "$NEED_NODE" = 1 ]; then
            [ ! -e "$ROOT/.tools/node" ] || fail 'Existing .tools/node is incompatible; move it aside manually before retrying (not replaced automatically).'
            fetch 'https://nodejs.org/dist/index.json' "$TMP/node.json"
            node_version=$("$PYTHON" - "$TMP/node.json" <<'PY'
import json, re, sys
versions = [r['version'] for r in json.load(open(sys.argv[1])) if r.get('lts') and re.fullmatch(r'v22\.\d+\.\d+', r.get('version', ''))]
if not versions:
    sys.exit('No Node 22 LTS in official metadata; install a compatible Node/npm manually.')
print(max(versions, key=lambda v: tuple(map(int, v[1:].split('.')))))
PY
            )
            file="node-$node_version-linux-$NODE_ARCH.tar.gz"
            fetch "https://nodejs.org/dist/$node_version/SHASUMS256.txt" "$TMP/SHASUMS256.txt"
            sha=$(awk -v name="$file" '$2 == name {print $1}' "$TMP/SHASUMS256.txt")
            [ "${#sha}" = 64 ] && printf '%s\n' "$sha" | grep -Eq '^[0-9a-f]{64}$' || fail 'Missing or invalid Node SHA-256 in vendor manifest.'
            fetch "https://nodejs.org/dist/$node_version/$file" "$TMP/$file"
            (cd "$TMP"; printf '%s  %s\n' "$sha" "$file" | sha256sum --check --status) || fail 'Node checksum mismatch; archive not extracted.'
            mkdir "$TMP/node"
            tar -xzf "$TMP/$file" --strip-components=1 -C "$TMP/node"
            mv "$TMP/node" "$ROOT/.tools/node"
        fi
        rm -rf -- "$TMP"
        trap - EXIT HUP INT TERM
    fi
    python_ok || fail 'Python >=3.11 with venv/ensurepip remains unavailable.'
    hash -r
    go_ok && node_ok && npm_ok && git_ok && docker_ok || fail 'Post-install dependency validation failed; review command versions and original package provider.'
    if [ "$START_DOCKER" = 1 ]; then
        command -v systemctl >/dev/null 2>&1 || fail 'systemctl unavailable; start Docker manually for this environment.'
        privileged systemctl start docker || fail 'Docker service could not start; inspect systemctl status docker. No daemon configuration was changed.'
    fi
    printf 'Dependencies ready. Docker access may require administrator-approved setup; no user was added to the root-equivalent docker group.\n'
fi
git_ok || fail 'Git >=2.32 is required to scan remote repositories; use --install-deps or install Git manually.'
[ "$DEPS_ONLY" = 0 ] || exit 0
python_ok || fail 'Python >=3.11 with venv/ensurepip required; use --install-deps or set PYTHON.'
go_ok || fail 'Go >=1.26 required; use --install-deps or install Go manually.'
node_ok && npm_ok || fail 'Node 20 or >=22 and npm >=7 required by parser lock; use --install-deps.'
if [ "$DEPLOY" = 1 ]; then
    for directory in .venv bin; do
        [ ! -L "$ROOT/$directory" ] || fail "Refusing to change ownership through $directory symlink."
        privileged install -d -o "$service_user" -g "$service_group" -m 0755 "$ROOT/$directory"
        # These contain only managed application files, never ~/.vulscan data
        # or the Docker credential directory. Repair earlier sudo installations.
        privileged chown -hR "$service_user:$service_group" "$ROOT/$directory"
    done
fi
service_run "$PYTHON" -m venv "$ROOT/.venv"
# Ubuntu's ensurepip can predate resumable downloads. Upgrade only this venv;
# bound transient network retries instead of retrying the entire installation.
service_run "$ROOT/.venv/bin/python" -m pip install --timeout 60 --retries 3 --upgrade 'pip>=25.3'
service_run "$ROOT/.venv/bin/python" -m pip install --timeout 60 --retries 3 --resume-retries 3 -r "$ROOT/libs/vulscan-core/requirements.txt"
service_run "$ROOT/.venv/bin/python" -m pip install --timeout 60 --retries 3 --resume-retries 3 --no-deps "$ROOT/libs/vulscan-core"
service_run "$ROOT/.venv/bin/python" -m pip check
JS_PARSER_DIR=$("$ROOT/.venv/bin/python" -I -c 'from pathlib import Path; import core; print(Path(core.__file__).resolve().parent.parent / "parsers" / "javascript")')
[ -n "$JS_PARSER_DIR" ] && [ -f "$JS_PARSER_DIR/package-lock.json" ] || fail 'Installed JavaScript parser lockfile is missing.'
(cd "$JS_PARSER_DIR" && service_run npm ci --engine-strict --no-audit --no-fund)
mkdir -p "$ROOT/bin"
(cd "$ROOT/apps/vulscan-cli" && service_run env GOTOOLCHAIN=local go build -buildvcs=false -trimpath -o "$ROOT/bin/vulscan-cli" ./main.go)
cat > "$ROOT/bin/vulscan" <<'EOF'
#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PATH="$ROOT/.tools/git/bin:$ROOT/.tools/go/bin:$ROOT/.tools/node/bin:$PATH"
export VULSCAN_PYTHON="$ROOT/.venv/bin/python"
export VULSCAN_PORTABLE_ROOT="$ROOT"
exec "$ROOT/bin/vulscan-cli" "$@"
EOF
chmod 755 "$ROOT/bin/vulscan"
printf '\nInstalled: %s/bin/vulscan\n' "$ROOT"
if [ "$DEPLOY" = 1 ]; then
    service_run "$ROOT/.venv/bin/python" "$ROOT/scripts/check-deployment.py" --root "$ROOT"
    unit_tmp=$(mktemp "$ROOT/.vulscan-service.XXXXXXXX")
    trap 'rm -f -- "$unit_tmp"' EXIT
    "$ROOT/.venv/bin/python" - "$ROOT" "$service_user" "$service_home" "$DOCKER_CONFIG" > "$unit_tmp" <<'PYUNIT'
import sys
root, user, home, docker_config = sys.argv[1:]
def q(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'
def command(*args):
    return ' '.join(q(arg).replace('$', '$$') for arg in args)
print('# Managed by 911VulScan installer\n[Unit]\nDescription=911VulScan security scanning workbench\nAfter=network-online.target docker.service\nWants=network-online.target\nRequires=docker.service\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n[Service]\nType=simple')
print('User=' + user + '\nSupplementaryGroups=docker')
print('WorkingDirectory=' + root.replace('%', '%%'))
print('Environment=' + q('HOME=' + home))
print('Environment=' + q('DOCKER_CONFIG=' + docker_config))
print('Environment=' + q('PATH=' + root + '/.tools/git/bin:' + root + '/.tools/go/bin:' + root + '/.tools/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'))
print('ExecStartPre=' + command(root + '/.venv/bin/python', root + '/scripts/check-deployment.py', '--root', root, '--docker'))
print('ExecStart=' + command(root + '/bin/vulscan', 'serve', '--addr', '127.0.0.1:8080'))
print('Restart=on-failure\nRestartSec=3\nTimeoutStartSec=300\nTimeoutStopSec=120\nKillMode=mixed\nUMask=0027\n\n[Install]\nWantedBy=multi-user.target')
PYUNIT
    privileged install -d -m 0755 "$SYSTEMD_DIR"
    privileged install -m 0644 "$unit_tmp" "$unit"
    rm -f "$unit_tmp"; trap - EXIT
    privileged systemctl daemon-reload
    privileged systemctl enable --now docker
    privileged systemctl enable vulscan
    privileged systemctl restart vulscan || fail 'vulscan.service startup failed; inspect journalctl -u vulscan -n 80.'
    service_pid=$(privileged systemctl show --property=MainPID --value vulscan)
    privileged "$ROOT/.venv/bin/python" "$ROOT/scripts/check-deployment.py" --root "$ROOT" --url http://127.0.0.1:8080 --service-pid "$service_pid" --service-uid "$service_uid" || fail 'Service startup/version check failed; inspect journalctl -u vulscan -n 80.'
    privileged systemctl is-active --quiet vulscan || fail 'vulscan.service is not running; inspect journalctl -u vulscan -n 80.'
    printf '\n911VulScan ready: http://127.0.0.1:8080\nService: systemctl status vulscan\nLogs: journalctl -u vulscan -f\nConfigure a model API key in the web form before scanning.\n'
fi
