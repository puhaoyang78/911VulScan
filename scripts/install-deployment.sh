#!/bin/sh
# Run from any directory; keep this installation tree together.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: scripts/install-deployment.sh [options]
  (no options)       Install the application using existing dependencies, no sudo.
  --install-deps     Bootstrap missing dependencies on Ubuntu 20.04/22.04/24.04/26.04.
  --deps-only        With --install-deps, skip application installation.
  --check            Read-only dependency check; exit 1 if anything is missing.
  --dry-run          Read-only dependency/application plan; no downloads or sudo.
  --yes             Approve the displayed bootstrap plan noninteractively.
  --start-docker    Also consent to installing/starting local Docker services.
  --allow-unsupported-docker  Opt into frozen Docker packages on Ubuntu 20.04.
  --help            Show this help.
Python >=3.11 (venv/ensurepip), Go >=1.26, Node 20 or >=22, npm >=7 required.
Docker Engine, Compose v2 and Buildx are checked separately; Docker is optional
for application installation. --install-deps includes missing Docker components.
Docker package scripts may start/enable services; fresh installation therefore
requires --start-docker as well as plan approval. No group/daemon/credential edits.
EOF
}
BOOTSTRAP=0; DEPS_ONLY=0; CHECK=0; DRY=0; YES=0; START_DOCKER=0; ALLOW_OLD_DOCKER=0
for arg in "$@"; do
    case "$arg" in
        --install-deps) BOOTSTRAP=1;; --deps-only) DEPS_ONLY=1;;
        --check) CHECK=1;; --dry-run) DRY=1;; --yes) YES=1;;
        --allow-unsupported-docker) ALLOW_OLD_DOCKER=1;;
        --start-docker) START_DOCKER=1;; --help|-h) usage; exit 0;;
        *) fail "Unknown option: $arg (see --help)";;
    esac
done
[ "$DEPS_ONLY" = 0 ] || [ "$BOOTSTRAP" = 1 ] || fail '--deps-only requires --install-deps'
[ "$START_DOCKER" = 0 ] || [ "$BOOTSTRAP" = 1 ] || fail '--start-docker requires --install-deps'
[ "$YES" = 0 ] || [ "$BOOTSTRAP" = 1 ] || fail '--yes requires --install-deps'
[ "$ALLOW_OLD_DOCKER" = 0 ] || [ "$BOOTSTRAP" = 1 ] || fail '--allow-unsupported-docker requires --install-deps'
[ "$CHECK" = 0 ] || [ "$DRY" = 0 ] || fail 'Choose --check or --dry-run, not both'
# App-local tools never replace /usr/bin or /usr/local binaries.
PATH="$ROOT/.tools/go/bin:$ROOT/.tools/node/bin:$PATH"
export PATH
PYTHON=${PYTHON:-python3}
if [ -x "$ROOT/.tools/python/bin/python3.12" ] && [ "$PYTHON" = python3 ]; then PYTHON="$ROOT/.tools/python/bin/python3.12"; fi
version_at_least() {
    printf '%s\n' "$1" | awk -F. -v maj="$2" -v min="$3" '
      /^[0-9]+\.[0-9]+(\.[0-9]+)?$/ {exit !(($1>maj)||($1==maj && $2>=min))}
      !/^[0-9]+\.[0-9]+(\.[0-9]+)?$/ {exit 1}'
}
python_ok() { "$PYTHON" -c 'import sys, venv, ensurepip; sys.exit(sys.version_info < (3,11))' >/dev/null 2>&1; }
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
docker_ok() {
    dockerd --version >/dev/null 2>&1 && docker --version >/dev/null 2>&1 &&
    docker compose version --short 2>/dev/null | grep -Eq '^v?[2-9][0-9]*\.' &&
    docker buildx version >/dev/null 2>&1
}
NEED_PY=0; NEED_GO=0; NEED_NODE=0; NEED_DOCKER=0
python_ok || NEED_PY=1
go_ok || NEED_GO=1
if ! node_ok || ! npm_ok; then NEED_NODE=1; fi
docker_ok || NEED_DOCKER=1
printf 'Dependencies (0=ready, 1=missing/incompatible): Python=%s Go=%s Node/npm=%s Docker/Compose/Buildx=%s\n' "$NEED_PY" "$NEED_GO" "$NEED_NODE" "$NEED_DOCKER"
if [ "$CHECK" = 1 ]; then
    [ "$NEED_PY$NEED_GO$NEED_NODE$NEED_DOCKER" = 0000 ] || exit 1
    printf 'All dependency checks passed (Docker daemon access is checked only at runtime).\n'
    exit 0
fi
PACKAGES=''; PLATFORM_ERROR=''; DOCKER_CONFLICT=''; BUILD_PY=0; FOCAL_DOCKER=0
if [ "$BOOTSTRAP" = 1 ]; then
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
    if [ "$NEED_PY" = 1 ]; then
        case "$os_version" in
            20.04|22.04) BUILD_PY=1; PACKAGES="$PACKAGES build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev liblzma-dev xz-utils";;
            *) PACKAGES="$PACKAGES python3 python3-venv";;
        esac
    fi
    if [ "$NEED_GO" = 1 ] || [ "$NEED_NODE" = 1 ] || [ "$BUILD_PY" = 1 ] || { [ "$os_version" = 20.04 ] && [ "$NEED_DOCKER" = 1 ]; }; then
        PACKAGES="$PACKAGES ca-certificates"
        command -v curl >/dev/null 2>&1 || PACKAGES="$PACKAGES curl"
        command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is required before bootstrap'
    fi
    if [ "$NEED_DOCKER" = 1 ]; then
        # Never remove CE, Podman shims, containerd.io or an unmanaged Docker CLI.
        for pkg in docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin podman-docker; do
            if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q '^install ok installed$'; then
                DOCKER_CONFLICT="Existing $pkg detected. Complete your existing Docker installation (Compose v2/Buildx) using its original provider; no packages were removed."
            fi
        done
        if command -v docker >/dev/null 2>&1 && ! dpkg-query -W -f='${Status}' docker.io 2>/dev/null | grep -q '^install ok installed$'; then
            DOCKER_CONFLICT='Existing non-Ubuntu/unmanaged Docker detected. Install missing Compose v2/Buildx with its original provider; refusing to replace it.'
        fi
        if [ "$os_version" = 20.04 ]; then
            FOCAL_DOCKER=1
            if command -v docker >/dev/null 2>&1; then DOCKER_CONFLICT='Existing incomplete Docker on Ubuntu 20.04: complete it using its original provider; refusing to replace or downgrade it.'; fi
        else
            PACKAGES="$PACKAGES docker.io docker-compose-v2 docker-buildx"
        fi
    fi
    printf '\nBootstrap plan:\n'
    [ -z "$PACKAGES" ] || printf '  sudo apt-get update; apt-get install --no-remove:%s\n  Uses configured APT repositories; ensure these are trusted Ubuntu repositories.\n' "$PACKAGES"
    [ "$BUILD_PY" = 0 ] || printf '  Build checksum-pinned Python 3.12.15 from python.org into .tools/python (make altinstall; system Python unchanged).\n'
    [ "$FOCAL_DOCKER" = 0 ] || printf '  WARNING: Docker no longer supports Ubuntu 20.04. Optional frozen official Focal packages: Engine/CLI 28.1.1, containerd 1.7.27, Compose 2.35.1, Buildx 0.23.0. No current security support; upgrade Ubuntu recommended. Requires --allow-unsupported-docker.\n'
    [ "$NEED_GO" = 0 ] || printf '  Download latest stable Go 1.26 patch from go.dev/dl metadata; verify SHA-256; install .tools/go.\n'
    [ "$NEED_NODE" = 0 ] || printf '  Download latest Node 22 LTS from nodejs.org; verify vendor SHA-256 manifest; install .tools/node (includes npm).\n'
    [ "$NEED_DOCKER" = 0 ] || printf '  Docker package scripts may START/ENABLE Docker/containerd services (requires --start-docker).\n'
    [ "$START_DOCKER" = 0 ] || printf '  Start existing/local docker.service using systemctl (no explicit enable or daemon changes).\n'
    printf '  No system Python replacement, Docker group changes, daemon configuration or credential changes.\n'
fi
if [ "$DEPS_ONLY" = 0 ]; then printf 'Application plan: create .venv, pip install core, npm ci parser lock, build bin/vulscan-cli and launcher.\n'; fi
[ -z "$PLATFORM_ERROR" ] || fail "$PLATFORM_ERROR"
[ -z "$DOCKER_CONFLICT" ] || fail "$DOCKER_CONFLICT"
if [ "$BOOTSTRAP" = 1 ]; then
    for tool in python go node; do
        case "$tool" in python) needed=$BUILD_PY;; go) needed=$NEED_GO;; node) needed=$NEED_NODE;; esac
        if [ "$needed" = 1 ] && { [ -e "$ROOT/.tools/$tool" ] || [ -L "$ROOT/.tools/$tool" ]; }; then
            fail "Existing .tools/$tool is incompatible; move it aside manually before retrying (not replaced automatically)."
        fi
    done
fi
[ "$DRY" = 0 ] || exit 0
if [ "$BOOTSTRAP" = 1 ]; then
    if [ "$FOCAL_DOCKER" = 1 ] && [ "$ALLOW_OLD_DOCKER" = 0 ]; then
        fail 'Docker on Ubuntu 20.04 is unsupported. Upgrade Ubuntu, prepare Docker independently, or explicitly accept frozen packages with --allow-unsupported-docker.'
    fi
    if [ "$NEED_DOCKER" = 1 ] && [ "$START_DOCKER" = 0 ]; then
        fail 'Installing Docker can start services. Review --dry-run, then explicitly add --start-docker to consent; or prepare Docker manually.'
    fi
    if [ "$YES" = 0 ]; then
        [ -t 0 ] || fail 'Noninteractive bootstrap requires --yes after reviewing --dry-run (Docker additionally requires --start-docker).'
        printf 'Apply this bootstrap plan? [y/N] '
        read -r answer
        case "$answer" in y|Y|yes|YES) :;; *) fail 'Cancelled; nothing was installed.';; esac
    fi
    privileged() {
        if [ "$(id -u)" = 0 ]; then "$@"; else sudo -- "$@"; fi
    }
    if [ -n "$PACKAGES" ]; then
        privileged apt-get update || fail 'APT update failed; check network and trusted Ubuntu repository configuration.'
        for pkg in $PACKAGES; do
            candidate=$(apt-cache policy "$pkg" | awk '/Candidate:/ {print $2}')
            [ -n "$candidate" ] && [ "$candidate" != '(none)' ] || fail "No APT candidate for $pkg. Enable the appropriate official Ubuntu universe/updates repositories yourself, then retry."
        done
        # --no-remove fails rather than silently removing conflicting packages.
        # shellcheck disable=SC2086
        privileged apt-get install --yes --no-remove --no-install-recommends $PACKAGES || fail 'APT install failed; check package availability/conflicts. No fallback repositories or PPAs are added.'
        if [ "$NEED_PY" = 1 ] && [ "$BUILD_PY" = 0 ]; then PYTHON=/usr/bin/python3; fi
    fi
    if [ "$NEED_GO" = 1 ] || [ "$NEED_NODE" = 1 ] || [ "$BUILD_PY" = 1 ] || [ "$FOCAL_DOCKER" = 1 ]; then
        mkdir -p "$ROOT/.tools"
        TMP=$(mktemp -d "$ROOT/.tools/.bootstrap.XXXXXXXX")
        trap 'rm -rf -- "$TMP"' EXIT
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fetch() { curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 600 --output "$2" "$1" || fail "Download failed: $1; no alternate mirror used."; }
        if [ "$BUILD_PY" = 1 ]; then
            [ ! -e "$ROOT/.tools/python" ] || fail 'Existing .tools/python is incompatible; move it aside manually before retrying.'
            file=Python-3.12.15.tar.xz
            fetch "https://www.python.org/ftp/python/3.12.15/$file" "$TMP/$file"
            (cd "$TMP"; printf '%s  %s\n' c2c4321961fab0fb999d66e0cecf521c2ab3994c7992873ea99e306c1094fd5a "$file" | sha256sum --check --status) || fail 'Python checksum mismatch; source not extracted.'
            tar -xJf "$TMP/$file" -C "$TMP"
            (cd "$TMP/Python-3.12.15" && ./configure --prefix="$ROOT/.tools/python" --with-ensurepip=install && make -j2 && make altinstall) || fail 'Python source build failed. No system Python was changed; review build dependencies.'
            PYTHON="$ROOT/.tools/python/bin/python3.12"
            "$PYTHON" -c 'import ssl, sqlite3, bz2, lzma, ctypes, readline, venv, ensurepip' || fail 'Built Python lacks required standard-library modules.'
            "$PYTHON" -m venv "$TMP/python-venv-check" && "$TMP/python-venv-check/bin/python" -m pip --version || fail 'Built Python could not create a working venv with pip.'
        fi
        python_ok || fail 'Python >=3.11 with venv/ensurepip is still unavailable; check python3-venv or set PYTHON.'
        if [ "$FOCAL_DOCKER" = 1 ]; then
            # Official retained distribution metadata provides exact .deb SHA-256.
            # No APT repository, trust key, daemon config, or package hold is changed.
            fetch "https://download.docker.com/linux/ubuntu/dists/focal/stable/binary-$ARCH/Packages.gz" "$TMP/docker-Packages.gz"
            "$PYTHON" - "$TMP/docker-Packages.gz" "$ARCH" > "$TMP/docker-selection" <<'PYDOCKER'
import gzip, re, sys
pins = {'docker-ce': '28.1.1', 'docker-ce-cli': '28.1.1', 'containerd.io': '1.7.27', 'docker-compose-plugin': '2.35.1', 'docker-buildx-plugin': '0.23.0'}
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
            privileged apt-get install --yes --no-remove --no-install-recommends "$TMP"/debs/*.deb || fail 'Frozen Docker package installation failed; no alternate repositories were added.'
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
    go_ok && node_ok && npm_ok && docker_ok || fail 'Post-install dependency validation failed; review command versions and original package provider.'
    if [ "$START_DOCKER" = 1 ]; then
        command -v systemctl >/dev/null 2>&1 || fail 'systemctl unavailable; start Docker manually for this environment.'
        privileged systemctl start docker || fail 'Docker service could not start; inspect systemctl status docker. No daemon configuration was changed.'
    fi
    printf 'Dependencies ready. Docker access may require administrator-approved setup; no user was added to the root-equivalent docker group.\n'
fi
[ "$DEPS_ONLY" = 0 ] || exit 0
python_ok || fail 'Python >=3.11 with venv/ensurepip required; use --install-deps or set PYTHON.'
go_ok || fail 'Go >=1.26 required; use --install-deps or install Go manually.'
node_ok && npm_ok || fail 'Node 20 or >=22 and npm >=7 required by parser lock; use --install-deps.'
"$PYTHON" -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/libs/vulscan-core/requirements.txt"
"$ROOT/.venv/bin/python" -m pip install --no-deps "$ROOT/libs/vulscan-core"
(cd "$ROOT/libs/vulscan-core/parsers/javascript" && npm ci --engine-strict --no-audit --no-fund)
mkdir -p "$ROOT/bin"
(cd "$ROOT/apps/vulscan-cli" && GOTOOLCHAIN=local go build -buildvcs=false -trimpath -o "$ROOT/bin/vulscan-cli" ./main.go)
cat > "$ROOT/bin/vulscan" <<'EOF'
#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PATH="$ROOT/.tools/go/bin:$ROOT/.tools/node/bin:$PATH"
export VULSCAN_PYTHON="$ROOT/.venv/bin/python"
export VULSCAN_PORTABLE_ROOT="$ROOT"
exec "$ROOT/bin/vulscan-cli" "$@"
EOF
chmod 755 "$ROOT/bin/vulscan"
printf '\nInstalled: %s/bin/vulscan\n' "$ROOT"
