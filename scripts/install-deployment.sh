#!/bin/sh
# Run from any directory; keep this installation tree together.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
"$PYTHON" -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/libs/vulscan-core/requirements.txt"
"$ROOT/.venv/bin/python" -m pip install --no-deps "$ROOT/libs/vulscan-core"
mkdir -p "$ROOT/bin"
(cd "$ROOT/apps/vulscan-cli" && go build -buildvcs=false -trimpath -o "$ROOT/bin/vulscan-cli" ./main.go)
cat > "$ROOT/bin/vulscan" <<'EOF'
#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export VULSCAN_PYTHON="$ROOT/.venv/bin/python"
export VULSCAN_PORTABLE_ROOT="$ROOT"
exec "$ROOT/bin/vulscan-cli" "$@"
EOF
chmod 755 "$ROOT/bin/vulscan"
printf '\nInstalled: %s/bin/vulscan\n' "$ROOT"
