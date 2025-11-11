#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

echo "=== Creating/activating venv ==="
if [[ ! -d "$root/.venv" ]]; then
  python3 -m venv "$root/.venv"
fi
source "$root/.venv/bin/activate"

echo "=== Installing dependencies ==="
python -m pip install --upgrade pip wheel
python -m pip install pyinstaller

echo "=== Installing project (editable) ==="
python -m pip install -e "$root"

echo "=== Building Linux binary (PyInstaller) ==="
name="IOXUSBLUpdater"
spec_entry="$root/src/haven_tftp/app.py"

# Optional: encryption key for embedded bytecode (discourages extraction)
# You can set it before running: export PYINSTALLER_KEY=$(python - <<<'import secrets;print(secrets.token_hex(16))')
key_arg=()
if [[ -n "${PYINSTALLER_KEY:-}" ]]; then
  key_arg=("--key" "$PYINSTALLER_KEY")
  echo "Using PyInstaller bytecode key (PYINSTALLER_KEY set)"
fi

# Optional: UPX if present for smaller binary
upx_arg=()
if command -v upx >/dev/null 2>&1; then
  upx_arg=("--upx-dir" "$(dirname $(command -v upx))")
  echo "UPX found: enabling compression"
else
  echo "UPX not found: skipping compression (optional)"
fi

# Include assets directory if present
common_args=("-F" "-w" "--clean" "-n" "$name" "${key_arg[@]}" "${upx_arg[@]}")
if [[ -d "$root/assets" ]]; then
  pyinstaller "${common_args[@]}" \
    --add-data "$root/assets:assets" \
    "$spec_entry"
else
  pyinstaller "${common_args[@]}" "$spec_entry"
fi

echo "=== Done ==="
echo "Binary at: $root/dist/$name"
