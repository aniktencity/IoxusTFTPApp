#!/usr/bin/env bash
set -euo pipefail

# Simple one-file console build for Linux using PyInstaller
# Requires: python3.11+ on target system (or compatible), pyinstaller installed in venv

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT="$HERE/.."

python3 -m venv "$ROOT/.venv"
source "$ROOT/.venv/bin/activate"
pip install --upgrade pip wheel
pip install pyinstaller

# Install project itself (editable)
pip install -e "$ROOT"

NAME="ioxus-updater-cli"
ENTRY="haven_tftp/cli.py"
SPEC_OUT="$ROOT/dist"

pyinstaller -F -n "$NAME" --console "$ROOT/src/$ENTRY" \
  --workpath "$ROOT/build/cli_build" --distpath "$SPEC_OUT"

echo "Built: $SPEC_OUT/$NAME"

