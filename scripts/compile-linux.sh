#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export electron_config_cache="$PWD/.electron-cache"
export ELECTRON_CACHE="$PWD/.electron-cache"
export ELECTRON_BUILDER_CACHE="$PWD/.electron-builder-cache"

PYTHON_BIN="${PYTHON:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -x ".venv/bin/python" ]]; then
    PYTHON_BIN=".venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

echo "Installing Python build dependencies..."
"${PYTHON_BIN}" -m pip install -r requirements.txt -r requirements-build.txt

echo "Building Python backend executable..."
"${PYTHON_BIN}" -m PyInstaller \
  --clean \
  --noconfirm \
  --onefile \
  --name gn-slop-backend \
  --add-data "app/static:app/static" \
  app/desktop_server.py

rm -rf dist/desktop-backend
mkdir -p dist/desktop-backend
cp dist/gn-slop-backend dist/desktop-backend/gn-slop-backend
chmod +x dist/desktop-backend/gn-slop-backend

echo "Installing Electron dependencies..."
npm install

echo "Packaging Linux app..."
npm run build:linux

echo "Done. Output is in the release directory."
