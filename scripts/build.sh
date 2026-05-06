#!/usr/bin/env bash
set -Eeuo pipefail

if command -v uv >/dev/null 2>&1; then
  exec uv run python scripts/build.py "$@"
fi

exec python3 scripts/build.py "$@"
