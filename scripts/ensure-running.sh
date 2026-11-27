#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
UI_PORT="${UI_PORT:-3450}"

if ! curl -fsS --max-time 3 "http://127.0.0.1:${UI_PORT}/api/health" >/dev/null 2>&1; then
  pm2 startOrRestart "$APP_DIR/ecosystem.config.cjs" --update-env
  pm2 save >/dev/null 2>&1 || true
fi
