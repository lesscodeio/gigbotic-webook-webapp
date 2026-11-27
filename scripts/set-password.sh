#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <new-password> [username]"
  exit 1
fi

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AUTH_FILE="$APP_DIR/data/auth.json"
mkdir -p "$APP_DIR/data"

NEW_PASS="$1"
NEW_USER="${2:-gigbotic}"

node --input-type=module -e '
  import crypto from "node:crypto";
  import fs from "node:fs";
  const [authFile, username, pass] = process.argv.slice(1);
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(pass, salt, 64).toString("hex");
  const cookieSecret = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(
    authFile,
    JSON.stringify({ username, salt, hash, cookieSecret, updatedAt: new Date().toISOString() }, null, 2),
    { mode: 0o600 }
  );
' "$AUTH_FILE" "$NEW_USER" "$NEW_PASS"

if command -v pm2 >/dev/null 2>&1 && pm2 describe gigbotic-managed-relay >/dev/null 2>&1; then
  pm2 restart gigbotic-managed-relay --update-env
fi

echo "Updated console credentials for user '$NEW_USER' in $AUTH_FILE."
