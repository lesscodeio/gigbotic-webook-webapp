#!/usr/bin/env bash
set -euo pipefail

# Linux installer (Debian/Ubuntu/generic x86_64) for Node 22 LTS + Codex + Claude Code + Antigravity (agy) + PM2.
# Usage:
#   INSTALL_HOME=/path/to/writable/home bash scripts/install-linux.sh

INSTALL_HOME="${INSTALL_HOME:-$HOME}"
LOCAL_DIR="$INSTALL_HOME/.local"
BIN_DIR="$LOCAL_DIR/bin"
NODE_VER="${NODE_VER:-v22.14.0}"

mkdir -p "$BIN_DIR" "$INSTALL_HOME/.config" "$INSTALL_HOME/.cache" "$INSTALL_HOME/.gigbotic"

export HOME="$INSTALL_HOME"
export XDG_CONFIG_HOME="$INSTALL_HOME/.config"
export XDG_CACHE_HOME="$INSTALL_HOME/.cache"
export XDG_DATA_HOME="$INSTALL_HOME/.local/share"
export NPM_CONFIG_PREFIX="$LOCAL_DIR"
export NPM_CONFIG_CACHE="$INSTALL_HOME/.npm"
export PM2_HOME="$INSTALL_HOME/.pm2"
export PATH="$BIN_DIR:$PATH"

echo "=== [1/4] Installing Node.js ${NODE_VER} (linux-x64) ==="
NODE_DIR="$LOCAL_DIR/node-${NODE_VER}-linux-x64"
if [ ! -x "$NODE_DIR/bin/node" ]; then
  curl -fsSL "https://nodejs.org/dist/${NODE_VER}/node-${NODE_VER}-linux-x64.tar.xz" -o "/tmp/node-${NODE_VER}.tar.xz"
  tar -xJf "/tmp/node-${NODE_VER}.tar.xz" -C "$LOCAL_DIR"
  rm -f "/tmp/node-${NODE_VER}.tar.xz"
fi
ln -sf "$NODE_DIR/bin/node" "$BIN_DIR/node"
ln -sf "$NODE_DIR/bin/npm" "$BIN_DIR/npm"
ln -sf "$NODE_DIR/bin/npx" "$BIN_DIR/npx"
ln -sf "$NODE_DIR/bin/corepack" "$BIN_DIR/corepack"

echo "=== [2/4] Installing Codex CLI (@openai/codex) & PM2 ==="
npm install -g @openai/codex pm2

echo "=== [3/4] Installing Claude Code CLI ==="
if ! curl -fsSL https://claude.ai/install.sh | bash; then
  npm install -g @anthropic-ai/claude-code
fi

echo "=== [4/4] Installing Antigravity CLI (agy) ==="
curl -fsSL https://antigravity.google/cli/install.sh | bash

echo ""
echo "Installed versions:"
echo "  node:   $(node -v)"
echo "  codex:  $(codex --version)"
echo "  claude: $(claude --version)"
echo "  agy:    $(agy --version)"
echo "  pm2:    $(pm2 -v)"
