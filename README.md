# Gigbotic Managed Relay — Multi-Agent Web Console

Self-hosted, zero-dependency Node.js 22+ web application for running multiple **Gigbotic Managed Relay** agents on any Linux server (`Codex CLI`, `Claude Code CLI`, and `Antigravity CLI`), complete with an authenticated Web UI and an interactive PTY CLI/MCP terminal.

## Features

- **Multi-Agent Managed Relay Manager**: Maintain simultaneous outbound WebSocket (`wss://webhook.gigbotic.com/ws/ch_...`) connections using Creator Studio's zero-trust Managed Relay tokens (`rly_...`) and encrypted v2 webhook secrets (`whsec_...`).
- **Per-Agent CLI & Model Selection**: Assign each agent to **`codex`** (`codex exec -` with piped stdin EOF), **`claude`** (`claude -p`), or **`agy`** (`agy -p`), with optional model overrides and strict `agt_...` scope pinning.
- **Quick Fill from Creator Studio**: Paste the env snippet from Creator Studio's *"Managed Relay Provisioned"* modal to auto-fill all 4 relay fields.
- **Per-Job Isolation & Reliability**:
  - Official HMAC-SHA256 + AES-256-GCM v2 verification (`gigbotic-webhook-receiver.mjs`).
  - Durable SQLite `Idempotency-Key` deduplication & run history (`node:sqlite`).
  - Per-job isolated workspaces (`~/.gigbotic/isolated-jobs/<jobId>`), coalescing queue, `job.cancel_requested` preemption, and automatic ephemeral `jobMcpToken` injection.
- **Interactive CLI & MCP Terminal Tab**:
  - Run `agy`, `codex`, `claude`, `npm`, and `pm2` directly from the browser inside a real Linux PTY (`pty-runner.py`).
  - One-click MCP add/remove/list presets and a **Complete OAuth Callback** bar to finish headless `http://127.0.0.1:<port>/callback?...` OAuth flows without SSH port-forwarding.
- **Hardened Security**:
  - Scrypt-hashed console credentials (`0600` in `data/auth.json`), HMAC-SHA256 signed `HttpOnly; Secure; SameSite=Lax` session cookie, login rate limiting, same-origin CSRF checks on CLI endpoints, `Cache-Control: no-store, private`, and `X-Robots-Tag: noindex, nofollow`.
  - All relay tokens and webhook secrets are masked in API/UI responses and stored locally with `0600` permissions.

## Requirements

- **Linux (Debian, Ubuntu, RHEL, etc.)**
- **Node.js `>= 22.5.0`** (uses built-in `node:sqlite`, zero `npm install` needed)
- **Python 3** (stdlib `pty` module for the interactive CLI terminal)
- One or more agent CLIs installed in `~/.local/bin`: `codex`, `claude`, `agy`

## Quick Start (Linux)

1. **Install Node 22 LTS + Codex + Claude Code + Antigravity + PM2** (optional helper):
   ```bash
   bash scripts/install-linux.sh
   ```

2. **Start the web app**:
   ```bash
   npm start
   # or with PM2:
   npm run pm2:start
   ```
   On first startup, if `data/auth.json` does not exist, a strong password is generated automatically and printed once to stdout. To set your own password anytime:
   ```bash
   bash scripts/set-password.sh "YourStrongPassword" gigbotic
   ```

3. **Access locally via SSH tunnel** (with live WebSocket streaming):
   ```bash
   ssh -L 3450:127.0.0.1:3450 user@your-server
   # Open http://127.0.0.1:3450
   ```

## Optional: Expose Over HTTPS (Nginx, Caddy, or Apache/PHP)

The `reverse-proxy/` folder includes drop-in examples to serve the console over HTTPS while keeping the Node app bound to `127.0.0.1:3450`:

- **Nginx** (`reverse-proxy/nginx.conf`): Full HTTPS + live WebSocket (`/ws`) support.
- **Caddy** (`reverse-proxy/Caddyfile`): Automatic TLS + live WebSocket (`/ws`) support.
- **Apache + PHP-FPM** (`reverse-proxy/apache-php/`): Fallback HTTP reverse proxy for shared/managed LAMP hosts where `mod_proxy_http` is unavailable (keep this app directory outside your web root).

## Optional: Cron Watchdog

Add a user cron entry (`crontab -e`) so the app recovers automatically after reboots:
```cron
@reboot /path/to/gigbotic-webook-webapp/scripts/ensure-running.sh >/dev/null 2>&1
*/5 * * * * /path/to/gigbotic-webook-webapp/scripts/ensure-running.sh >/dev/null 2>&1
```

## Project Layout

```text
├── server.mjs                      # Multi-agent Managed Relay server, auth, API, WS & CLI PTY manager
├── gigbotic-webhook-receiver.mjs   # Encrypted v2 HMAC + AES-256-GCM verifier & WSS relay client
├── gigbotic-relay-bridge.mjs       # Standalone headless raw-envelope Managed Relay bridge
├── pty-runner.py                   # Stdlib Python 3 PTY wrapper for interactive CLI sessions
├── public/index.html               # Single-file web console UI (Agents, Live Runs, CLI & MCP Terminal)
├── reverse-proxy/                  # Optional HTTPS reverse-proxy configs
│   ├── nginx.conf
│   ├── Caddyfile
│   └── apache-php/
│       ├── .htaccess
│       └── index.php
├── scripts/
│   ├── install-linux.sh            # Installs Node 22, Codex, Claude Code, Antigravity, PM2
│   ├── set-password.sh             # Updates scrypt-hashed console credentials
│   └── ensure-running.sh           # Healthcheck watchdog for cron/PM2
├── ecosystem.config.cjs            # PM2 process configuration
└── package.json
```
