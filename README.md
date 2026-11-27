# Gigbotic Managed Relay — Multi-Agent Linux Web Console & Docker Sandbox

Self-hosted, zero-dependency Node.js 22+ web application for running multiple **Gigbotic Managed Relay** agents on any Linux VPS (`Codex CLI`, `Claude Code CLI`, and `Antigravity CLI`), with **Per-Job Docker + Host-Side Egress Proxy isolation**, an authenticated Web UI, and an interactive PTY CLI/MCP terminal.

- **Public Repository**: `https://github.com/lesscodeio/gigbotic-webook-webapp`
- **Documentation & Reference**: [gigbotic.com/docs](https://gigbotic.com/docs)
- **Linux VPS & Docker Playbook**: [Self-Host Gigbotic Agents on Linux VPS with Docker & Managed Relay](https://gigbotic.com/guides/linux-managed-relay-docker-vps-guide)
- **Security Hardening Playbook**: [How to Make AI Agents Secure: 5-Layer Defense, Docker Isolation & Hardening Playbook](https://gigbotic.com/guides/how-to-make-ai-agents-secure-on-gigbotic)

---

## Architecture & 5-Layer Security Overview

```text
+-----------------------------------------------------------------------------+
|                        Gigbotic Cloud (gigbotic.com)                        |
|   Signed + AES-256-GCM v2 WSS Relay  |  /mcp (Job Plane) & Cloud Core Files |
+-----------------------------------------------------------------------------+
                |  1. Outbound WSS (Authorization: Bearer rly_...)
                |  2. Pre-spawn read_agent_core_files + SHA-256 verify
                v
+-----------------------------------------------------------------------------+
|                Linux Managed Relay Host (server.mjs + PM2)                  |
|  - Zero-dep Node 22+ HTTP/WS Web UI (127.0.0.1:3450, scrypt + HttpOnly)     |
|  - SQLite WAL Idempotency-Key dedup & run history (data/relay-state.sqlite) |
|  - runner-sandbox.mjs: SHA-256 Core Files cache, ephemeral fake-home,       |
|    strict env allowlist, Docker driver & instant docker kill on stop        |
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  | Host-Side Egress Allowlist Proxy (egress-proxy.mjs)                   |  |
|  | Bound ONLY to br-gbsandbox gateway IP | Per-job Basic-auth token      |  |
|  | Port 443 only | Pre-connect DNS SSRF guard | 3-tier networkPolicy     |  |
|  +-----------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------+
                |  3. Per-job `docker run --rm` on `--internal` bridge
                |     (zero default route / zero direct internet access)
                v
+-----------------------------------------------------------------------------+
|             Ephemeral Per-Job Container (gigbotic-runner:latest)            |
|  --read-only rootfs | --cap-drop=ALL | no-new-privileges:true | UID:GID     |
|  :ro AGENTS.md / Core Files overlay | /home/runner -> ephemeral fake-home   |
|  /run/gigbotic/* (:ro control dir)  | HTTP(S)_PROXY -> br-gbsandbox proxy   |
+-----------------------------------------------------------------------------+
                |  4. Proxied HTTPS (443) to pinned public IP only
                v
+-----------------------------------------------------------------------------+
|        Allowed Gigbotic /mcp, Engine LLM APIs & Policy-Permitted Hosts      |
+-----------------------------------------------------------------------------+
```

### 5-Layer Defense-in-Depth

1. **Layer 1 — Zero-Trust Managed Relay & Encrypted v2 Webhooks (`gigbotic-webhook-receiver.mjs`)**:
   - Outbound-only WebSocket (`wss://webhook.gigbotic.com/ws/ch_...`) authenticated via `Authorization: Bearer <rly_...>` — no public inbound webhook port required on your VPS.
   - Verifies HMAC-SHA256 signatures and decrypts AES-256-GCM v2 envelopes locally with your `whsec_...` secret; persists `Idempotency-Key` deduplication in `node:sqlite` (`WAL` mode).
2. **Layer 2 — Scoped Job MCP Execution Plane & Ephemeral Tokens**:
   - Every wakeup injects only the job-scoped ephemeral `jobMcpToken` targeting `https://gigbotic.com/mcp` (and disables any creator/other Gigbotic MCP entries).
   - Client OAuth connections remain brokered through Gigbotic's Approval Gates and `vault_http_request` — third-party tokens never touch your VPS.
3. **Layer 3 — Pre-Spawn Cloud Core Files Verification & Prompt Elevation (`runner-sandbox.mjs`)**:
   - Before spawning any CLI, the host calls stateless JSON-RPC `read_agent_core_files` with `if_none_match` / `core_files_cache_token` and tamper-proof `runner_security` telemetry.
   - Verifies every file's SHA-256 and recomputes the deterministic bundle SHA-256 before writing to the immutable cache (`~/.gigbotic/core-files-cache/<agentId>/v<ver>/<hash>/`, `0400`). Fails closed if required core files fail verification.
   - Elevates **Tier-1 Immutable Platform Policy + Tier-2 Pinned Cloud Core Files** to each CLI's highest instruction tier (`developer_instructions` in isolated Codex `config.toml`, `--append-system-prompt-file` for Claude, `.agents/rules/00-gigbotic-platform-policy.md` for Agy) and materializes read-only (`0444`) `AGENTS.md` (plus `CLAUDE.md` for Claude) with kernel-enforced `:ro` overlay mounts inside Docker.
4. **Layer 4 — Per-Job Docker Isolation & Host-Side Egress Proxy (`runner-sandbox.mjs` + `egress-proxy.mjs`)**:
   - **Zero `--dangerously-*` flags**: Never passes `--dangerously-bypass-approvals-and-sandbox` or `--dangerously-skip-permissions`. Local `maxSandboxMode` / `maxNetworkPolicy` caps can only tighten (never weaken) the cloud-signed `executionPolicy`.
   - **Hardened Container Flags**: `--rm --init --user <hostUid>:<hostGid> --read-only --cap-drop=ALL --security-opt no-new-privileges:true --ulimit nofile=2048:4096`, `/run:rw,noexec,nosuid,nodev,size=16m`, and `--network gigbotic-sandbox-net` (`--internal` bridge `br-gbsandbox` with zero direct internet route).
   - **Ephemeral `fake-home` & Secret Scrubbing**: Each run receives a fresh `0700` control directory (`~/.gigbotic/runner-meta/<jobId>/<deliveryId>/`) outside `/workspace` containing `fake-home/`, `system-prompt.md`, `mcp.json`, and `agy-settings.json` (mounted `:ro` at `/run/gigbotic/`). Only the single active CLI auth file is copied into `fake-home` — never `~/.ssh`, `data/webhooks.json`, or host credentials. `buildSanitizedChildEnv` uses a strict allowlist (never spreads `process.env`), and Codex's `shell_environment_policy` explicitly scrubs `GIGBOTIC_MCP_TOKEN`, `AWS_*`, `GCP_*`, `OPENAI_*`, `ANTHROPIC_*`, `GITHUB_*`, `DATABASE_*`, `STRIPE_*`, `SSH_*`, `PM2_*`, `*_SECRET*`, `*_TOKEN*`, `*_KEY*`, and `*_PASSWORD*` from child shells.
   - **Dynamic Resource Limits** (scaled automatically per `sandboxMode`, overridable via env vars):

     | Resource | `mcp_only` / `read_only` | `workspace_write` | Env Override |
     | :--- | :--- | :--- | :--- |
     | Workspace mount & host mode | `:ro` (`0555` on host) | `:rw` (`0700` on host) | — |
     | Memory (`--memory` & `--memory-swap`) | `2g` | `clamp(2g..8g, floor(hostMemGb * 0.55))` | `GIGBOTIC_DOCKER_MEMORY` |
     | CPUs (`--cpus`) | `2` | `min(4, max(2, hostCpus))` | `GIGBOTIC_DOCKER_CPUS` |
     | PIDs (`--pids-limit`) | `128` | `512` | `GIGBOTIC_DOCKER_PIDS_LIMIT` |
     | `/tmp` tmpfs | `256m` (`rw,noexec,nosuid,nodev`) | `1g` (`rw,nosuid,nodev`) | `GIGBOTIC_DOCKER_TMPFS_SIZE` |
     | Max file size (`--ulimit fsize`) | `500 MB` (`524288000`) | `2 GiB` (`2147483648`) | — |
     | Open files (`--ulimit nofile`) | `2048:4096` | `2048:4096` | — |

   - **Host-Side Egress Proxy (`egress-proxy.mjs`)**:
     - Listens strictly on the `br-gbsandbox` Docker bridge gateway IP with a per-job 24-byte random Basic-auth token (`http://job:<token>@<gatewayIp>:<port>`) that is revoked immediately on exit or stop.
     - **3-Tier `networkPolicy`**:
       - `locked`: Permits **only** `gigbotic.com`, the active `mcpHost`, `allowedUploadHosts`, and the active CLI's `ENGINE_LLM_HOSTS`.
       - `public_web`: Permits public HTTPS (`443`) websites while hard-blocking Git hosts (`github.com`, `gitlab.com`, `bitbucket.org`, `codeberg.org`, `git.sr.ht`, etc.) and package registries (`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `crates.io`, `rubygems.org`, `proxy.golang.org`, `hub.docker.com`, `ghcr.io`, etc.).
       - `public_web_and_git`: Permits public HTTPS + Git hosts + package registries (Git hosts remain blocked if `allowExternalGitClone` is `false`).
     - **SSRF & DNS-Rebinding Guard (all tiers)**: Blocks raw IP literals, non-`443` ports, local/internal hostnames (`localhost`, `metadata.google.internal`, `host.docker.internal`, `*.localhost`, `*.local`, `*.localdomain`, `*.internal`, `*.home.arpa`), loopback (`127.0.0.0/8`, `::1`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64/10`), link-local / cloud instance metadata (`169.254.0.0/16`), IPv6 ULA (`fc00::/7`), link-local (`fe80::/10`), IPv4-mapped (`::ffff:0:0/96`), and NAT64 (`64:ff9b::/96`). Resolves all A/AAAA records before connecting and dials the verified public IP directly so DNS rebinding cannot bypass the check.
     - **Built-in `ENGINE_LLM_HOSTS`**:
       - `codex`: `api.openai.com`, `chatgpt.com`, `auth.openai.com`
       - `claude`: `api.anthropic.com`, `claude.ai`, `console.anthropic.com`
       - `agy`: `generativelanguage.googleapis.com`, `cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.sandbox.googleapis.com`, `autopush-cloudcode-pa.googleapis.com`, `autopush-cloudcode-pa.sandbox.googleapis.com`, `aicode.googleapis.com`, `play.googleapis.com`, `oauth2.googleapis.com`, `www.googleapis.com`, `accounts.google.com`
5. **Layer 5 — Preemption, Orphan Sweeping & Console Hardening**:
   - Instant `job.turn_stopped` and `job.cancel_requested` preemption revokes the job's egress proxy token, runs `docker kill`, and reaps the child process group (`SIGTERM` → `SIGKILL` after 3.5s). Wall-clock timeout enforces `executionPolicy.maxExecutionSeconds` (default `900s`, `1800s` for `workspace_write`, clamped `60..3600s`).
   - On server startup, `sweepOrphanedDockerContainers()` kills any stray containers labeled `gigbotic.managed=true` left behind after an unclean host reboot or crash.
   - Console auth uses scrypt-hashed credentials (`0600` in `data/auth.json`), HMAC-SHA256 signed `HttpOnly; SameSite=Lax` (plus `Secure` behind HTTPS) session cookies, 10-attempts/5-min IP login rate limiting, same-origin CSRF checks on CLI endpoints, `Cache-Control: no-store, private`, `X-Frame-Options: DENY`, and `X-Robots-Tag: noindex, nofollow`.

---

## Quick Start on Linux VPS

### Prerequisites

- **Linux VPS** (Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky 9) — 2 vCPU / 4 GB RAM minimum; 4 vCPU / 8+ GB RAM recommended for `workspace_write` media/coding agents
- **Node.js `>= 22.5.0`** (uses built-in `node:sqlite` and `node:test`; zero `npm install` needed)
- **Python 3** (stdlib `pty` module for the browser Terminal tab)
- **Docker Engine** (strongly recommended — enables kernel-level per-job container isolation + egress proxy automatically under the default `GIGBOTIC_SANDBOX_DRIVER=auto`)
- At least one agent CLI (`codex`, `claude`, or `agy`) installed in `~/.local/bin`

### 1. Clone the Repository & Install Node 22 + CLIs + PM2

```bash
git clone https://github.com/lesscodeio/gigbotic-webook-webapp.git
cd gigbotic-webook-webapp

# Optional helper: installs Node 22 LTS, Codex CLI, Claude Code CLI, Antigravity CLI (agy), and PM2 into ~/.local/bin
bash scripts/install-linux.sh
export PATH="$HOME/.local/bin:$PATH"
```

### 2. Install Docker Engine & Grant `docker` Group Access

```bash
# Ubuntu / Debian example (see https://docs.docker.com/engine/install/ for other distros)
curl -fsSL https://get.docker.com | sudo sh

# Allow your non-root relay user to manage per-job containers
sudo usermod -aG docker "$USER"
newgrp docker

# Verify non-root Docker access
docker info --format '{{.ServerVersion}}'
```

### 3. Build the Runner Image (`gigbotic-runner:latest`)

```bash
npm run docker:build
# Equivalent to:
# docker build -t gigbotic-runner:latest -f docker/Dockerfile.runner .
```

The base `docker/Dockerfile.runner` image (`node:22-bookworm-slim`) pre-installs `ca-certificates`, `curl`, `fonts-dejavu-core`, `git`, `python3`, `python3-pil`, `python3-venv`, `ffmpeg`, `jq`, `ripgrep`, `unzip`, `@openai/codex`, `@anthropic-ai/claude-code`, and `agy` (with all SUID/SGID bits stripped, no `sudo`/`ssh`/`cron`/`docker-cli`, running as non-root `runner` UID/GID `1000`).

#### Optional: Custom Derived Image & NVIDIA GPU Pass-Through

Need extra packages (for example Playwright, LaTeX, ImageMagick, or custom Python libraries)? Extend the official runner image and keep `USER 1000:1000`:

```dockerfile
# Dockerfile.custom
FROM gigbotic-runner:latest
USER root
RUN apt-get update \
  && apt-get install -y --no-install-recommends imagemagick pandoc \
  && rm -rf /var/lib/apt/lists/* \
  && find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
USER 1000:1000
```

```bash
docker build -t my-gigbotic-runner:latest -f Dockerfile.custom .
export GIGBOTIC_RUNNER_IMAGE=my-gigbotic-runner:latest
```

For GPU-accelerated inference or video rendering (requires [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html) on the host):

```bash
export GIGBOTIC_DOCKER_GPUS=all   # or e.g. device=0
```

### 4. Set Console Password & Start Under PM2

```bash
# Optional: set your own Web UI password (otherwise a random password is generated and printed once on first boot)
bash scripts/set-password.sh "YourStrongPassword" gigbotic

# Optional: enforce Docker fail-closed for workspace_write agents
export GIGBOTIC_REQUIRE_DOCKER=1

# Start with PM2 (preserves GIGBOTIC_* env overrides via ecosystem.config.cjs)
npm run pm2:start
npm run pm2:logs
```

Or run directly in the foreground without PM2:

```bash
npm start
```

### 5. Access the Web Console (SSH Tunnel or HTTPS Reverse Proxy)

`server.mjs` binds to `127.0.0.1:3450` by default so the console is never exposed directly on a public port.

- **Option A — Local SSH Tunnel (Zero public exposure, full live WebSockets)**:
  ```bash
  ssh -L 3450:127.0.0.1:3450 user@your-vps
  # Open http://127.0.0.1:3450
  ```
- **Option B — HTTPS Reverse Proxy** (drop-in configs in `reverse-proxy/`):
  - **Nginx** (`reverse-proxy/nginx.conf`): Full HTTPS + live WebSocket (`/ws`) proxy with `proxy_read_timeout 3600s`.
  - **Caddy** (`reverse-proxy/Caddyfile`): Automatic Let's Encrypt TLS + live WebSocket (`/ws`) proxy.
  - **Apache + PHP-FPM** (`reverse-proxy/apache-php/`): Fallback HTTP reverse proxy for shared/managed LAMP hosts where `mod_proxy_http` is unavailable (keep the app directory outside your web root).

### 6. Authenticate Headless CLIs via the Terminal Tab

Open the **Terminal** tab in the Web UI (powered by `pty-runner.py` + vendored `xterm.js`) and log into the CLI(s) you plan to run:

- **Codex CLI**: `codex login`
- **Claude Code CLI**: `claude auth login` (or `claude`)
- **Antigravity CLI**: `agy login`

When a CLI prints an OAuth URL, click the detected link to sign in on your local browser. Your browser will redirect to an unreachable `http://127.0.0.1:<port>/callback?...` URL — copy that full URL from your browser's address bar, paste it into the **Complete OAuth Callback** bar inside the **Terminal** tab, and submit. The server delivers the callback locally (`/api/cli/oauth-callback`, restricted strictly to ephemeral loopback ports `1024..65535`) so you never need extra SSH port-forwarding for headless OAuth.

### 7. Connect Agents via Creator Studio Quick Fill

1. In [Gigbotic Creator Studio](https://gigbotic.com/creator/agents), open your agent → **Webhooks & Relay** → provision a **Managed Relay** channel.
2. Copy the env block from the one-time **"Managed Relay Provisioned"** modal (`GIGBOTIC_RELAY_URL`, `GIGBOTIC_RELAY_TOKEN`, `GIGBOTIC_WEBHOOK_ID`, `GIGBOTIC_WEBHOOK_SECRET`).
3. In the Web UI **Agents & Relays** tab, click **Add Agent**, paste the snippet into **Quick Fill**, select the CLI engine (`codex`, `claude`, or `agy`) and optional model override, and save.
4. Click **Test CLI** (local smoke test) and trigger a **Test Delivery** from Creator Studio to confirm `200 OK` end-to-end.

---

## Environment Variables Reference

Copy `.env.example` or export overrides before running `npm start` / `npm run pm2:start` / `npm run pm2:restart`:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `UI_HOST` | `127.0.0.1` | Bind address for the Web UI, REST API, and `/ws` server. Keep `127.0.0.1` behind SSH tunnel or reverse proxy. |
| `UI_PORT` | `3450` | TCP port for the Web UI & API server (also read by `scripts/ensure-running.sh`). |
| `GIGBOTIC_CONSOLE_USER` | `gigbotic` | Initial Web UI username used only on first boot when `data/auth.json` does not exist yet. |
| `GIGBOTIC_CONSOLE_PASSWORD` | Auto-generated (`GB-…`) | Initial Web UI password on first boot (if unset, a random strong password is generated and printed once to stdout). |
| `GIGBOTIC_SANDBOX_DRIVER` | `auto` | Sandbox execution backend: `auto` (use Docker whenever daemon + image are ready, else native hardened CLI sandbox), `docker` (always require Docker; fail-closed if unavailable), or `native` (host CLI sandbox only). |
| `GIGBOTIC_REQUIRE_DOCKER` | unset (`0`) | Set to `1` to fail-closed on `workspace_write` jobs if Docker is unavailable instead of falling back to native `cli_sandbox`. |
| `GIGBOTIC_RUNNER_IMAGE` | `gigbotic-runner:latest` | Docker image tag launched for each isolated job turn. Override when using a custom derived Dockerfile. |
| `GIGBOTIC_DOCKER_MEMORY` | Dynamic (`2g` or `2g..8g`) | Container RAM & swap cap (`--memory` and `--memory-swap`). Default: `clamp(2g..8g, floor(hostMemGb * 0.55))` for `workspace_write`; `2g` for `mcp_only` / `read_only`. |
| `GIGBOTIC_DOCKER_CPUS` | Dynamic (`2` or `2..4`) | Container CPU quota (`--cpus`). Default: `min(4, max(2, hostCpus))` for `workspace_write`; `2` for `mcp_only` / `read_only`. |
| `GIGBOTIC_DOCKER_PIDS_LIMIT` | Dynamic (`128` or `512`) | Maximum processes/threads (`--pids-limit`). Default: `512` for `workspace_write`; `128` for `mcp_only` / `read_only`. |
| `GIGBOTIC_DOCKER_TMPFS_SIZE` | Dynamic (`256m` or `1g`) | In-memory `/tmp` tmpfs cap. Default: `1g` (`rw,nosuid,nodev`) for `workspace_write`; `256m` (`rw,noexec,nosuid,nodev`) for `mcp_only` / `read_only`. |
| `GIGBOTIC_DOCKER_GPUS` | unset (disabled) | Optional `--gpus` flag forwarded to `docker run` (e.g., `all` or `device=0`) for NVIDIA GPU pass-through. |
| `GIGBOTIC_EGRESS_PROXY_PORT` | `0` (ephemeral) | TCP port for the host-side egress allowlist proxy bound strictly to the `br-gbsandbox` Docker gateway IP. `0` picks an ephemeral port automatically. |
| `NODE_BIN` | `$HOME/.local/bin/node` | Explicit Node.js 22+ binary path used as the PM2 `interpreter` in `ecosystem.config.cjs`. |
| `INSTALL_HOME` | `$HOME` | Target writable home directory used by `scripts/install-linux.sh` for `.local/bin`, `.config`, `.cache`, and `.gigbotic`. |
| `NODE_VER` | `v22.14.0` | Node.js LTS release downloaded by `scripts/install-linux.sh`. |

> **PM2 Tip**: `ecosystem.config.cjs` automatically passes through all `GIGBOTIC_SANDBOX_DRIVER`, `GIGBOTIC_REQUIRE_DOCKER`, `GIGBOTIC_RUNNER_IMAGE`, `GIGBOTIC_DOCKER_*`, and `GIGBOTIC_EGRESS_PROXY_PORT` values from `process.env` when defined. Apply changes cleanly with:
> ```bash
> GIGBOTIC_REQUIRE_DOCKER=1 GIGBOTIC_DOCKER_MEMORY=6g npm run pm2:restart
> ```

---

## Project Layout

```text
├── server.mjs                      # Multi-agent Managed Relay server, auth, API, WS, job runner & PTY manager
├── runner-sandbox.mjs              # Layers 3 & 4: Core Files SHA-256 preflight, fake-home, CLI flags & Docker driver
├── egress-proxy.mjs                # Host-side HTTP/CONNECT egress allowlist proxy & DNS-rebinding/SSRF guard
├── gigbotic-webhook-receiver.mjs   # Encrypted v2 HMAC-SHA256 + AES-256-GCM verifier & WSS relay client
├── gigbotic-relay-bridge.mjs       # Standalone headless raw-envelope Managed Relay bridge
├── pty-runner.py                   # Stdlib Python 3 PTY wrapper for interactive CLI sessions
├── docker/
│   └── Dockerfile.runner           # Non-root gigbotic-runner:latest image (Node 22, FFmpeg, Python, Codex, Claude, Agy)
├── tests/
│   └── runner-sandbox.test.mjs     # Built-in node:test security suite (CLI matrix, fake-home, SHA-256, egress SSRF)
├── public/
│   ├── index.html                  # Single-file web console UI (Agents & Relays, Live Runs & Logs, Terminal)
│   └── vendor/                     # Vendored xterm.js + fit addon + CSS (zero CDN dependency)
├── reverse-proxy/                  # Optional HTTPS reverse-proxy configs
│   ├── nginx.conf
│   ├── Caddyfile
│   └── apache-php/
│       ├── .htaccess
│       └── index.php
├── scripts/
│   ├── install-linux.sh            # Installs Node 22, Codex, Claude Code, Antigravity (agy), PM2
│   ├── set-password.sh             # Updates scrypt-hashed console credentials (0600 data/auth.json)
│   └── ensure-running.sh           # Healthcheck watchdog for cron/PM2 (/api/health)
├── .env.example                    # Documented template for console, Docker sandbox & egress proxy overrides
├── ecosystem.config.cjs            # PM2 process config with automatic GIGBOTIC_* env pass-through
└── package.json                    # Scripts: start, test, docker:build, set-password, pm2:*
```

---

## Testing

Run the built-in zero-dependency `node:test` security verification suite (19 assertions across Layer 3 & Layer 4):

```bash
npm test
# Runs: node --test tests/runner-sandbox.test.mjs
```

It verifies:
- Zero `--dangerously-*` flags across `codex`, `claude`, and `agy` under `mcp_only`, `read_only`, and `workspace_write`
- Strict environment allowlist & ephemeral `fake-home` isolation (zero host secret leakage)
- Pre-spawn `read_agent_core_files` SHA-256 verification, immutable cache, `0444 AGENTS.md`, `0555 workDir`, and fail-closed hash mismatch handling
- Host-side egress proxy `407` auth, 3-tier `networkPolicy` (`locked` / `public_web` / `public_web_and_git`), Git/package-registry blocking, and DNS-rebinding / private-IP SSRF blocking

---

## Upgrading

```bash
cd /path/to/gigbotic-webook-webapp
git pull origin main

# Rebuild gigbotic-runner:latest whenever docker/Dockerfile.runner changes
npm run docker:build

# Verify tests & reload PM2 cleanly
npm test
npm run pm2:restart
```

---

## Optional: Cron Watchdog

Add a user cron entry (`crontab -e`) so the relay restarts automatically after VPS reboots or unexpected exits:

```cron
@reboot /path/to/gigbotic-webook-webapp/scripts/ensure-running.sh >/dev/null 2>&1
*/5 * * * * /path/to/gigbotic-webook-webapp/scripts/ensure-running.sh >/dev/null 2>&1
```

---

## Troubleshooting

| Symptom / Error | Cause | Fix |
| :--- | :--- | :--- |
| **Job exits with code `137` (SIGKILL / OOM)** | Container hit `--memory` / `--memory-swap` or `/tmp` tmpfs limit during heavy FFmpeg, headless browser, or build workloads. | Increase `GIGBOTIC_DOCKER_MEMORY` (e.g. `4g` or `8g`) and/or `GIGBOTIC_DOCKER_TMPFS_SIZE` (e.g. `2g`), ensure the VPS has enough host RAM, and run `npm run pm2:restart`. |
| **Egress proxy returns `403 Forbidden`** (`network_locked`, `git_host_blocked`, `package_registry_blocked`, `BLOCKED_PRIVATE_IP`, `raw_ip_blocked`, `port_not_allowed`) | The agent attempted an outbound connection forbidden by its `executionPolicy.networkPolicy`, used a raw IP / non-443 port, or resolved to a private/metadata IP. | Inspect `[egress-blocked]` entries in `npm run pm2:logs`. If the domain is legitimate for the agent's task, update the agent's **Network Policy** (`locked` → `public_web` or `public_web_and_git`) or **Allowed Upload Hosts** in Creator Studio — never weaken SSRF rules. |
| **Docker permissions error or Creator Studio shows *"Unverified Runner — Update Required"*** | The relay user cannot access `/var/run/docker.sock`, `gigbotic-runner:latest` has not been built yet, or the runner fell back to native mode / outdated `runner-sandbox.mjs`. | Run `sudo usermod -aG docker "$USER" && newgrp docker`, verify `docker info`, run `npm run docker:build`, confirm `GIGBOTIC_SANDBOX_DRIVER` is `auto` or `docker` (and `GIGBOTIC_REQUIRE_DOCKER=1` for `workspace_write` agents), then run `npm run pm2:restart`. |
| **`CORE_FILES_PREFETCH_FAILED` / `CORE_FILES_REQUIRED`** | The pre-spawn `read_agent_core_files` call failed network reachability, received an expired/missing `jobMcpToken`, or detected a SHA-256 bundle mismatch. | Confirm the agent has published Cloud Core Files in Creator Studio, verify host outbound HTTPS access to `https://gigbotic.com/mcp`, and check `npm run pm2:logs` for the exact HTTP status or hash error. |
| **`agy` command not found inside Docker container** | `agy` was skipped or unavailable during `Dockerfile.runner` build on your architecture, or is missing from host `$HOME/.local/bin/agy`. | On Linux, `runner-sandbox.mjs` automatically bind-mounts host `~/.local/bin/agy` (or `/usr/local/bin/agy`) read-only into `/usr/local/bin/agy`. Install `agy` on the host (`curl -fsSL https://antigravity.google/cli/install.sh \| bash`) or rebuild `npm run docker:build`. |
| **Nested sandbox `EPERM` (`operation not permitted`) inside Docker** | Running a CLI's inner Linux namespace/bubblewrap sandbox inside a `--cap-drop=ALL --security-opt no-new-privileges:true` container fails with `EPERM`. | `runner-sandbox.mjs` automatically delegates kernel sandboxing to the Docker container for `workspace_write` + `allowShell` (using Codex `danger-full-access` and omitting `agy --sandbox` strictly inside Docker while keeping full CLI sandboxes on native host runs and in `mcp_only` / `read_only`). Pull the latest `main` and restart PM2 if you hit this on an older checkout. |
