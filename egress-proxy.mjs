/**
 * Gigbotic Host-Side Egress Allowlist Proxy (Zero npm dependencies, Node.js 22+).
 *
 * Binds strictly to the internal Docker sandbox bridge gateway IP (or explicit host)
 * and enforces per-job domain allowlists + pre-connect DNS IP verification so
 * sandboxed containers cannot reach:
 * - Host loopback (`127.0.0.0/8`, `::1`, Relay UI `:3450`)
 * - Cloud instance metadata (`169.254.169.254`, `169.254.0.0/16`)
 * - RFC1918 / CGNAT / ULA / link-local / multicast private networks
 * - Arbitrary domains or Git/package registries blocked by `executionPolicy.networkPolicy`
 *
 * 3-tier `networkPolicy`:
 * - `locked`: Gigbotic MCP + `allowedUploadHosts` + selected engine LLM API hosts ONLY.
 * - `public_web`: Public HTTPS websites allowed; blocks private/loopback/metadata IPs
 *   AND blocks Git hosts (`github.com`, `gitlab.com`, `bitbucket.org`, etc.) and package
 *   registries (`registry.npmjs.org`, `pypi.org`, etc.).
 * - `public_web_and_git`: Public HTTPS websites + Git hosts + package registries;
 *   still hard-blocks all private/loopback/metadata IPs.
 */
import crypto from "node:crypto";
import dns from "node:dns";
import http from "node:http";
import net from "node:net";

export const ENGINE_LLM_HOSTS = Object.freeze({
  codex: Object.freeze(["api.openai.com", "chatgpt.com", "auth.openai.com"]),
  claude: Object.freeze(["api.anthropic.com", "claude.ai", "console.anthropic.com"]),
  agy: Object.freeze([
    "generativelanguage.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.sandbox.googleapis.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
  ]),
  lambda: Object.freeze([]),
});

const GIT_EXACT_HOSTS = new Set([
  "github.com",
  "api.github.com",
  "raw.githubusercontent.com",
  "objects.githubusercontent.com",
  "codeload.github.com",
  "gist.github.com",
  "ssh.github.com",
  "uploads.github.com",
  "gitlab.com",
  "registry.gitlab.com",
  "bitbucket.org",
  "api.bitbucket.org",
  "codeberg.org",
  "git.sr.ht",
]);

const GIT_SUFFIX_HOSTS = [
  ".github.com",
  ".githubusercontent.com",
  ".gitlab.com",
  ".bitbucket.org",
];

const PACKAGE_REGISTRY_EXACT_HOSTS = new Set([
  "registry.npmjs.org",
  "npmjs.org",
  "www.npmjs.com",
  "registry.yarnpkg.com",
  "pypi.org",
  "files.pythonhosted.org",
  "crates.io",
  "index.crates.io",
  "static.crates.io",
  "rubygems.org",
  "proxy.golang.org",
  "sum.golang.org",
  "repo.maven.apache.org",
  "packagist.org",
  "hub.docker.com",
  "registry-1.docker.io",
  "ghcr.io",
]);

const PACKAGE_REGISTRY_SUFFIX_HOSTS = [
  ".npmjs.org",
  ".pythonhosted.org",
  ".crates.io",
];

const BLOCKED_HOSTNAME_SUFFIXES = [
  ".localhost",
  ".local",
  ".localdomain",
  ".internal",
  ".home.arpa",
];

const BLOCKED_EXACT_HOSTNAMES = new Set([
  "localhost",
  "ip6-localhost",
  "ip6-loopback",
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "host.docker.internal",
  "gateway.docker.internal",
]);

export function normalizeHostname(raw) {
  let host = String(raw || "").trim().toLowerCase();
  if (!host) return "";
  if (host.startsWith("[") && host.endsWith("]")) {
    host = host.slice(1, -1);
  }
  // Strip trailing DNS root dot to prevent `github.com.` bypasses
  host = host.replace(/\.+$/, "");
  return host;
}

export function isGitHost(rawHostname) {
  const host = normalizeHostname(rawHostname);
  if (!host) return false;
  if (GIT_EXACT_HOSTS.has(host)) return true;
  return GIT_SUFFIX_HOSTS.some((suffix) => host.endsWith(suffix));
}

export function isPackageRegistryHost(rawHostname) {
  const host = normalizeHostname(rawHostname);
  if (!host) return false;
  if (PACKAGE_REGISTRY_EXACT_HOSTS.has(host)) return true;
  return PACKAGE_REGISTRY_SUFFIX_HOSTS.some((suffix) => host.endsWith(suffix));
}

export function isGitOrPackageHost(rawHostname) {
  return isGitHost(rawHostname) || isPackageRegistryHost(rawHostname);
}

function parseIpv4ToUint32(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = (value * 256) + n;
  }
  return value >>> 0;
}

function isBlockedIpv4(ip) {
  const n = parseIpv4ToUint32(ip);
  if (n === null) return true;
  const a = (n >>> 24) & 0xff;
  const b = (n >>> 16) & 0xff;
  const c = (n >>> 8) & 0xff;

  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8 (RFC1918)
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
  if (a === 127) return true; // 127.0.0.0/8 (loopback)
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 (link-local & cloud metadata 169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 (RFC1918 & Docker bridges)
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24
  if (a === 192 && b === 0 && c === 2) return true; // 192.0.2.0/24 (TEST-NET-1)
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 (RFC1918)
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 (benchmarking)
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 (TEST-NET-2)
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 (TEST-NET-3)
  if (a >= 224) return true; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + broadcast
  return false;
}

function expandIpv6Groups(rawIp) {
  const ip = String(rawIp || "").trim().toLowerCase().split("%")[0];
  if (!ip || net.isIPv6(ip) === false) return null;

  // Handle embedded IPv4 suffix (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
  const lastColon = ip.lastIndexOf(":");
  let normalized = ip;
  if (lastColon !== -1 && ip.slice(lastColon + 1).includes(".")) {
    const v4 = parseIpv4ToUint32(ip.slice(lastColon + 1));
    if (v4 === null) return null;
    const hi = ((v4 >>> 16) & 0xffff).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    normalized = `${ip.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":").filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":").filter(Boolean) : [];
  const missing = 8 - (left.length + right.length);
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    return null;
  }
  const full = [...left, ...Array(Math.max(0, missing)).fill("0"), ...right];
  if (full.length !== 8) return null;
  const groups = [];
  for (const g of full) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    groups.push(parseInt(g, 16));
  }
  return groups;
}

/**
 * Returns true if `ip` is private, loopback, link-local, metadata, multicast,
 * reserved, IPv4-mapped private, or invalid. Fail-closed.
 */
export function isBlockedIpAddress(rawIp) {
  const ip = String(rawIp || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!ip) return true;

  const ipVer = net.isIP(ip.split("%")[0]);
  if (ipVer === 4) {
    return isBlockedIpv4(ip);
  }
  if (ipVer === 6) {
    const g = expandIpv6Groups(ip);
    if (!g) return true;
    const isAllZero = g.every((v) => v === 0);
    if (isAllZero) return true; // ::
    const isLoopback = g.slice(0, 7).every((v) => v === 0) && g[7] === 1;
    if (isLoopback) return true; // ::1

    // IPv4-mapped ::ffff:0:0/96 or IPv4-compatible ::0:0/96 or NAT64 64:ff9b::/96
    const isV4Mapped =
      g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && (g[5] === 0xffff || g[5] === 0);
    const isNat64 =
      g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0;
    if (isV4Mapped || isNat64) {
      const embedded = `${(g[6] >>> 8) & 0xff}.${g[6] & 0xff}.${(g[7] >>> 8) & 0xff}.${g[7] & 0xff}`;
      return isBlockedIpv4(embedded);
    }

    if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 Unique Local (ULA)
    if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 Link-Local
    if ((g[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 Deprecated Site-Local
    if ((g[0] & 0xff00) === 0xff00) return true; // ff00::/8 Multicast
    if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // 2001:db8::/32 Documentation
    if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true; // 100::/64 Discard
    return false;
  }

  return true;
}

function hostMatchesAllowlistEntry(host, entry) {
  const cleanEntry = normalizeHostname(entry);
  if (!cleanEntry) return false;
  if (cleanEntry.startsWith("*.")) {
    const suffix = cleanEntry.slice(1); // `.example.com`
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return host === cleanEntry;
}

/**
 * Evaluates whether a target `(hostname, port)` is permitted under a job's policy
 * BEFORE DNS resolution. DNS IP checks are still enforced separately on every connect.
 */
export function evaluateHostPolicy(rawHostname, port, policy = {}) {
  const host = normalizeHostname(rawHostname);
  const numericPort = Number(port);
  if (!host || host.length > 253 || /[\s/\\@:?#]/.test(host)) {
    return { allowed: false, reason: "invalid_hostname" };
  }
  if (!Number.isInteger(numericPort) || numericPort < 1 || numericPort > 65535) {
    return { allowed: false, reason: "invalid_port" };
  }

  const allowedPorts = policy.allowHttp80 ? new Set([443, 80]) : new Set([443]);
  if (!allowedPorts.has(numericPort)) {
    return { allowed: false, reason: "port_not_allowed" };
  }

  // Always block raw IP literals (prevents bypassing hostname allowlists & hitting metadata IPs)
  if (net.isIP(host) !== 0) {
    return { allowed: false, reason: "raw_ip_blocked" };
  }

  if (
    BLOCKED_EXACT_HOSTNAMES.has(host) ||
    BLOCKED_HOSTNAME_SUFFIXES.some((s) => host.endsWith(s))
  ) {
    return { allowed: false, reason: "private_hostname_blocked" };
  }

  const engine = String(policy.engine || "codex").toLowerCase();
  const alwaysAllowed = new Set(["gigbotic.com"]);
  if (policy.mcpHost) {
    const h = normalizeHostname(policy.mcpHost);
    if (h) alwaysAllowed.add(h);
  }
  for (const h of ENGINE_LLM_HOSTS[engine] || []) {
    alwaysAllowed.add(h);
  }
  if (Array.isArray(policy.allowedUploadHosts)) {
    for (const h of policy.allowedUploadHosts) {
      const clean = normalizeHostname(h);
      if (clean && !BLOCKED_EXACT_HOSTNAMES.has(clean)) {
        alwaysAllowed.add(clean);
      }
    }
  }

  for (const entry of alwaysAllowed) {
    if (hostMatchesAllowlistEntry(host, entry)) {
      return { allowed: true, reason: "core_allowlist" };
    }
  }

  const networkPolicy = String(policy.networkPolicy || "locked").toLowerCase();
  if (networkPolicy === "locked") {
    return { allowed: false, reason: "network_locked" };
  }

  if (networkPolicy === "public_web") {
    if (isGitHost(host)) {
      return { allowed: false, reason: "git_host_blocked" };
    }
    if (isPackageRegistryHost(host)) {
      return { allowed: false, reason: "package_registry_blocked" };
    }
    return { allowed: true, reason: "public_web" };
  }

  if (networkPolicy === "public_web_and_git") {
    if (policy.allowExternalGitClone === false && isGitHost(host)) {
      return { allowed: false, reason: "git_host_blocked" };
    }
    return { allowed: true, reason: "public_web_and_git" };
  }

  return { allowed: false, reason: "unknown_network_policy" };
}

/**
 * Resolves `hostname` via DNS and guarantees EVERY returned IP is a non-private
 * public address before returning the pinned IP to connect to directly.
 */
export async function resolveAndVerifyPublicIp(hostname, lookupFn = dns.promises.lookup) {
  const host = normalizeHostname(hostname);
  if (!host || net.isIP(host) !== 0) {
    throw Object.assign(new Error(`Blocked host: ${hostname}`), { code: "BLOCKED_HOST" });
  }
  const records = await lookupFn(host, { all: true, verbatim: true });
  if (!Array.isArray(records) || records.length === 0) {
    throw Object.assign(new Error(`DNS lookup returned no addresses for ${host}`), {
      code: "DNS_EMPTY",
    });
  }
  for (const rec of records) {
    if (isBlockedIpAddress(rec.address)) {
      throw Object.assign(
        new Error(`Blocked private/loopback/metadata IP (${rec.address}) for ${host}`),
        { code: "BLOCKED_PRIVATE_IP", blockedIp: rec.address }
      );
    }
  }
  // Prefer IPv4 first for broad Docker bridge/host compatibility, else IPv6
  const chosen = records.find((r) => r.family === 4) || records[0];
  return { address: chosen.address, family: chosen.family };
}

function parseProxyToken(proxyAuthHeader) {
  const raw = String(proxyAuthHeader || "").trim();
  if (!raw.toLowerCase().startsWith("basic ")) return null;
  try {
    const decoded = Buffer.from(raw.slice(6).trim(), "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    if (idx === -1) return null;
    const user = decoded.slice(0, idx);
    const pass = decoded.slice(idx + 1);
    if (user !== "job" || !pass) return null;
    return pass;
  } catch {
    return null;
  }
}

function timingSafeLookupPolicy(policiesMap, candidateToken) {
  if (!candidateToken || typeof candidateToken !== "string") return null;
  const candBuf = Buffer.from(candidateToken, "utf8");
  for (const [token, entry] of policiesMap.entries()) {
    const tokBuf = Buffer.from(token, "utf8");
    if (tokBuf.length === candBuf.length && crypto.timingSafeEqual(tokBuf, candBuf)) {
      return entry;
    }
  }
  return null;
}

function parseConnectAuthority(authority) {
  const raw = String(authority || "").trim();
  if (!raw) return null;
  if (raw.startsWith("[")) {
    const end = raw.indexOf("]");
    if (end <= 1) return null;
    const host = raw.slice(1, end);
    const rest = raw.slice(end + 1);
    const port = rest.startsWith(":") ? Number(rest.slice(1)) : 443;
    return { host, port };
  }
  const idx = raw.lastIndexOf(":");
  if (idx === -1) return { host: raw, port: 443 };
  return { host: raw.slice(0, idx), port: Number(raw.slice(idx + 1)) };
}

/**
 * Creates a zero-dependency host-side HTTP/CONNECT allowlist proxy.
 * Bind strictly to the Docker bridge gateway IP (or `127.0.0.1` in tests).
 */
export function createEgressProxyServer(options = {}) {
  const bindHost = String(options.bindHost || "127.0.0.1");
  const requestedPort = Number.isInteger(options.port) ? options.port : 0;
  const lookupFn = options.lookupFn || dns.promises.lookup;
  const onBlocked = typeof options.onBlocked === "function" ? options.onBlocked : null;
  const connectTimeoutMs = Number(options.connectTimeoutMs || 10_000);

  /** @type {Map<string, { policy: any, sockets: Set<net.Socket> }>} */
  const activePolicies = new Map();
  let listenPort = null;
  let running = false;

  const notifyBlocked = (info) => {
    try {
      onBlocked?.(info);
    } catch {}
  };

  const server = http.createServer(async (req, res) => {
    const token = parseProxyToken(req.headers["proxy-authorization"]);
    const entry = timingSafeLookupPolicy(activePolicies, token);
    if (!entry) {
      res.writeHead(407, {
        "Proxy-Authenticate": 'Basic realm="gigbotic-sandbox-egress"',
        "Content-Type": "text/plain",
      });
      res.end("Proxy authentication required.\n");
      return;
    }

    let targetUrl;
    try {
      targetUrl = new URL(String(req.url || ""));
    } catch {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Invalid absolute proxy URL.\n");
      return;
    }
    if (targetUrl.protocol !== "http:" && targetUrl.protocol !== "https:") {
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end("Unsupported protocol.\n");
      return;
    }
    const port = targetUrl.port
      ? Number(targetUrl.port)
      : targetUrl.protocol === "https:"
        ? 443
        : 80;
    const verdict = evaluateHostPolicy(targetUrl.hostname, port, {
      ...entry.policy,
      allowHttp80: targetUrl.protocol === "http:" ? Boolean(entry.policy.allowHttp80) : false,
    });
    if (!verdict.allowed) {
      notifyBlocked({
        jobId: entry.policy.jobId,
        deliveryId: entry.policy.deliveryId,
        host: targetUrl.hostname,
        port,
        reason: verdict.reason,
        method: req.method,
      });
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end(`Gigbotic egress proxy blocked ${targetUrl.hostname}:${port} (${verdict.reason}).\n`);
      return;
    }

    let resolved;
    try {
      resolved = await resolveAndVerifyPublicIp(targetUrl.hostname, lookupFn);
    } catch (err) {
      notifyBlocked({
        jobId: entry.policy.jobId,
        deliveryId: entry.policy.deliveryId,
        host: targetUrl.hostname,
        port,
        reason: err?.code || "dns_blocked",
        method: req.method,
      });
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end(`Gigbotic egress proxy blocked ${targetUrl.hostname} (${err?.code || "dns_blocked"}).\n`);
      return;
    }

    const fwdHeaders = { ...req.headers };
    delete fwdHeaders["proxy-authorization"];
    delete fwdHeaders["proxy-connection"];
    fwdHeaders.host = targetUrl.host;

    const upstreamReq = http.request(
      {
        host: resolved.address,
        family: resolved.family,
        port,
        method: req.method,
        path: `${targetUrl.pathname}${targetUrl.search}`,
        headers: fwdHeaders,
        timeout: connectTimeoutMs,
      },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers);
        upstreamRes.pipe(res);
      }
    );
    upstreamReq.on("socket", (sock) => {
      entry.sockets.add(sock);
      sock.on("close", () => entry.sockets.delete(sock));
    });
    upstreamReq.on("error", () => {
      if (!res.headersSent) {
        res.writeHead(502, { "Content-Type": "text/plain" });
      }
      res.end("Upstream connection failed.\n");
    });
    req.pipe(upstreamReq);
  });

  server.on("connect", async (req, clientSocket, head) => {
    const rejectSocket = (statusLine, body = "") => {
      try {
        clientSocket.end(`HTTP/1.1 ${statusLine}\r\nConnection: close\r\n\r\n${body}`);
      } catch {}
    };

    const token = parseProxyToken(req.headers["proxy-authorization"]);
    const entry = timingSafeLookupPolicy(activePolicies, token);
    if (!entry) {
      rejectSocket(
        '407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="gigbotic-sandbox-egress"'
      );
      return;
    }

    const parsed = parseConnectAuthority(req.url);
    if (!parsed) {
      rejectSocket("400 Bad Request");
      return;
    }

    const verdict = evaluateHostPolicy(parsed.host, parsed.port, entry.policy);
    if (!verdict.allowed) {
      notifyBlocked({
        jobId: entry.policy.jobId,
        deliveryId: entry.policy.deliveryId,
        host: parsed.host,
        port: parsed.port,
        reason: verdict.reason,
        method: "CONNECT",
      });
      rejectSocket("403 Forbidden", `Blocked by Gigbotic egress policy (${verdict.reason})`);
      return;
    }

    let resolved;
    try {
      resolved = await resolveAndVerifyPublicIp(parsed.host, lookupFn);
    } catch (err) {
      notifyBlocked({
        jobId: entry.policy.jobId,
        deliveryId: entry.policy.deliveryId,
        host: parsed.host,
        port: parsed.port,
        reason: err?.code || "dns_blocked",
        method: "CONNECT",
      });
      rejectSocket("403 Forbidden", `Blocked by Gigbotic DNS guard (${err?.code || "dns_blocked"})`);
      return;
    }

    const upstream = net.connect({
      host: resolved.address,
      family: resolved.family,
      port: parsed.port,
    });
    upstream.setTimeout(connectTimeoutMs, () => {
      upstream.destroy(new Error("Upstream connect timeout"));
    });

    entry.sockets.add(upstream);
    entry.sockets.add(clientSocket);
    const untrack = () => {
      entry.sockets.delete(upstream);
      entry.sockets.delete(clientSocket);
    };

    upstream.once("connect", () => {
      upstream.setTimeout(0);
      try {
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head && head.length > 0) upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      } catch {
        upstream.destroy();
        clientSocket.destroy();
      }
    });

    upstream.on("error", () => {
      untrack();
      if (!clientSocket.destroyed) {
        rejectSocket("502 Bad Gateway");
      }
    });
    upstream.on("close", () => {
      untrack();
      if (!clientSocket.destroyed) clientSocket.destroy();
    });
    clientSocket.on("error", () => {
      untrack();
      if (!upstream.destroyed) upstream.destroy();
    });
    clientSocket.on("close", () => {
      untrack();
      if (!upstream.destroyed) upstream.destroy();
    });
  });

  return {
    async start() {
      if (running) return { host: bindHost, port: listenPort };
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(requestedPort, bindHost, () => {
          server.removeListener("error", reject);
          const addr = server.address();
          listenPort = typeof addr === "object" && addr ? addr.port : requestedPort;
          running = true;
          resolve();
        });
      });
      return { host: bindHost, port: listenPort };
    },
    async stop() {
      for (const [, entry] of activePolicies.entries()) {
        for (const sock of entry.sockets) {
          try { sock.destroy(); } catch {}
        }
        entry.sockets.clear();
      }
      activePolicies.clear();
      if (!running) return;
      running = false;
      await new Promise((resolve) => server.close(() => resolve()));
    },
    isRunning() {
      return running;
    },
    getListenAddress() {
      return running ? { host: bindHost, port: listenPort } : null;
    },
    registerJobPolicy(policy) {
      if (!running || !listenPort) {
        throw new Error("Egress proxy server must be started before registering job policies.");
      }
      const token = crypto.randomBytes(24).toString("hex");
      const entry = { policy: { ...policy }, sockets: new Set() };
      activePolicies.set(token, entry);
      const proxyUrl = `http://job:${token}@${bindHost}:${listenPort}`;
      return {
        token,
        proxyUrl,
        revoke() {
          activePolicies.delete(token);
          for (const sock of entry.sockets) {
            try { sock.destroy(); } catch {}
          }
          entry.sockets.clear();
        },
      };
    },
  };
}
