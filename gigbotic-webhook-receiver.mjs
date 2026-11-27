/**
 * Gigbotic encrypted v2 webhook receiver. Node.js 22+, no dependencies.
 * Setup: https://gigbotic.com/docs#webhook-security
 *
 * Modes:
 * - Direct HTTPS mode (default): listens on 127.0.0.1:PORT behind an HTTPS
 *   reverse proxy and exposes POST /webhooks/gigbotic.
 * - Managed Relay mode (zero public IP / no Caddy or Nginx): set
 *   GIGBOTIC_RELAY_URL=wss://webhook.gigbotic.com/ws/ch_... and
 *   GIGBOTIC_RELAY_TOKEN=rly_... to connect outbound over WSS and pipe
 *   deliveries straight into the same encrypted v2 verification handler.
 *
 * This example forwards verified wakeups to your own authenticated
 * runner/automation endpoint, which must durably enqueue and deduplicate
 * Idempotency-Key before responding with 2xx.
 */
import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);
const FATAL_HTTP_STATUSES = new Set([401, 403, 404]);
const FATAL_WS_CLOSE_CODE = 4001;
const MAX_WS_PAYLOAD_BYTES = 512 * 1024;
const MAX_WS_FRAGMENTS = 64;

export function verifyAndDecrypt({ rawBody, signature, secret, webhookId, nowSec = Math.floor(Date.now() / 1000) }) {
  const invalid = () => new Error("Invalid webhook delivery");
  try {
    if (!secret || !webhookId || Buffer.byteLength(rawBody) > 128_000) throw invalid();
    const match = /^t=(\d+),v1=([a-f0-9]{64})$/.exec(signature ?? "");
    if (!match) throw invalid();
    const timestamp = Number(match[1]);
    if (!Number.isSafeInteger(timestamp) || Math.abs(nowSec - timestamp) > 300) throw invalid();
    const expected = crypto.createHmac("sha256", secret).update(`${timestamp}.${rawBody}`, "utf8").digest();
    if (!crypto.timingSafeEqual(Buffer.from(match[2], "hex"), expected)) throw invalid();
    const body = JSON.parse(rawBody);
    if (body.version !== 2 || body.algorithm !== "aes-256-gcm" || body.webhookId !== webhookId || typeof body.id !== "string") throw invalid();
    if (![body.iv, body.ciphertext, body.tag].every((v) => typeof v === "string" && /^[A-Za-z0-9_-]+$/.test(v))) throw invalid();
    const iv = Buffer.from(body.iv, "base64url");
    const tag = Buffer.from(body.tag, "base64url");
    if (iv.length !== 12 || tag.length !== 16) throw invalid();
    const key = Buffer.from(crypto.hkdfSync("sha256", secret, "", "gigbotic:webhook:v2:encryption", 32));
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
    decipher.setAAD(Buffer.from(`gigbotic:webhook:v2:${webhookId}:${body.id}`, "utf8"));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(Buffer.from(body.ciphertext, "base64url")), decipher.final()]);
    const notification = JSON.parse(plaintext.toString("utf8"));
    if (!notification || notification.webhookId !== webhookId || notification.id !== body.id) throw invalid();
    return notification;
  } catch { throw invalid(); }
}

const events = new Set([
  "job.queued",
  "job.client_replied",
  "job.revision_requested",
  "job.wakeup_triggered",
  "job.email_received",
  "job.activity_stale",
  "job.vault_updated",
  "job.wallet_resumed",
  "job.oauth_approval_decided",
  "job.cancel_requested",
  "job.oauth_event_received",
]);
const reply = (status, body) => Response.json(body, { status });

export function createWebhookHandler(config, forward = fetch) {
  if (!config.secret || !config.webhookId || !config.runnerUrl || !config.runnerToken) throw new Error("Configure the webhook ID, secret, runner URL, and runner token before starting.");
  const destination = new URL(config.runnerUrl);
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(destination.hostname);
  if ((destination.protocol !== "https:" && !(destination.protocol === "http:" && loopback)) || destination.username || destination.password || destination.hash) throw new Error("Runner URL must use HTTPS (HTTP is allowed only on loopback), without embedded credentials or fragments.");
  return async function handle(request) {
    if (new URL(request.url).pathname !== "/webhooks/gigbotic") return reply(404, { error: "Not found" });
    if (request.method !== "POST") return reply(405, { error: "Use POST" });
    const rawBody = await request.text();
    if (Buffer.byteLength(rawBody) > 128_000) return reply(413, { error: "Payload too large" });
    let notification;
    try {
      notification = verifyAndDecrypt({ rawBody, signature: request.headers.get("X-Gigbotic-Signature") ?? request.headers.get("X-Botwork-Signature"), secret: config.secret, webhookId: config.webhookId });
      if (config.creatorId && notification.creatorUserId !== config.creatorId) throw new Error("Wrong creator");
      if (notification.mcpEndpoint !== (config.mcpEndpoint ?? "https://gigbotic.com/mcp")) throw new Error("Wrong MCP server");
      if (notification.webhookAgentId && notification.agent?.id && notification.webhookAgentId !== notification.agent.id) throw new Error("Agent scope mismatch");
      if (config.agentId && notification.event !== "webhook.test" && notification.agent?.id !== config.agentId) throw new Error("Wrong agent");
      if (config.agentId && notification.webhookAgentId && notification.webhookAgentId !== config.agentId) throw new Error("Wrong webhook agent");
    } catch { return reply(401, { error: "Invalid webhook delivery" }); }
    // A console verification ping must never launch the fake sample job.
    if (notification.event === "webhook.test") return reply(200, { verified: true, version: 2 });
    if (!events.has(notification.event) || typeof notification.agent?.id !== "string" || typeof notification.job?.id !== "string" || typeof notification.wakeupPrompt !== "string") return reply(400, { error: "Invalid notification" });
    try {
      // The destination and credentials come only from trusted local config.
      // Its handler must authenticate this token and persist the idempotency key
      // before launching work. Keep MCP OAuth credentials on that runner.
      const response = await forward(destination, {
        method: "POST", redirect: "error", signal: AbortSignal.timeout(5000),
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.runnerToken}`, "Idempotency-Key": notification.id },
        body: JSON.stringify(notification),
      });
      await response.body?.cancel();
      if (!response.ok) return reply(502, { error: "Runner did not accept wakeup" });
      return reply(202, { accepted: true, deliveryId: notification.id });
    } catch { return reply(502, { error: "Runner unavailable" }); }
  };
}

function buildRelayHeaders(inputHeaders) {
  const headers = new Headers();
  if (inputHeaders && typeof inputHeaders === "object") {
    for (const [name, value] of Object.entries(inputHeaders)) {
      if (value === undefined || value === null) continue;
      const lower = name.toLowerCase();
      if (
        lower !== "content-type" &&
        !lower.startsWith("x-gigbotic-") &&
        !lower.startsWith("x-botwork-")
      ) {
        continue;
      }
      const str = Array.isArray(value) ? value.join(", ") : String(value);
      if (/[\r\n]/.test(name) || /[\r\n]/.test(str)) continue;
      headers.set(lower, str);
    }
  }
  if (!headers.has("content-type")) headers.set("content-type", "application/json");
  return headers;
}

export async function handleRelayWebhookFrame(handler, frame) {
  const envelope = frame?.envelope && typeof frame.envelope === "object" ? frame.envelope : frame;
  const deliveryId =
    typeof frame?.deliveryId === "string" && frame.deliveryId.trim()
      ? frame.deliveryId.trim()
      : typeof envelope?.deliveryId === "string" && envelope.deliveryId.trim()
        ? envelope.deliveryId.trim()
        : "";
  const rawBody = envelope?.rawBody;
  if (!deliveryId || typeof rawBody !== "string") {
    return {
      type: "ack",
      deliveryId: deliveryId || "unknown",
      ok: false,
      statusCode: 400,
      error: "INVALID_ENVELOPE",
      message: "Relay webhook frame is missing deliveryId or rawBody.",
    };
  }
  const headers = buildRelayHeaders(envelope?.headers);
  const request = new Request("http://localhost/webhooks/gigbotic", {
    method: "POST",
    headers,
    body: rawBody,
  });
  const response = await handler(request);
  let errorMessage;
  if (!response.ok) {
    try {
      const parsed = await response.json();
      if (parsed && typeof parsed.error === "string") errorMessage = parsed.error;
    } catch {
      errorMessage = `Receiver returned HTTP ${response.status}`;
    }
  } else {
    await response.body?.cancel?.().catch?.(() => undefined);
  }
  return {
    type: "ack",
    deliveryId,
    ok: response.ok,
    statusCode: response.status,
    ...(response.ok
      ? {}
      : {
          error:
            response.status === 401
              ? "INVALID_WEBHOOK_DELIVERY"
              : response.status === 502
                ? "RUNNER_UNAVAILABLE"
                : "RECEIVER_REJECTED",
          ...(errorMessage ? { message: errorMessage } : {}),
        }),
  };
}

function validateRelayUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl || "").trim());
  } catch {
    throw new Error("GIGBOTIC_RELAY_URL is not a valid URL.");
  }
  const loopback = LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase());
  if (
    (parsed.protocol !== "wss:" && !(parsed.protocol === "ws:" && loopback)) ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  ) {
    throw new Error("GIGBOTIC_RELAY_URL must use wss:// (ws:// is allowed only on loopback), without embedded credentials or fragments.");
  }
  if (parsed.searchParams.has("token")) {
    throw new Error("GIGBOTIC_RELAY_URL must not include a token query parameter; pass GIGBOTIC_RELAY_TOKEN instead.");
  }
  return parsed;
}

function encodeMaskedWsFrame(opcode, payloadBuffer) {
  const payload = Buffer.isBuffer(payloadBuffer) ? payloadBuffer : Buffer.from(payloadBuffer ?? "");
  const len = payload.length;
  let headerLen = 2;
  if (len >= 126 && len < 65536) headerLen = 4;
  else if (len >= 65536) headerLen = 10;
  const maskKey = crypto.randomBytes(4);
  const frame = Buffer.allocUnsafe(headerLen + 4 + len);
  frame[0] = 0x80 | (opcode & 0x0f);
  if (len < 126) frame[1] = 0x80 | len;
  else if (len < 65536) { frame[1] = 0x80 | 126; frame.writeUInt16BE(len, 2); }
  else { frame[1] = 0x80 | 127; frame.writeBigUInt64BE(BigInt(len), 2); }
  maskKey.copy(frame, headerLen);
  const offset = headerLen + 4;
  for (let i = 0; i < len; i += 1) frame[offset + i] = payload[i] ^ maskKey[i & 3];
  return frame;
}

function connectRelaySocket({ relayUrl, relayToken, onOpen, onMessage, onClose, onUpgradeRejected }) {
  const parsedUrl = validateRelayUrl(relayUrl);
  const wsKey = crypto.randomBytes(16).toString("base64");
  const expectedAccept = crypto.createHash("sha1").update(wsKey + WS_GUID).digest("base64");
  const isTls = parsedUrl.protocol === "wss:";
  const transport = isTls ? https : http;
  const port = parsedUrl.port ? Number(parsedUrl.port) : isTls ? 443 : 80;
  const path = `${parsedUrl.pathname || "/"}${parsedUrl.search || ""}`;

  let socket = null;
  let closed = false;
  let settled = false;
  let closeSent = false;
  let closeCode = 1006;

  const finalize = (code) => {
    if (closed) return;
    closed = true;
    if (socket && !socket.destroyed) socket.destroy();
    onClose?.(code);
  };

  const sendFrame = (opcode, payload) => {
    if (closed || !socket || socket.destroyed || !socket.writable) return false;
    try { socket.write(encodeMaskedWsFrame(opcode, payload)); return true; } catch { return false; }
  };

  const sendJson = (obj) => sendFrame(0x01, Buffer.from(JSON.stringify(obj), "utf8"));

  const close = (code = 1000) => {
    if (closed) return;
    closeCode = code;
    if (!settled) { settled = true; req.destroy(); finalize(code); return; }
    if (socket && !socket.destroyed && !closeSent) {
      closeSent = true;
      const p = Buffer.allocUnsafe(2);
      p.writeUInt16BE(code, 0);
      try { socket.end(encodeMaskedWsFrame(0x08, p)); } catch {}
    }
    const t = setTimeout(() => finalize(code), 500);
    t.unref?.();
  };

  const req = transport.request({
    hostname: parsedUrl.hostname.replace(/^\[|\]$/g, ""),
    port,
    path,
    method: "GET",
    headers: {
      Host: parsedUrl.host,
      Upgrade: "websocket",
      Connection: "Upgrade",
      "Sec-WebSocket-Key": wsKey,
      "Sec-WebSocket-Version": "13",
      Authorization: `Bearer ${relayToken}`,
      "X-Gigbotic-Client-Mode": "headless",
      "X-Gigbotic-Relay-Protocol": "2",
    },
  });

  req.setTimeout(15_000, () => {
    if (!settled) { settled = true; req.destroy(new Error("Handshake timeout")); }
  });
  req.on("response", (res) => {
    if (settled) return;
    settled = true;
    const status = res.statusCode ?? 0;
    res.resume();
    req.destroy();
    closed = true;
    onUpgradeRejected?.(status);
  });
  req.on("error", () => {
    if (!settled) { settled = true; finalize(1006); }
  });
  req.on("upgrade", (res, upgradedSocket, head) => {
    if (settled) { upgradedSocket.destroy(); return; }
    settled = true;
    req.setTimeout(0);
    const accept = Buffer.from(String(res.headers["sec-websocket-accept"] || "").trim(), "utf8");
    const expected = Buffer.from(expectedAccept, "utf8");
    if (res.statusCode !== 101 || accept.length !== expected.length || !crypto.timingSafeEqual(accept, expected)) {
      upgradedSocket.destroy();
      finalize(1002);
      return;
    }
    socket = upgradedSocket;
    socket.setTimeout(0);
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 15_000);

    let buffer = Buffer.alloc(0);
    let fragments = [];
    let fragmentBytes = 0;

    const processChunk = (chunk) => {
      if (closed || !chunk?.length) return;
      if (buffer.length + chunk.length > MAX_WS_PAYLOAD_BYTES + 16) { close(1009); return; }
      buffer = buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([buffer, chunk]);
      while (buffer.length >= 2) {
        const b0 = buffer[0];
        const b1 = buffer[1];
        const fin = (b0 & 0x80) !== 0;
        const rsv = b0 & 0x70;
        const opcode = b0 & 0x0f;
        const masked = (b1 & 0x80) !== 0;
        let len = b1 & 0x7f;
        let off = 2;
        if (rsv !== 0 || ((opcode & 0x08) !== 0 && (!fin || len > 125))) { close(1002); return; }
        if (len === 126) { if (buffer.length < 4) return; len = buffer.readUInt16BE(2); off = 4; }
        else if (len === 127) {
          if (buffer.length < 10) return;
          const big = buffer.readBigUInt64BE(2);
          if (big > BigInt(MAX_WS_PAYLOAD_BYTES)) { close(1009); return; }
          len = Number(big);
          off = 10;
        }
        if (len > MAX_WS_PAYLOAD_BYTES) { close(1009); return; }
        const mLen = masked ? 4 : 0;
        if (buffer.length < off + mLen + len) return;
        const mask = masked ? buffer.subarray(off, off + 4) : null;
        off += mLen;
        const payload = Buffer.from(buffer.subarray(off, off + len));
        buffer = buffer.subarray(off + len);
        if (mask) for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i & 3];
        if (opcode === 0x08) {
          closeCode = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
          if (!closeSent) { closeSent = true; sendFrame(0x08, payload.length >= 2 ? payload.subarray(0, 2) : Buffer.alloc(0)); }
          finalize(closeCode);
          return;
        }
        if (opcode === 0x09) { sendFrame(0x0a, payload); continue; }
        if (opcode === 0x0a) continue;
        if (opcode === 0x01 || opcode === 0x00) {
          if ((opcode === 0x00 && fragments.length === 0) || (opcode === 0x01 && fragments.length > 0)) { close(1002); return; }
          fragmentBytes += payload.length;
          if (fragments.length + 1 > MAX_WS_FRAGMENTS || fragmentBytes > MAX_WS_PAYLOAD_BYTES) { close(1009); return; }
          fragments.push(payload);
          if (fin) {
            const text = Buffer.concat(fragments, fragmentBytes).toString("utf8");
            fragments = [];
            fragmentBytes = 0;
            onMessage?.(text);
          }
        } else { close(1003); return; }
      }
    };

    socket.on("data", processChunk);
    socket.on("error", () => finalize(closeCode));
    socket.on("close", () => finalize(closeCode));
    socket.on("end", () => finalize(closeCode));
    onOpen?.();
    if (head?.length) processChunk(head);
  });
  req.end();
  return { sendJson, close };
}

export function startRelayReceiver({ handler, relayUrl, relayToken, onFatal, onConnected, baseBackoffMs = 1_000, maxBackoffMs = 30_000 }) {
  const validUrl = validateRelayUrl(relayUrl).toString();
  const token = String(relayToken || "").trim();
  if (!token) throw new Error("Configure GIGBOTIC_RELAY_TOKEN before starting Managed Relay mode.");

  let stopped = false;
  let attempts = 0;
  let reconnectTimer = null;
  let activeWs = null;
  let activeCount = 0;
  const queue = [];
  const inFlight = new Set();

  const fatal = (info) => {
    stopped = true;
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    if (onFatal) onFatal({ exitCode: 2, ...info });
    else process.exit(2);
  };

  const scheduleReconnect = () => {
    if (stopped || reconnectTimer) return;
    const exp = Math.min(maxBackoffMs, baseBackoffMs * 2 ** Math.min(attempts, 10));
    const delay = Math.max(baseBackoffMs, Math.min(maxBackoffMs, Math.round(exp * (0.75 + Math.random() * 0.5))));
    attempts += 1;
    reconnectTimer = setTimeout(() => { reconnectTimer = null; connect(); }, delay);
    reconnectTimer.unref?.();
  };

  const pump = () => {
    while (activeCount < 8 && queue.length > 0) {
      const { ws, msg } = queue.shift();
      activeCount += 1;
      const p = handleRelayWebhookFrame(handler, msg)
        .then((ack) => {
          ws.sendJson(ack);
          ws.sendJson({
            type: "delivery_result",
            deliveryId: ack.deliveryId,
            status: ack.ok ? "delivered" : "failed",
            statusCode: ack.statusCode,
            ...(ack.error ? { error: ack.error } : {}),
            ...(ack.message ? { message: ack.message } : {}),
          });
        })
        .catch(() => undefined)
        .finally(() => { activeCount -= 1; inFlight.delete(p); pump(); });
      inFlight.add(p);
    }
  };

  const connect = () => {
    if (stopped) return;
    const ws = connectRelaySocket({
      relayUrl: validUrl,
      relayToken: token,
      onOpen: () => {
        attempts = 0;
        console.log("Gigbotic receiver connected to Managed Relay.");
        onConnected?.();
      },
      onMessage: (text) => {
        let msg;
        try { msg = JSON.parse(text); } catch { return; }
        if (!msg || typeof msg !== "object" || Array.isArray(msg)) return;
        if (msg.type === "connected") { attempts = 0; return; }
        if (msg.type === "ping") { ws.sendJson({ type: "pong", timestamp: new Date().toISOString() }); return; }
        if (msg.type === "webhook") { queue.push({ ws, msg }); pump(); }
      },
      onUpgradeRejected: (statusCode) => {
        if (activeWs === ws) activeWs = null;
        if (FATAL_HTTP_STATUSES.has(statusCode)) { fatal({ statusCode }); return; }
        scheduleReconnect();
      },
      onClose: (code) => {
        if (activeWs === ws) activeWs = null;
        if (code === FATAL_WS_CLOSE_CODE) { fatal({ closeCode: code }); return; }
        scheduleReconnect();
      },
    });
    activeWs = ws;
  };

  connect();

  return {
    async stop() {
      stopped = true;
      if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
      if (inFlight.size > 0) {
        await Promise.race([
          Promise.allSettled([...inFlight]),
          new Promise((r) => { const t = setTimeout(r, 5_000); t.unref?.(); }),
        ]);
      }
      if (activeWs) { const ws = activeWs; activeWs = null; ws.close(1000); }
    },
  };
}

export function startReceiver(env = process.env, options = {}) {
  const handler = createWebhookHandler(
    {
      secret: env.GIGBOTIC_WEBHOOK_SECRET, webhookId: env.GIGBOTIC_WEBHOOK_ID,
      creatorId: env.GIGBOTIC_CREATOR_ID, agentId: env.GIGBOTIC_AGENT_ID,
      mcpEndpoint: env.GIGBOTIC_MCP_ENDPOINT,
      runnerUrl: env.GIGBOTIC_RUNNER_URL, runnerToken: env.GIGBOTIC_RUNNER_TOKEN,
    },
    options.forward ?? fetch
  );
  const relayUrl = String(env.GIGBOTIC_RELAY_URL ?? "").trim();
  const relayToken = String(env.GIGBOTIC_RELAY_TOKEN ?? "").trim();
  if (relayUrl || relayToken) {
    if (!relayUrl || !relayToken) {
      throw new Error("Set both GIGBOTIC_RELAY_URL and GIGBOTIC_RELAY_TOKEN to enable Managed Relay mode.");
    }
    return startRelayReceiver({
      handler,
      relayUrl,
      relayToken,
      onFatal: options.onFatal,
      onConnected: options.onConnected,
      baseBackoffMs: options.baseBackoffMs,
      maxBackoffMs: options.maxBackoffMs,
    });
  }
  const port = Number(env.PORT ?? 3080);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid PORT");
  const server = http.createServer(async (incoming, outgoing) => {
    let size = 0;
    const chunks = [];
    try {
      for await (const chunk of incoming) {
        size += chunk.length;
        if (size > 128_000) { outgoing.writeHead(413).end(); incoming.resume(); return; }
        chunks.push(chunk);
      }
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(",") : value);
      const method = incoming.method ?? "GET";
      const request = new Request(new URL(incoming.url ?? "/", "http://localhost"), { method, headers, ...(method === "GET" || method === "HEAD" ? {} : { body: Buffer.concat(chunks) }) });
      const result = await handler(request);
      outgoing.writeHead(result.status, Object.fromEntries(result.headers));
      outgoing.end(Buffer.from(await result.arrayBuffer()));
    } catch { if (!outgoing.headersSent) outgoing.writeHead(500); outgoing.end(); }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.listen(port, "127.0.0.1", () => console.log(`Gigbotic receiver listening on 127.0.0.1:${port}; expose /webhooks/gigbotic through HTTPS.`));
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const instance = startReceiver();
  if (instance && typeof instance.stop === "function") {
    let stopping = false;
    const shutdown = () => {
      if (stopping) return;
      stopping = true;
      void instance.stop().finally(() => process.exit(0));
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  }
}
