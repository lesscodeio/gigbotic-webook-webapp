#!/usr/bin/env node
/**
 * Gigbotic Managed Relay headless bridge. Node.js 22+, zero npm dependencies.
 * Setup: https://gigbotic.com/docs#webhook-security
 *
 * Zero-trust raw encrypted bytes forwarding:
 * - Connects outbound over WSS to wss://webhook.gigbotic.com/ws/ch_...
 *   using Authorization: Bearer <rly_...> (never puts the token in the URL).
 * - Forwards untouched UTF-8 rawBody + whitelisted X-Gigbotic-* / X-Botwork-* /
 *   Content-Type headers to your local webhook receiver (never holds whsec_...).
 * - Sends explicit RFC 6455 masked ack and delivery_result frames so Creator
 *   Studio reports exact downstream 2xx/401/502 outcomes.
 *
 * Usage:
 *   GIGBOTIC_RELAY_URL=wss://webhook.gigbotic.com/ws/ch_... \
 *   GIGBOTIC_RELAY_TOKEN=rly_... \
 *   node gigbotic-relay-bridge.mjs --forward http://127.0.0.1:3080/webhooks/gigbotic
 */
import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const DEFAULT_FORWARD_URL = "http://127.0.0.1:3080/webhooks/gigbotic";
const DEFAULT_FORWARD_TIMEOUT_MS = 8_000;
const DEFAULT_MAX_CONCURRENCY = 8;
const DEFAULT_BASE_BACKOFF_MS = 1_000;
const DEFAULT_MAX_BACKOFF_MS = 30_000;
const DEFAULT_DRAIN_TIMEOUT_MS = 5_000;
const HANDSHAKE_TIMEOUT_MS = 15_000;
const MAX_WS_PAYLOAD_BYTES = 512 * 1024;
const MAX_WS_FRAGMENTS = 64;
const FATAL_HTTP_STATUSES = new Set([401, 403, 404]);
const FATAL_WS_CLOSE_CODE = 4001;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

function isLoopbackHostname(hostname) {
  return LOOPBACK_HOSTS.has(String(hostname || "").toLowerCase());
}

export function validateForwardUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    throw new Error("Forward URL must be a non-empty URL.");
  }
  let destination;
  try {
    destination = new URL(rawUrl.trim());
  } catch {
    throw new Error("Forward URL is not a valid URL.");
  }
  const loopback = isLoopbackHostname(destination.hostname);
  if (
    (destination.protocol !== "https:" && !(destination.protocol === "http:" && loopback)) ||
    destination.username ||
    destination.password ||
    destination.hash
  ) {
    throw new Error(
      "Forward URL must use HTTPS (HTTP is allowed only on loopback 127.0.0.1, localhost, or ::1), without embedded credentials or fragments."
    );
  }
  return destination;
}

export function validateRelayUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    throw new Error("Configure GIGBOTIC_RELAY_URL (or --url) before starting.");
  }
  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error("Relay URL is not a valid URL.");
  }
  const loopback = isLoopbackHostname(parsed.hostname);
  if (
    (parsed.protocol !== "wss:" && !(parsed.protocol === "ws:" && loopback)) ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  ) {
    throw new Error(
      "Relay URL must use wss:// (ws:// is allowed only on loopback), without embedded credentials or fragments."
    );
  }
  if (parsed.searchParams.has("token")) {
    throw new Error(
      "Relay URL must not include a token query parameter; pass the token via GIGBOTIC_RELAY_TOKEN or --token."
    );
  }
  return parsed;
}

export function parseBridgeConfig(argvOrEnv = process.argv.slice(2), envArg = process.env) {
  let argv = [];
  let env = envArg;
  if (Array.isArray(argvOrEnv)) {
    argv = argvOrEnv;
  } else if (argvOrEnv && typeof argvOrEnv === "object") {
    if ("argv" in argvOrEnv || "env" in argvOrEnv) {
      argv = Array.isArray(argvOrEnv.argv) ? argvOrEnv.argv : [];
      env = argvOrEnv.env ?? process.env;
    } else {
      env = argvOrEnv;
    }
  }

  const cli = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (typeof arg !== "string" || !arg.startsWith("--")) continue;
    const eqIdx = arg.indexOf("=");
    const flag = eqIdx >= 0 ? arg.slice(0, eqIdx) : arg;
    const nextValue = () => {
      if (eqIdx >= 0) return arg.slice(eqIdx + 1);
      if (i + 1 >= argv.length) throw new Error(`Missing value for ${flag}`);
      i += 1;
      return argv[i];
    };
    if (flag === "--url") cli.relayUrl = nextValue();
    else if (flag === "--token") cli.relayToken = nextValue();
    else if (flag === "--forward") cli.forwardUrl = nextValue();
    else if (flag === "--timeout-ms") cli.timeoutMs = nextValue();
    else if (flag === "--max-concurrency") cli.maxConcurrency = nextValue();
    else throw new Error(`Unknown CLI flag: ${flag}`);
  }

  const relayUrl = validateRelayUrl(cli.relayUrl ?? env?.GIGBOTIC_RELAY_URL ?? "").toString();
  const relayToken = String(cli.relayToken ?? env?.GIGBOTIC_RELAY_TOKEN ?? "").trim();
  if (!relayToken) {
    throw new Error("Configure GIGBOTIC_RELAY_TOKEN (or --token) before starting.");
  }
  const forwardUrl = validateForwardUrl(
    cli.forwardUrl ?? env?.GIGBOTIC_FORWARD_URL ?? DEFAULT_FORWARD_URL
  ).toString();

  const rawTimeout = cli.timeoutMs ?? env?.GIGBOTIC_FORWARD_TIMEOUT_MS ?? String(DEFAULT_FORWARD_TIMEOUT_MS);
  const timeoutMs = Number(rawTimeout);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
    throw new Error("Forward timeout (--timeout-ms / GIGBOTIC_FORWARD_TIMEOUT_MS) must be an integer between 100 and 120000.");
  }

  const rawConcurrency = cli.maxConcurrency ?? env?.GIGBOTIC_MAX_CONCURRENCY ?? String(DEFAULT_MAX_CONCURRENCY);
  const maxConcurrency = Number(rawConcurrency);
  if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1 || maxConcurrency > 64) {
    throw new Error("Max concurrency must be an integer between 1 and 64.");
  }

  return { relayUrl, relayToken, forwardUrl, timeoutMs, maxConcurrency };
}

function filterForwardedHeaders(inputHeaders) {
  const headers = {};
  if (inputHeaders && typeof inputHeaders === "object") {
    for (const [rawName, rawValue] of Object.entries(inputHeaders)) {
      if (rawValue === undefined || rawValue === null) continue;
      const lower = rawName.toLowerCase();
      if (
        lower !== "content-type" &&
        !lower.startsWith("x-gigbotic-") &&
        !lower.startsWith("x-botwork-")
      ) {
        continue;
      }
      const value = Array.isArray(rawValue) ? rawValue.join(", ") : String(rawValue);
      if (/[\r\n]/.test(rawName) || /[\r\n]/.test(value)) continue;
      headers[lower] = value;
    }
  }
  if (!headers["content-type"]) {
    headers["content-type"] = "application/json";
  }
  return headers;
}

async function readSafeErrorSummary(response) {
  try {
    const text = (await response.text()).slice(0, 512).trim();
    if (!text) return `Downstream receiver returned HTTP ${response.status}.`;
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed.error === "string" && parsed.error.trim()) {
        return parsed.error.trim().slice(0, 200);
      }
      if (parsed && typeof parsed.message === "string" && parsed.message.trim()) {
        return parsed.message.trim().slice(0, 200);
      }
    } catch {
      // Plain text error body
    }
    return `Downstream receiver returned HTTP ${response.status}.`;
  } catch {
    return `Downstream receiver returned HTTP ${response.status}.`;
  }
}

export async function forwardRawEnvelope({
  forwardUrl,
  envelope,
  timeoutMs = DEFAULT_FORWARD_TIMEOUT_MS,
  fetchImpl = fetch,
}) {
  const destination = validateForwardUrl(
    forwardUrl instanceof URL ? forwardUrl.toString() : forwardUrl
  );
  const rawBody = envelope?.rawBody;
  if (typeof rawBody !== "string") {
    return {
      ok: false,
      statusCode: 400,
      error: "INVALID_ENVELOPE",
      message: "Relay webhook frame is missing rawBody.",
    };
  }
  const headers = filterForwardedHeaders(envelope?.headers);
  const bodyBytes = Buffer.from(rawBody, "utf8");
  try {
    const response = await fetchImpl(destination.toString(), {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
      headers,
      body: bodyBytes,
    });
    if (response.ok) {
      await response.body?.cancel?.().catch?.(() => undefined);
      return {
        ok: true,
        statusCode: response.status,
      };
    }
    const message = await readSafeErrorSummary(response);
    return {
      ok: false,
      statusCode: response.status,
      error: "DOWNSTREAM_REJECTED",
      message,
    };
  } catch (err) {
    const isTimeout =
      err && typeof err === "object" && (err.name === "TimeoutError" || err.name === "AbortError");
    return {
      ok: false,
      statusCode: 502,
      error: "DOWNSTREAM_UNREACHABLE",
      message: isTimeout
        ? `Local receiver timed out after ${timeoutMs}ms.`
        : "Local receiver is unreachable.",
    };
  }
}

/**
 * RFC 6455 §5.3 client-to-server masked WebSocket frame encoder.
 */
function encodeMaskedWsFrame(opcode, payloadBuffer) {
  const payload = Buffer.isBuffer(payloadBuffer)
    ? payloadBuffer
    : Buffer.from(payloadBuffer ?? "");
  const len = payload.length;
  let headerLen = 2;
  if (len >= 126 && len < 65536) headerLen = 4;
  else if (len >= 65536) headerLen = 10;

  const maskKey = crypto.randomBytes(4);
  const frame = Buffer.allocUnsafe(headerLen + 4 + len);
  frame[0] = 0x80 | (opcode & 0x0f);
  if (len < 126) {
    frame[1] = 0x80 | len;
  } else if (len < 65536) {
    frame[1] = 0x80 | 126;
    frame.writeUInt16BE(len, 2);
  } else {
    frame[1] = 0x80 | 127;
    frame.writeBigUInt64BE(BigInt(len), 2);
  }
  maskKey.copy(frame, headerLen);
  const dataOffset = headerLen + 4;
  for (let i = 0; i < len; i += 1) {
    frame[dataOffset + i] = payload[i] ^ maskKey[i & 3];
  }
  return frame;
}

function timingSafeEqualStr(a, b) {
  const bufA = Buffer.from(String(a), "utf8");
  const bufB = Buffer.from(String(b), "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Minimal zero-dependency RFC 6455 WebSocket client over node:https / node:http.
 * Sends Authorization: Bearer + Gigbotic relay protocol v2 headers without
 * ever placing tokens in the URL query string.
 */
export function connectRelayWebSocket({
  relayUrl,
  relayToken,
  onOpen,
  onMessage,
  onClose,
  onUpgradeRejected,
  onError,
}) {
  const parsedUrl = validateRelayUrl(relayUrl);
  const wsKey = crypto.randomBytes(16).toString("base64");
  const expectedAccept = crypto
    .createHash("sha1")
    .update(wsKey + WS_GUID)
    .digest("base64");

  const isTls = parsedUrl.protocol === "wss:";
  const transport = isTls ? https : http;
  const port = parsedUrl.port ? Number(parsedUrl.port) : isTls ? 443 : 80;
  const path = `${parsedUrl.pathname || "/"}${parsedUrl.search || ""}`;

  let socket = null;
  let closed = false;
  let handshakeSettled = false;
  let closeFrameSent = false;
  let lastCloseCode = 1006;
  let lastCloseReason = "";

  const finalizeClose = (code, reason) => {
    if (closed) return;
    closed = true;
    if (socket && !socket.destroyed) {
      socket.destroy();
    }
    onClose?.({ code, reason });
  };

  const sendRawFrame = (opcode, payload) => {
    if (closed || !socket || socket.destroyed || !socket.writable) return false;
    try {
      socket.write(encodeMaskedWsFrame(opcode, payload));
      return true;
    } catch {
      return false;
    }
  };

  const sendJson = (payload) => {
    return sendRawFrame(0x01, Buffer.from(JSON.stringify(payload), "utf8"));
  };

  const close = (code = 1000, reason = "") => {
    if (closed) return;
    lastCloseCode = code;
    lastCloseReason = reason;
    if (!handshakeSettled) {
      handshakeSettled = true;
      req.destroy();
      finalizeClose(code, reason);
      return;
    }
    if (socket && !socket.destroyed && !closeFrameSent) {
      closeFrameSent = true;
      const reasonBuf = Buffer.from(String(reason).slice(0, 120), "utf8");
      const closePayload = Buffer.allocUnsafe(2 + reasonBuf.length);
      closePayload.writeUInt16BE(code, 0);
      reasonBuf.copy(closePayload, 2);
      try {
        socket.end(encodeMaskedWsFrame(0x08, closePayload));
      } catch {
        // Ignore write error during close
      }
    }
    const timer = setTimeout(() => finalizeClose(code, reason), 500);
    timer.unref?.();
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

  req.setTimeout(HANDSHAKE_TIMEOUT_MS, () => {
    if (handshakeSettled) return;
    handshakeSettled = true;
    req.destroy(new Error("WebSocket handshake timed out."));
  });

  req.on("response", (res) => {
    if (handshakeSettled) return;
    handshakeSettled = true;
    const statusCode = res.statusCode ?? 0;
    res.resume();
    req.destroy();
    closed = true;
    onUpgradeRejected?.(statusCode);
  });

  req.on("error", (err) => {
    if (!handshakeSettled) {
      handshakeSettled = true;
      onError?.(err);
      finalizeClose(1006, err?.message || "Connection error");
    }
  });

  req.on("upgrade", (res, upgradedSocket, head) => {
    if (handshakeSettled) {
      upgradedSocket.destroy();
      return;
    }
    handshakeSettled = true;
    req.setTimeout(0);

    const acceptHeader = String(res.headers["sec-websocket-accept"] || "").trim();
    if (res.statusCode !== 101 || !timingSafeEqualStr(acceptHeader, expectedAccept)) {
      upgradedSocket.destroy();
      const err = new Error("Invalid Sec-WebSocket-Accept response from relay.");
      onError?.(err);
      finalizeClose(1002, err.message);
      return;
    }

    socket = upgradedSocket;
    socket.setTimeout(0);
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 15_000);

    let buffer = Buffer.alloc(0);
    let fragments = [];
    let fragmentBytes = 0;

    const failProtocol = (code = 1002, reason = "Protocol error") => {
      buffer = Buffer.alloc(0);
      fragments = [];
      fragmentBytes = 0;
      close(code, reason);
    };

    const processChunk = (chunk) => {
      if (closed || !chunk || chunk.length === 0) return;
      if (buffer.length + chunk.length > MAX_WS_PAYLOAD_BYTES + 16) {
        failProtocol(1009, "Frame too large");
        return;
      }
      buffer = buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([buffer, chunk]);

      while (buffer.length >= 2) {
        const firstByte = buffer[0];
        const secondByte = buffer[1];
        const fin = (firstByte & 0x80) !== 0;
        const rsv = firstByte & 0x70;
        const opcode = firstByte & 0x0f;
        const masked = (secondByte & 0x80) !== 0;
        let payloadLen = secondByte & 0x7f;
        let offset = 2;

        if (rsv !== 0) {
          failProtocol(1002, "Unexpected reserved bits");
          return;
        }

        const isControl = (opcode & 0x08) !== 0;
        if (isControl && (!fin || payloadLen > 125)) {
          failProtocol(1002, "Invalid control frame");
          return;
        }

        if (payloadLen === 126) {
          if (buffer.length < 4) return;
          payloadLen = buffer.readUInt16BE(2);
          offset = 4;
        } else if (payloadLen === 127) {
          if (buffer.length < 10) return;
          const bigLen = buffer.readBigUInt64BE(2);
          if (bigLen > BigInt(MAX_WS_PAYLOAD_BYTES)) {
            failProtocol(1009, "Payload too large");
            return;
          }
          payloadLen = Number(bigLen);
          offset = 10;
        }

        if (payloadLen > MAX_WS_PAYLOAD_BYTES) {
          failProtocol(1009, "Payload too large");
          return;
        }

        const maskLen = masked ? 4 : 0;
        if (buffer.length < offset + maskLen + payloadLen) return;
        const maskKey = masked ? buffer.subarray(offset, offset + 4) : null;
        offset += maskLen;
        const payload = Buffer.from(buffer.subarray(offset, offset + payloadLen));
        buffer = buffer.subarray(offset + payloadLen);

        if (maskKey) {
          for (let i = 0; i < payload.length; i += 1) {
            payload[i] ^= maskKey[i & 3];
          }
        }

        if (opcode === 0x08) {
          let code = 1005;
          let reason = "";
          if (payload.length >= 2) {
            code = payload.readUInt16BE(0);
            reason = payload.subarray(2).toString("utf8");
          }
          lastCloseCode = code;
          lastCloseReason = reason;
          if (!closeFrameSent) {
            closeFrameSent = true;
            const ackPayload = payload.length >= 2 ? payload.subarray(0, 2) : Buffer.alloc(0);
            sendRawFrame(0x08, ackPayload);
          }
          finalizeClose(code, reason);
          return;
        }

        if (opcode === 0x09) {
          sendRawFrame(0x0a, payload);
          continue;
        }

        if (opcode === 0x0a) {
          continue;
        }

        if (opcode === 0x01 || opcode === 0x00) {
          if (opcode === 0x00 && fragments.length === 0) {
            failProtocol(1002, "Unexpected continuation frame");
            return;
          }
          if (opcode === 0x01 && fragments.length > 0) {
            failProtocol(1002, "Unfinished fragmented message");
            return;
          }
          fragmentBytes += payload.length;
          if (fragments.length + 1 > MAX_WS_FRAGMENTS || fragmentBytes > MAX_WS_PAYLOAD_BYTES) {
            failProtocol(1009, "Message too large");
            return;
          }
          fragments.push(payload);
          if (fin) {
            const text = Buffer.concat(fragments, fragmentBytes).toString("utf8");
            fragments = [];
            fragmentBytes = 0;
            onMessage?.(text);
          }
        } else {
          failProtocol(1003, "Unsupported opcode");
          return;
        }
      }
    };

    socket.on("data", processChunk);
    socket.on("error", (err) => {
      onError?.(err);
      finalizeClose(lastCloseCode, err?.message || "Socket error");
    });
    socket.on("close", () => finalizeClose(lastCloseCode, lastCloseReason));
    socket.on("end", () => finalizeClose(lastCloseCode, lastCloseReason));

    onOpen?.();
    if (head && head.length > 0) {
      processChunk(head);
    }
  });

  req.end();

  return {
    sendJson,
    sendPing: (payload = Buffer.alloc(0)) => sendRawFrame(0x09, payload),
    close,
  };
}

function computeBackoffMs(attempt, baseMs, maxMs) {
  const exp = Math.min(maxMs, baseMs * 2 ** Math.min(attempt, 10));
  const jitter = 0.75 + Math.random() * 0.5;
  return Math.max(baseMs, Math.min(maxMs, Math.round(exp * jitter)));
}

export function createRelayBridge(config, deps = {}) {
  const relayUrl = validateRelayUrl(config?.relayUrl).toString();
  const relayToken = String(config?.relayToken ?? "").trim();
  if (!relayToken) {
    throw new Error("Configure relayToken before creating the relay bridge.");
  }
  const forwardUrl = validateForwardUrl(config?.forwardUrl ?? DEFAULT_FORWARD_URL).toString();
  const timeoutMs = Number(config?.timeoutMs ?? DEFAULT_FORWARD_TIMEOUT_MS);
  const maxConcurrency = Number(config?.maxConcurrency ?? DEFAULT_MAX_CONCURRENCY);
  const baseBackoffMs = Number(config?.baseBackoffMs ?? DEFAULT_BASE_BACKOFF_MS);
  const maxBackoffMs = Number(config?.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS);
  const drainTimeoutMs = Number(config?.drainTimeoutMs ?? DEFAULT_DRAIN_TIMEOUT_MS);

  const fetchImpl = deps.fetchImpl ?? fetch;
  const log = deps.onLog ?? ((msg) => console.log(`[gigbotic-relay-bridge] ${msg}`));

  let stopped = false;
  let connected = false;
  let reconnectAttempts = 0;
  let reconnectTimer = null;
  let activeWs = null;
  let fatalExitCode = null;
  let activeCount = 0;
  const pendingQueue = [];
  const inFlightPromises = new Set();

  const triggerFatal = (info) => {
    if (fatalExitCode !== null) return;
    fatalExitCode = 2;
    stopped = true;
    connected = false;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    log(`Fatal relay rejection (${info.reason}); exiting with code 2.`);
    deps.onFatal?.({ exitCode: 2, ...info });
  };

  const scheduleReconnect = (reason) => {
    if (stopped || fatalExitCode !== null) return;
    if (reconnectTimer) return;
    const delayMs = computeBackoffMs(reconnectAttempts, baseBackoffMs, maxBackoffMs);
    reconnectAttempts += 1;
    log(`Disconnected (${reason}). Reconnecting in ${delayMs}ms...`);
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, delayMs);
    reconnectTimer.unref?.();
  };

  const processDelivery = async (ws, msg) => {
    const envelope = msg.envelope && typeof msg.envelope === "object" ? msg.envelope : msg;
    const deliveryId =
      typeof msg.deliveryId === "string" && msg.deliveryId.trim()
        ? msg.deliveryId.trim()
        : typeof envelope?.deliveryId === "string" && envelope.deliveryId.trim()
          ? envelope.deliveryId.trim()
          : "";
    if (!deliveryId) return;

    const outcome = await forwardRawEnvelope({
      forwardUrl,
      envelope,
      timeoutMs,
      fetchImpl,
    });

    const ackFrame = {
      type: "ack",
      deliveryId,
      ok: outcome.ok,
      statusCode: outcome.statusCode,
      ...(outcome.error ? { error: outcome.error } : {}),
      ...(outcome.message ? { message: outcome.message } : {}),
    };
    const resultFrame = {
      type: "delivery_result",
      deliveryId,
      status: outcome.ok ? "delivered" : "failed",
      statusCode: outcome.statusCode,
      ...(outcome.error ? { error: outcome.error } : {}),
      ...(outcome.message ? { message: outcome.message } : {}),
    };

    ws.sendJson(ackFrame);
    ws.sendJson(resultFrame);
    log(`Delivery ${deliveryId} -> HTTP ${outcome.statusCode} (${outcome.ok ? "ok" : outcome.error})`);
    deps.onDelivery?.({ deliveryId, outcome, ackFrame, resultFrame });
  };

  const pumpQueue = () => {
    while (activeCount < maxConcurrency && pendingQueue.length > 0) {
      const next = pendingQueue.shift();
      activeCount += 1;
      const promise = processDelivery(next.ws, next.msg)
        .catch(() => undefined)
        .finally(() => {
          activeCount -= 1;
          inFlightPromises.delete(promise);
          pumpQueue();
        });
      inFlightPromises.add(promise);
    }
  };

  const connect = () => {
    if (stopped || fatalExitCode !== null) return;
    const ws = connectRelayWebSocket({
      relayUrl,
      relayToken,
      onOpen: () => {
        connected = true;
        reconnectAttempts = 0;
        log(`Connected to Managed Relay; forwarding to ${forwardUrl}`);
        deps.onConnected?.();
      },
      onMessage: (rawText) => {
        let msg;
        try {
          msg = JSON.parse(rawText);
        } catch {
          return;
        }
        if (!msg || typeof msg !== "object" || Array.isArray(msg)) return;
        if (msg.type === "connected") {
          reconnectAttempts = 0;
          return;
        }
        if (msg.type === "ping") {
          ws.sendJson({ type: "pong", timestamp: new Date().toISOString() });
          return;
        }
        if (msg.type === "webhook") {
          pendingQueue.push({ ws, msg });
          pumpQueue();
        }
      },
      onUpgradeRejected: (statusCode) => {
        connected = false;
        activeWs = null;
        if (FATAL_HTTP_STATUSES.has(statusCode)) {
          triggerFatal({
            statusCode,
            reason: `HTTP ${statusCode} — relay token revoked, rotated, or channel not found`,
          });
          return;
        }
        deps.onDisconnected?.({ statusCode });
        scheduleReconnect(`HTTP ${statusCode}`);
      },
      onClose: ({ code, reason }) => {
        connected = false;
        if (activeWs === ws) activeWs = null;
        if (code === FATAL_WS_CLOSE_CODE) {
          triggerFatal({
            closeCode: code,
            reason: reason || "WS 4001 — relay token revoked or rotated",
          });
          return;
        }
        deps.onDisconnected?.({ code, reason });
        scheduleReconnect(`WS close ${code}`);
      },
      onError: () => {
        // Handled through onClose / onUpgradeRejected
      },
    });
    activeWs = ws;
  };

  const start = () => {
    stopped = false;
    fatalExitCode = null;
    connect();
  };

  const stop = async () => {
    stopped = true;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (inFlightPromises.size > 0) {
      await Promise.race([
        Promise.allSettled([...inFlightPromises]),
        new Promise((resolveTimer) => {
          const t = setTimeout(resolveTimer, drainTimeoutMs);
          t.unref?.();
        }),
      ]);
    }
    connected = false;
    if (activeWs) {
      const ws = activeWs;
      activeWs = null;
      ws.close(1000, "shutdown");
    }
  };

  const getState = () => ({
    connected,
    stopped,
    inFlight: activeCount,
    queued: pendingQueue.length,
    reconnectAttempts,
    fatalExitCode,
  });

  return { start, stop, getState };
}

function runCli() {
  let config;
  try {
    config = parseBridgeConfig(process.argv.slice(2), process.env);
  } catch (err) {
    console.error(`[gigbotic-relay-bridge] ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }

  const bridge = createRelayBridge(config, {
    onFatal: ({ exitCode }) => {
      process.exit(exitCode ?? 2);
    },
  });

  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    void bridge.stop().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  bridge.start();
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runCli();
}
