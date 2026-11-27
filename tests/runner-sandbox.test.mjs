import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  createEgressProxyServer,
  evaluateHostPolicy,
  isBlockedIpAddress,
  isGitOrPackageHost,
  resolveAndVerifyPublicIp,
} from "../egress-proxy.mjs";
import {
  buildAgySessionSettings,
  buildAuthoritativeSystemPrompt,
  buildCodexIsolatedConfigToml,
  buildDockerContainerName,
  buildDockerRunArgs,
  buildHardenedCliInvocation,
  buildRunnerSecurityTelemetry,
  buildSanitizedChildEnv,
  computeBundleSha256,
  normalizeExecutionPolicy,
  prefetchPinnedCoreFiles,
  prepareHardenedJobEnvironment,
} from "../runner-sandbox.mjs";

const sha256 = (s) => crypto.createHash("sha256").update(s, "utf8").digest("hex");

describe("Layer 4 — CLI Sandbox Flag Matrix (zero --dangerously-* flags)", () => {
  const engines = ["codex", "claude", "agy"];
  const modes = ["mcp_only", "read_only", "workspace_write"];

  for (const engine of engines) {
    for (const sandboxMode of modes) {
      it(`${engine} under ${sandboxMode} never uses dangerous bypass flags`, () => {
        const policy = normalizeExecutionPolicy({
          executionPolicy: {
            sandboxMode,
            networkPolicy: sandboxMode === "workspace_write" ? "public_web" : "locked",
            allowShell: sandboxMode === "workspace_write",
          },
        });
        const inv = buildHardenedCliInvocation({
          engine,
          bin: `/usr/local/bin/${engine}`,
          model: "test-model",
          prompt: "hello",
          workDir: "/workspace",
          systemPromptPath: "/run/gigbotic/system-prompt.md",
          mcpConfigPath: "/run/gigbotic/mcp.json",
          agySettingsPath: "/run/gigbotic/agy-settings.json",
          executionPolicy: policy,
        });

        assert.ok(
          !inv.args.includes("--dangerously-bypass-approvals-and-sandbox"),
          `${engine}/${sandboxMode} must never pass --dangerously-bypass-approvals-and-sandbox`
        );
        assert.ok(
          !inv.args.includes("--dangerously-skip-permissions"),
          `${engine}/${sandboxMode} must never pass --dangerously-skip-permissions`
        );

        if (engine === "codex") {
          assert.ok(inv.args.includes("exec"));
          assert.ok(inv.args.includes("--ephemeral"));
          if (sandboxMode === "mcp_only") {
            assert.equal(inv.args[inv.args.indexOf("-s") + 1], "read-only");
            assert.ok(inv.args.includes("shell_tool"));
            assert.ok(inv.args.includes("unified_exec"));
          } else if (sandboxMode === "workspace_write") {
            assert.equal(inv.args[inv.args.indexOf("-s") + 1], "workspace-write");
          }
        }

        if (engine === "claude") {
          assert.ok(inv.args.includes("--append-system-prompt-file"));
          assert.ok(inv.args.includes("--strict-mcp-config"));
          assert.ok(inv.args.includes("--setting-sources"));
          assert.ok(inv.args.includes("--system-prompt-snapshot"));
          if (sandboxMode === "mcp_only") {
            assert.equal(inv.args[inv.args.indexOf("--tools") + 1], "");
            assert.equal(inv.args[inv.args.indexOf("--allowedTools") + 1], "mcp__gigbotic__*");
            assert.equal(inv.args[inv.args.indexOf("--permission-mode") + 1], "dontAsk");
            assert.equal(inv.args[inv.args.indexOf("--permission-prompts") + 1], "none");
          } else if (sandboxMode === "read_only") {
            assert.ok(inv.args.includes("--restricted"));
            assert.equal(inv.args[inv.args.indexOf("--tools") + 1], "Read,Glob,Grep");
          }
        }

        if (engine === "agy") {
          assert.ok(inv.args.includes("--sandbox"));
          assert.ok(inv.args.includes("--new-project"));
          assert.ok(inv.args.includes("--settings"));
          assert.ok(!inv.args.includes("--mode"));
          const agySettings = buildAgySessionSettings({ executionPolicy: policy });
          assert.equal(agySettings.mcpServers, undefined, "agy --settings rejects mcpServers");
          assert.ok(agySettings.permissions.allow.includes("mcp(gigbotic/*)"));
          if (sandboxMode === "mcp_only") {
            assert.ok(agySettings.permissions.deny.includes("command(*)"));
            assert.ok(agySettings.permissions.deny.includes("write_file(*)"));
          }
        }
      });
    }
  }

  it("Codex isolated config.toml embeds developer_instructions, disables shell in mcp_only, and preserves egress proxy in Docker workspace_write", () => {
    const policy = normalizeExecutionPolicy({
      executionPolicy: { sandboxMode: "mcp_only", networkPolicy: "locked" },
    });
    const toml = buildCodexIsolatedConfigToml({
      mcpEndpoint: "https://gigbotic.com/mcp",
      executionPolicy: policy,
      systemPromptText: 'Tier-1 "Immutable" Policy\nAGENTS.md content',
      model: "gpt-5",
    });
    assert.match(toml, /approval_policy = "never"/);
    assert.match(toml, /sandbox_mode = "read-only"/);
    assert.match(toml, /shell_tool = false/);
    assert.match(toml, /unified_exec = false/);
    assert.match(toml, /developer_instructions = """/);
    assert.match(toml, /inherit = "none"/);
    assert.match(toml, /\[mcp_servers\.gigbotic\]/);
    assert.match(toml, /GIGBOTIC_MCP_TOKEN/);
    assert.match(toml, /default_tools_approval_mode = "approve"/);

    const wsPolicy = normalizeExecutionPolicy({
      executionPolicy: { sandboxMode: "workspace_write", networkPolicy: "public_web", allowShell: true },
    });
    const dockerToml = buildCodexIsolatedConfigToml({
      mcpEndpoint: "https://gigbotic.com/mcp",
      executionPolicy: wsPolicy,
      systemPromptText: "sys",
      inDocker: true,
      proxyUrl: "http://job:tok@172.18.0.1:3455",
    });
    assert.match(dockerToml, /sandbox_mode = "danger-full-access"/);
    assert.match(dockerToml, /HTTPS_PROXY = "http:\/\/job:tok@172\.18\.0\.1:3455"/);
    const nativeToml = buildCodexIsolatedConfigToml({
      mcpEndpoint: "https://gigbotic.com/mcp",
      executionPolicy: wsPolicy,
      systemPromptText: "sys",
      inDocker: false,
    });
    assert.match(nativeToml, /sandbox_mode = "workspace-write"/);
  });

  it("Agy prepareHardenedJobEnvironment writes job-scoped MCP to .gemini/config/mcp_config.json and omits mcpServers from agy-settings.json", () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gb-agy-env-"));
    try {
      const policy = normalizeExecutionPolicy({
        executionPolicy: { sandboxMode: "workspace_write", networkPolicy: "public_web", allowShell: true },
      });
      const envSetup = prepareHardenedJobEnvironment({
        isolatedRoot: path.join(tmpRoot, "iso"),
        metaRoot: path.join(tmpRoot, "meta"),
        realHomeDir: path.join(tmpRoot, "empty-home"),
        jobId: "job_agy_1",
        deliveryId: "whd_1",
        engine: "agy",
        model: "",
        mcpEndpoint: "https://gigbotic.com/mcp",
        jobMcpToken: "bw_job_agy_secret",
        executionPolicy: policy,
        coreFiles: { required: false, loaded: false, files: [], manifest: [] },
        systemPromptText: "sys",
        inDocker: true,
      });
      const settingsJson = JSON.parse(fs.readFileSync(envSetup.agySettingsPath, "utf8"));
      assert.equal(settingsJson.mcpServers, undefined);
      assert.equal(settingsJson.enableTerminalSandbox, false);
      assert.equal(settingsJson.toolPermission, "always-proceed");
      const nativeSettings = buildAgySessionSettings({ executionPolicy: policy, inDocker: false });
      assert.equal(nativeSettings.enableTerminalSandbox, true);
      assert.equal(nativeSettings.toolPermission, "proceed-in-sandbox");
      const mcpCfg = JSON.parse(
        fs.readFileSync(path.join(envSetup.fakeHomeDir, ".gemini", "config", "mcp_config.json"), "utf8")
      );
      assert.equal(mcpCfg.mcpServers.gigbotic.serverUrl, "https://gigbotic.com/mcp");
      assert.equal(mcpCfg.mcpServers.gigbotic.headers.Authorization, "Bearer bw_job_agy_secret");
      const cliSettings = JSON.parse(
        fs.readFileSync(path.join(envSetup.fakeHomeDir, ".gemini", "antigravity-cli", "settings.json"), "utf8")
      );
      assert.deepEqual(cliSettings.trustedWorkspaces, ["/workspace"]);
      envSetup.cleanup();
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it("normalizeExecutionPolicy lets local cap tighten cloud policy but never weaken it", () => {
    const tightened = normalizeExecutionPolicy(
      { executionPolicy: { sandboxMode: "workspace_write", networkPolicy: "public_web_and_git", allowShell: true } },
      { maxSandboxMode: "mcp_only", maxNetworkPolicy: "locked" }
    );
    assert.equal(tightened.sandboxMode, "mcp_only");
    assert.equal(tightened.networkPolicy, "locked");
    assert.equal(tightened.allowShell, false);
    assert.equal(tightened.allowExternalGitClone, false);

    // Cannot weaken cloud mcp_only via local defaultSandboxMode
    const preserved = normalizeExecutionPolicy(
      { agent: { executionPolicy: { sandboxMode: "mcp_only", networkPolicy: "locked" } } },
      { defaultSandboxMode: "workspace_write" }
    );
    assert.equal(preserved.sandboxMode, "mcp_only");
    assert.equal(preserved.allowShell, false);
  });
});

describe("Layer 4 — Environment Sanitization & Fake $HOME", () => {
  it("buildSanitizedChildEnv strips all host secrets and enforces fake HOME + empty PATH in mcp_only", () => {
    const dirtyHostEnv = {
      PATH: "/usr/local/bin:/usr/bin:/bin:/opt/secret",
      HOME: "/home/creator",
      LANG: "en_US.UTF-8",
      AWS_SECRET_ACCESS_KEY: "aws-secret",
      DATABASE_URL: "postgres://prod",
      STRIPE_SECRET_KEY: "sk_live_xxx",
      OPENAI_API_KEY: "sk-openai-xxx",
      ANTHROPIC_API_KEY: "sk-ant-xxx",
      GITHUB_TOKEN: "ghp_xxx",
      SSH_AUTH_SOCK: "/tmp/ssh-agent.sock",
      GIGBOTIC_CONSOLE_PASSWORD: "supersecretpassword",
      WEBHOOK_SIGNING_SECRET: "whsec_xxx",
    };

    const sanitized = buildSanitizedChildEnv(dirtyHostEnv, {
      sandboxMode: "mcp_only",
      fakeHomeDir: "/tmp/fake-home-job1",
      tmpDir: "/tmp/job1-tmp",
      codexHome: "/tmp/fake-home-job1/.codex",
      jobId: "job_123",
      mcpEndpoint: "https://gigbotic.com/mcp",
      jobMcpToken: "bw_job_tok",
      inDocker: false,
    });

    assert.equal(sanitized.HOME, "/tmp/fake-home-job1");
    assert.equal(sanitized.CODEX_HOME, "/tmp/fake-home-job1/.codex");
    assert.equal(sanitized.GIGBOTIC_MCP_TOKEN, "bw_job_tok");
    if (process.platform !== "win32") {
      assert.equal(sanitized.PATH, "");
    }
    for (const secretKey of [
      "AWS_SECRET_ACCESS_KEY",
      "DATABASE_URL",
      "STRIPE_SECRET_KEY",
      "OPENAI_API_KEY",
      "ANTHROPIC_API_KEY",
      "GITHUB_TOKEN",
      "SSH_AUTH_SOCK",
      "GIGBOTIC_CONSOLE_PASSWORD",
      "WEBHOOK_SIGNING_SECRET",
    ]) {
      assert.equal(sanitized[secretKey], undefined, `${secretKey} must be stripped`);
    }
  });
});

describe("Layer 3 — Core Files Pre-Fetch, SHA-256 Cache & Hardened Workspace", () => {
  it("prefetches pinned core files, verifies SHA-256, writes 0444 AGENTS.md + 0555 workDir + external mcp.json", async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gb-sandbox-test-"));
    try {
      const fakeRealHome = path.join(tmpRoot, "real-home");
      fs.mkdirSync(path.join(fakeRealHome, ".ssh"), { recursive: true });
      fs.writeFileSync(path.join(fakeRealHome, ".ssh", "id_ed25519"), "SECRET_SSH_KEY");
      fs.mkdirSync(path.join(fakeRealHome, ".codex"), { recursive: true });
      fs.writeFileSync(path.join(fakeRealHome, ".codex", "auth.json"), '{"token":"ok"}');
      fs.writeFileSync(path.join(fakeRealHome, ".codex", "AGENTS.md"), "HOST_GLOBAL_AGENTS_MUST_NOT_LEAK");

      const agentsContent = "# PagePilot — LinkedIn-Only Agent\nNever clone git repos or make videos.\n";
      const fileSha = sha256(agentsContent);
      const manifest = [
        {
          path: "AGENTS.md",
          file_kind: "instruction",
          is_entrypoint: true,
          load_policy: "always",
          sha256: fileSha,
          size_bytes: Buffer.byteLength(agentsContent),
        },
      ];
      const bundleHash = computeBundleSha256(manifest);
      const cacheRoot = path.join(tmpRoot, "cache");

      const calls = [];
      const mockFetch = async (_url, init) => {
        const body = JSON.parse(init.body);
        calls.push(body.params.arguments);
        const isHit = body.params.arguments.if_none_match === bundleHash;
        const payload = isHit
          ? {
              agent_id: "agt_pagepilot",
              job_id: "job_test1",
              agent_version: 3,
              required: true,
              unchanged: true,
              acknowledged: true,
              bundle_hash: bundleHash,
              entrypoint_path: "AGENTS.md",
              manifest,
              files: [],
            }
          : {
              agent_id: "agt_pagepilot",
              job_id: "job_test1",
              agent_version: 3,
              required: true,
              unchanged: false,
              acknowledged: true,
              bundle_hash: bundleHash,
              entrypoint_path: "AGENTS.md",
              manifest,
              files: [{ ...manifest[0], content: agentsContent }],
            };
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: body.id,
            result: { content: [{ type: "text", text: JSON.stringify(payload) }] },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      };

      const telemetry = buildRunnerSecurityTelemetry({
        sandboxDriver: "cli_sandbox",
        sandboxMode: "mcp_only",
        egressProxyActive: false,
      });

      // Cold fetch
      const first = await prefetchPinnedCoreFiles({
        mcpEndpoint: "https://gigbotic.com/mcp",
        jobMcpToken: "bw_job_secret",
        agentId: "agt_pagepilot",
        jobId: "job_test1",
        coreFilesMeta: { required: true, agentVersion: 3, bundleHash },
        workerReference: "managed_relay_codex_job_test1",
        runnerSecurity: telemetry,
        cacheRoot,
        fetchFn: mockFetch,
      });
      assert.equal(first.loaded, true);
      assert.equal(first.fromCache, false);
      assert.equal(calls[0].if_none_match, undefined);
      assert.equal(calls[0].runner_security.sandbox_enforced, true);

      // Warm cache hit sends if_none_match
      const second = await prefetchPinnedCoreFiles({
        mcpEndpoint: "https://gigbotic.com/mcp",
        jobMcpToken: "bw_job_secret",
        agentId: "agt_pagepilot",
        jobId: "job_test1",
        coreFilesMeta: { required: true, agentVersion: 3, bundleHash },
        workerReference: "managed_relay_codex_job_test1",
        runnerSecurity: telemetry,
        cacheRoot,
        fetchFn: mockFetch,
      });
      assert.equal(second.fromCache, true);
      assert.equal(calls[1].if_none_match, bundleHash);

      // Prepare hardened workspace
      const policy = normalizeExecutionPolicy({
        executionPolicy: { sandboxMode: "mcp_only", networkPolicy: "locked" },
      });
      const sysPrompt = buildAuthoritativeSystemPrompt({
        executionPolicy: policy,
        coreFiles: second,
        jobId: "job_test1",
        agentId: "agt_pagepilot",
        workerReference: "managed_relay_codex_job_test1",
        agentName: "PagePilot",
      });
      assert.match(sysPrompt, /TIER-1 IMMUTABLE PLATFORM SECURITY/);
      assert.match(sysPrompt, /PagePilot — LinkedIn-Only Agent/);

      const envSetup = prepareHardenedJobEnvironment({
        isolatedRoot: path.join(tmpRoot, "isolated"),
        metaRoot: path.join(tmpRoot, "meta"),
        realHomeDir: fakeRealHome,
        jobId: "job_test1",
        deliveryId: "whd_abc",
        engine: "codex",
        model: "gpt-5",
        mcpEndpoint: "https://gigbotic.com/mcp",
        jobMcpToken: "bw_job_secret",
        executionPolicy: policy,
        coreFiles: second,
        systemPromptText: sysPrompt,
        inDocker: true,
      });

      // Verify AGENTS.md is 0444, workDir is 0555, mcp.json is OUTSIDE workDir, fakeHome has NO .ssh or host AGENTS.md
      const agentsPath = path.join(envSetup.workDir, "AGENTS.md");
      assert.equal(fs.readFileSync(agentsPath, "utf8"), agentsContent);
      assert.equal(fs.existsSync(path.join(envSetup.workDir, ".mcp.json")), false);
      assert.equal(fs.existsSync(envSetup.mcpConfigPath), true);
      assert.equal(fs.existsSync(path.join(envSetup.fakeHomeDir, ".ssh")), false);
      assert.equal(fs.existsSync(path.join(envSetup.fakeHomeDir, ".codex", "AGENTS.md")), false);
      assert.equal(fs.existsSync(path.join(envSetup.fakeHomeDir, ".codex", "auth.json")), true);
      if (process.platform !== "win32") {
        assert.equal(fs.statSync(agentsPath).mode & 0o777, 0o444);
        assert.equal(fs.statSync(envSetup.workDir).mode & 0o777, 0o555);
      }

      // Verify Docker run args include security flags & optional GPUs
      const dockerArgs = buildDockerRunArgs({
        containerName: buildDockerContainerName("job_test1", "whd_abc"),
        image: "gigbotic-runner:latest",
        gpus: "all",
        workDir: envSetup.workDir,
        fakeHomeDir: envSetup.fakeHomeDir,
        systemPromptPath: envSetup.systemPromptPath,
        mcpConfigPath: envSetup.mcpConfigPath,
        readOnlyBindMounts: envSetup.readOnlyBindMounts,
        executionPolicy: policy,
        jobId: "job_test1",
        deliveryId: "whd_abc",
        workerReference: "managed_relay_codex_job_test1",
        mcpEndpoint: "https://gigbotic.com/mcp",
        jobMcpToken: "bw_job_secret",
        proxyUrl: "http://job:tok@172.30.0.1:3455",
        cliCommand: "codex",
        cliArgs: ["exec", "-s", "read-only", "-"],
      });
      assert.ok(dockerArgs.includes("--read-only"));
      assert.ok(dockerArgs.includes("--cap-drop=ALL"));
      assert.ok(dockerArgs.includes("no-new-privileges:true"));
      assert.ok(dockerArgs.includes("--gpus"));
      assert.ok(dockerArgs.includes("all"));
      assert.ok(dockerArgs.some((a) => a.endsWith(":/workspace/AGENTS.md:ro")));
      assert.ok(dockerArgs.some((a) => a.endsWith(":/workspace:ro")));

      envSetup.cleanup();
      assert.equal(fs.existsSync(envSetup.metaDir), false);
    } finally {
      // Unlock before rmSync
      try { fs.chmodSync(path.join(tmpRoot, "isolated", "job_test1"), 0o700); } catch {}
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it("fails closed when required cloud core files hash mismatches", async () => {
    const mockFetch = async () =>
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: "1",
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  required: true,
                  bundle_hash: "deadbeef",
                  manifest: [],
                  files: [],
                }),
              },
            ],
          },
        }),
        { status: 200 }
      );

    await assert.rejects(
      () =>
        prefetchPinnedCoreFiles({
          mcpEndpoint: "https://gigbotic.com/mcp",
          jobMcpToken: "bw_job_secret",
          agentId: "agt_1",
          jobId: "job_1",
          coreFilesMeta: { required: true, agentVersion: 1, bundleHash: "expected_sha" },
          cacheRoot: path.join(os.tmpdir(), "gb-unused-cache"),
          fetchFn: mockFetch,
        }),
      /CORE_FILES_PREFETCH_FAILED/
    );
  });
});

describe("Layer 4 — Host-Side Egress Allowlist Proxy & SSRF / DNS-Rebinding Guard", () => {
  it("isBlockedIpAddress blocks loopback, RFC1918, cloud metadata, and IPv6 private/mapped IPs", () => {
    const blocked = [
      "127.0.0.1",
      "127.255.255.254",
      "10.0.0.1",
      "172.16.0.1",
      "172.31.255.254",
      "192.168.1.10",
      "169.254.169.254",
      "100.64.0.1",
      "0.0.0.0",
      "224.0.0.1",
      "::1",
      "::",
      "fc00::1",
      "fd12:3456::1",
      "fe80::1",
      "::ffff:127.0.0.1",
      "::ffff:169.254.169.254",
      "::ffff:10.0.0.5",
      "not-an-ip",
    ];
    for (const ip of blocked) {
      assert.equal(isBlockedIpAddress(ip), true, `${ip} MUST be blocked`);
    }

    const allowed = ["93.184.216.34", "1.1.1.1", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"];
    for (const ip of allowed) {
      assert.equal(isBlockedIpAddress(ip), false, `${ip} should be allowed`);
    }
  });

  it("enforces 3-tier networkPolicy (locked / public_web / public_web_and_git) + allowedUploadHosts", () => {
    const base = {
      engine: "codex",
      mcpHost: "gigbotic.com",
      allowedUploadHosts: ["uploads.r2.cloudflarestorage.com"],
    };

    // locked: allows gigbotic, upload host, and codex LLM API ONLY
    assert.equal(evaluateHostPolicy("gigbotic.com", 443, { ...base, networkPolicy: "locked" }).allowed, true);
    assert.equal(evaluateHostPolicy("uploads.r2.cloudflarestorage.com", 443, { ...base, networkPolicy: "locked" }).allowed, true);
    assert.equal(evaluateHostPolicy("api.openai.com", 443, { ...base, networkPolicy: "locked" }).allowed, true);
    assert.equal(evaluateHostPolicy("api.anthropic.com", 443, { ...base, networkPolicy: "locked" }).allowed, false);
    assert.equal(evaluateHostPolicy("example.com", 443, { ...base, networkPolicy: "locked" }).allowed, false);
    assert.equal(evaluateHostPolicy("github.com", 443, { ...base, networkPolicy: "locked" }).allowed, false);

    // public_web: allows normal public HTTPS sites, blocks github/gitlab/npm/pypi & raw IPs
    assert.equal(evaluateHostPolicy("example.com", 443, { ...base, networkPolicy: "public_web" }).allowed, true);
    assert.equal(evaluateHostPolicy("github.com", 443, { ...base, networkPolicy: "public_web" }).allowed, false);
    assert.equal(evaluateHostPolicy("github.com.", 443, { ...base, networkPolicy: "public_web" }).allowed, false);
    assert.equal(evaluateHostPolicy("gitlab.com", 443, { ...base, networkPolicy: "public_web" }).allowed, false);
    assert.equal(evaluateHostPolicy("bitbucket.org", 443, { ...base, networkPolicy: "public_web" }).allowed, false);
    assert.equal(evaluateHostPolicy("registry.npmjs.org", 443, { ...base, networkPolicy: "public_web" }).allowed, false);
    assert.equal(evaluateHostPolicy("pypi.org", 443, { ...base, networkPolicy: "public_web" }).allowed, false);
    assert.equal(evaluateHostPolicy("169.254.169.254", 443, { ...base, networkPolicy: "public_web" }).allowed, false);
    assert.equal(evaluateHostPolicy("localhost", 443, { ...base, networkPolicy: "public_web" }).allowed, false);
    assert.equal(evaluateHostPolicy("metadata.google.internal", 443, { ...base, networkPolicy: "public_web" }).allowed, false);

    // public_web_and_git: allows github + npm + pypi, still blocks private hostnames & raw IPs
    assert.equal(evaluateHostPolicy("github.com", 443, { ...base, networkPolicy: "public_web_and_git" }).allowed, true);
    assert.equal(evaluateHostPolicy("registry.npmjs.org", 443, { ...base, networkPolicy: "public_web_and_git" }).allowed, true);
    assert.equal(evaluateHostPolicy("127.0.0.1", 443, { ...base, networkPolicy: "public_web_and_git" }).allowed, false);
    assert.equal(evaluateHostPolicy("localhost", 443, { ...base, networkPolicy: "public_web_and_git" }).allowed, false);

    assert.equal(isGitOrPackageHost("raw.githubusercontent.com"), true);
    assert.equal(isGitOrPackageHost("files.pythonhosted.org"), true);
  });

  it("resolveAndVerifyPublicIp defeats DNS rebinding if any A/AAAA record is private", async () => {
    await assert.rejects(
      () =>
        resolveAndVerifyPublicIp("evil-rebind.example", async () => [
          { address: "93.184.216.34", family: 4 },
          { address: "169.254.169.254", family: 4 },
        ]),
      /Blocked private\/loopback\/metadata IP/
    );

    const ok = await resolveAndVerifyPublicIp("clean.example", async () => [
      { address: "93.184.216.34", family: 4 },
    ]);
    assert.equal(ok.address, "93.184.216.34");
  });

  it("live CONNECT proxy enforces auth (407), git blocking (403), and DNS SSRF blocking (403)", async () => {
    const blockedEvents = [];
    const proxy = createEgressProxyServer({
      bindHost: "127.0.0.1",
      port: 0,
      onBlocked: (ev) => blockedEvents.push(ev),
      lookupFn: async (host) => {
        if (host === "ssrf.example") return [{ address: "169.254.169.254", family: 4 }];
        if (host === "loopback.example") return [{ address: "127.0.0.1", family: 4 }];
        return [{ address: "93.184.216.34", family: 4 }];
      },
    });
    const { host, port } = await proxy.start();
    const handle = proxy.registerJobPolicy({
      jobId: "job_proxy_test",
      deliveryId: "whd_1",
      engine: "codex",
      mcpHost: "gigbotic.com",
      networkPolicy: "public_web",
      allowedUploadHosts: ["uploads.r2.cloudflarestorage.com"],
    });

    const sendConnect = (authority, authHeader) =>
      new Promise((resolve, reject) => {
        const sock = net.connect(port, host, () => {
          const hdr = authHeader ? `Proxy-Authorization: ${authHeader}\r\n` : "";
          sock.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${hdr}\r\n`);
        });
        let data = "";
        sock.on("data", (c) => {
          data += c.toString("utf8");
          if (data.includes("\r\n\r\n")) {
            sock.destroy();
            resolve(data.split("\r\n")[0]);
          }
        });
        sock.on("error", reject);
      });

    try {
      const auth = `Basic ${Buffer.from(`job:${handle.token}`).toString("base64")}`;

      // 1. Missing auth -> 407
      assert.match(await sendConnect("example.com:443", null), /407/);

      // 2. github.com blocked in public_web -> 403
      assert.match(await sendConnect("github.com:443", auth), /403/);

      // 3. DNS rebinding to metadata 169.254.169.254 -> 403
      assert.match(await sendConnect("ssrf.example:443", auth), /403/);

      // 4. DNS rebinding to 127.0.0.1 -> 403
      assert.match(await sendConnect("loopback.example:443", auth), /403/);

      // 5. Raw IP literal -> 403
      assert.match(await sendConnect("127.0.0.1:443", auth), /403/);

      assert.ok(blockedEvents.length >= 4);

      // 6. Revoking token immediately returns 407
      handle.revoke();
      assert.match(await sendConnect("example.com:443", auth), /407/);
    } finally {
      await proxy.stop();
    }
  });
});
