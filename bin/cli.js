#!/usr/bin/env node
"use strict";

/**
 * TITAN Statutory Gate CLI (Standalone Zero-Dependency Node.js Implementation)
 * Entity: TITAN Capital Forensics LLC (Albuquerque, New Mexico, USA)
 *
 * Security & Determinism Guarantees:
 * - Zero subprocess or shell invocations (0 Python runtime requirement).
 * - Strict ASCII CLI grammar, finite numeric bounds, and HS/CN regex validation.
 * - Native http/https client with wall-clock timeout (default 10s), redirect block,
 *   and <= 2 MiB streaming response cap.
 * - Optional native node:crypto Ed25519 signature verification (RFC 8032 / RFC 8410).
 * - Deterministic exit codes: 0 = success, 2 = invalid CLI argument, 3 = upstream/network error.
 */

const http = require("node:http");
const https = require("node:https");
const crypto = require("node:crypto");
const { URL } = require("node:url");

const CLI_VERSION = "0.2.0";
const DEFAULT_ENDPOINT = "https://mcp.titancapitalforensics.com/mcp";
const DEFAULT_TIMEOUT_MS = 10000;
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MiB hard streaming ceiling
const MAX_ARG_BYTES = 4096;
const DEFAULT_AUTHORITY_PUBKEY_B64 = "Ub3/lGEK5NXfeyoxdb11R7s06hPixx4FLnzHQyAPJnc=";
const USER_AGENT = `titan-statutory-cli/${CLI_VERSION}`;

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const USAGE_TEXT = [
  "Usage: titan-statutory <command> [options]",
  "",
  "Zero-dependency statutory applicability diagnostics for TITAN Capital Forensics LLC (Albuquerque, New Mexico, USA).",
  "",
  "Commands:",
  "  check-cbam      Check EU CBAM / EUDR statutory applicability",
  "  check-179d      Check US IRS Section 179D / CMMC readiness",
  "  check-einvoice  Check UAE QFZP / GDPR statutory applicability",
  "  check-qfzp      Check UAE QFZP 0% de-minimis cliff (dual regime)",
  "  catalog         List available statutory diagnostic tools",
  "",
  "Global Options:",
  "  --json                 Emit machine-readable JSON only",
  "  --endpoint <url>       Override MCP JSON-RPC HTTPS endpoint",
  "  --verify-signature     Require valid Ed25519 signature on response",
  "  --pubkey <base64>      Override 32-byte Ed25519 authority public key",
  "  -h, --help             Show this help message and exit",
  "  -V, --version          Show CLI version and exit",
].join("\n");

const COMMANDS = new Set([
  "check-cbam",
  "check-179d",
  "check-einvoice",
  "check-qfzp",
  "catalog",
]);

const GLOBAL_BOOL_FLAGS = new Set(["--json", "--verify-signature"]);
const GLOBAL_VALUE_FLAGS = new Set(["--endpoint", "--pubkey"]);

const CMD_BOOL_FLAGS = {
  "check-cbam": new Set(["--ring-closed"]),
  "check-179d": new Set(["--wage-met", "--exempt"]),
  "check-einvoice": new Set(["--excluded", "--eu-subjects", "--high-risk"]),
  "check-qfzp": new Set(["--excluded", "--eu-subjects", "--high-risk"]),
  "catalog": new Set(),
};

const CMD_VALUE_FLAGS = {
  "check-cbam": new Set(["--cn-or-hs", "--annual-mass", "--plot-area", "--regime"]),
  "check-179d": new Set(["--sqft", "--sprs", "--cui-fci", "--mandate"]),
  "check-einvoice": new Set(["--non-qual-pct", "--non-qual-aed"]),
  "check-qfzp": new Set(["--non-qual-pct", "--non-qual-aed"]),
  "catalog": new Set(),
};

const ALL_KNOWN_BOOL_FLAGS = new Set([
  ...GLOBAL_BOOL_FLAGS,
  "--ring-closed",
  "--wage-met",
  "--exempt",
  "--excluded",
  "--eu-subjects",
  "--high-risk",
]);

const ALL_KNOWN_VALUE_FLAGS = new Set([
  ...GLOBAL_VALUE_FLAGS,
  "--cn-or-hs",
  "--annual-mass",
  "--plot-area",
  "--regime",
  "--sqft",
  "--sprs",
  "--cui-fci",
  "--mandate",
  "--non-qual-pct",
  "--non-qual-aed",
]);

const CONTROL_CHAR_RE = /[\x00-\x1f\x7f-\x9f]/;
const STRICT_FLOAT_RE = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/;
const STRICT_INT_RE = /^-?(?:0|[1-9][0-9]*)$/;
const STRICT_HSCN_RE = /^[A-Za-z0-9]{2,12}(?:\.[A-Za-z0-9]{1,8}){0,4}$/;
const STRICT_B64_32_RE = /^[A-Za-z0-9+/]{43}=$/;
const STRICT_B64_64_RE = /^[A-Za-z0-9+/]{86}==$/;
const STRICT_URL_CHARS_RE = /^[A-Za-z0-9\-._~:/?&=[\]]+$/;
const STRICT_PATH_RE = /^[A-Za-z0-9\-._~/]+$/;
const STRICT_QUERY_RE = /^(?:[A-Za-z0-9\-._~]+=[A-Za-z0-9\-._~]*(?:&[A-Za-z0-9\-._~]+=[A-Za-z0-9\-._~]*)*)?$/;

class CliUsageError extends Error {
  constructor(message) {
    super(message);
    this.name = "CliUsageError";
  }
}

class UpstreamError extends Error {
  constructor(message, prefix = "Upstream Error") {
    super(message);
    this.name = "UpstreamError";
    this.prefix = prefix;
  }
}

function isPlainObject(val) {
  return val !== null && typeof val === "object" && !Array.isArray(val);
}

function sanitizeLogLine(str) {
  return String(str).replace(/[\x00-\x1f\x7f-\x9f]+/g, " ").trim().slice(0, 300);
}

function verifyEd25519(messageBytes, signatureB64, pubkeyB64 = DEFAULT_AUTHORITY_PUBKEY_B64) {
  try {
    if (typeof signatureB64 !== "string" || typeof pubkeyB64 !== "string") {
      return false;
    }
    if (!STRICT_B64_64_RE.test(signatureB64) || !STRICT_B64_32_RE.test(pubkeyB64)) {
      return false;
    }
    const pubRaw = Buffer.from(pubkeyB64, "base64");
    const sigRaw = Buffer.from(signatureB64, "base64");
    if (pubRaw.length !== 32 || sigRaw.length !== 64) {
      return false;
    }
    const msgBuf = Buffer.isBuffer(messageBytes)
      ? messageBytes
      : Buffer.from(String(messageBytes), "utf8");
    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, pubRaw]);
    const publicKey = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
    return crypto.verify(null, msgBuf, publicKey, sigRaw);
  } catch (_) {
    return false;
  }
}

function validateEndpoint(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.length === 0 || rawUrl.length > 2048) {
    throw new CliUsageError("Invalid endpoint URL");
  }
  if (
    CONTROL_CHAR_RE.test(rawUrl) ||
    /\s/.test(rawUrl) ||
    !STRICT_URL_CHARS_RE.test(rawUrl)
  ) {
    throw new CliUsageError("Invalid endpoint URL");
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_) {
    throw new CliUsageError("Invalid endpoint URL");
  }
  if (
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    !STRICT_PATH_RE.test(parsed.pathname) ||
    !STRICT_QUERY_RE.test(parsed.search ? parsed.search.slice(1) : "")
  ) {
    throw new CliUsageError("Invalid endpoint URL");
  }
  const host = parsed.hostname.toLowerCase();
  if (!host) {
    throw new CliUsageError("Invalid endpoint URL");
  }
  const isLoopback = host === "127.0.0.1" || host === "localhost" || host === "[::1]" || host === "::1";
  if (parsed.protocol === "https:") {
    // Allowed for all valid hosts
  } else if (parsed.protocol === "http:" && isLoopback) {
    // Allowed strictly for local loopback testing
  } else {
    throw new CliUsageError("Invalid endpoint URL (HTTPS required for non-loopback hosts)");
  }
  if (parsed.port !== "") {
    const p = Number(parsed.port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      throw new CliUsageError("Invalid endpoint URL");
    }
  }
  return parsed;
}

function validatePubkeyB64(raw) {
  if (typeof raw !== "string" || !STRICT_B64_32_RE.test(raw)) {
    throw new CliUsageError("Invalid --pubkey (expected 32-byte Base64 Ed25519 public key)");
  }
  const buf = Buffer.from(raw, "base64");
  if (buf.length !== 32) {
    throw new CliUsageError("Invalid --pubkey (expected 32-byte Base64 Ed25519 public key)");
  }
  return raw;
}

function validateHsCnCode(raw) {
  if (
    typeof raw !== "string" ||
    raw.length < 4 ||
    raw.length > 20 ||
    !STRICT_HSCN_RE.test(raw)
  ) {
    throw new CliUsageError("Invalid --cn-or-hs (expected 4-20 char alphanumeric/dot HS or CN code)");
  }
  return raw;
}

function parseBoundedFloat(flag, raw, minVal, maxVal) {
  if (typeof raw !== "string" || !STRICT_FLOAT_RE.test(raw)) {
    throw new CliUsageError(`Invalid ${flag} (expected finite number in range ${minVal}..${maxVal})`);
  }
  const num = Number(raw);
  if (!Number.isFinite(num) || num < minVal || num > maxVal) {
    throw new CliUsageError(`Invalid ${flag} (expected finite number in range ${minVal}..${maxVal})`);
  }
  return Object.is(num, -0) ? 0 : num;
}

function parseBoundedInt(flag, raw, minVal, maxVal) {
  if (typeof raw !== "string" || !STRICT_INT_RE.test(raw)) {
    throw new CliUsageError(`Invalid ${flag} (expected integer in range ${minVal}..${maxVal})`);
  }
  const num = Number(raw);
  if (!Number.isSafeInteger(num) || num < minVal || num > maxVal) {
    throw new CliUsageError(`Invalid ${flag} (expected integer in range ${minVal}..${maxVal})`);
  }
  return Object.is(num, -0) ? 0 : num;
}

function parseEnum(flag, raw, allowed) {
  if (!allowed.includes(raw)) {
    throw new CliUsageError(`Invalid ${flag} (expected one of: ${allowed.join(", ")})`);
  }
  return raw;
}

function resolveTimeoutMs(env) {
  const raw = env && env.TITAN_MCP_TIMEOUT_MS;
  if (raw === undefined || raw === "") {
    return DEFAULT_TIMEOUT_MS;
  }
  if (typeof raw !== "string" || !STRICT_INT_RE.test(raw)) {
    throw new CliUsageError("Invalid TITAN_MCP_TIMEOUT_MS environment variable");
  }
  const ms = Number(raw);
  if (!Number.isSafeInteger(ms) || ms < 100 || ms > 60000) {
    throw new CliUsageError("Invalid TITAN_MCP_TIMEOUT_MS environment variable");
  }
  return ms;
}

function parseCliArgs(argv, env = process.env) {
  if (!Array.isArray(argv)) {
    throw new CliUsageError("Invalid argument vector");
  }
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (typeof tok !== "string") {
      throw new CliUsageError("Invalid non-string argument");
    }
    if (Buffer.byteLength(tok, "utf8") > MAX_ARG_BYTES) {
      throw new CliUsageError(`Argument exceeds maximum length of ${MAX_ARG_BYTES} bytes`);
    }
    if (CONTROL_CHAR_RE.test(tok)) {
      throw new CliUsageError("Argument contains prohibited control characters");
    }
  }

  if (argv.length === 0) {
    throw new CliUsageError("Missing command");
  }

  let command = null;
  const bools = new Set();
  const values = new Map();

  let i = 0;
  while (i < argv.length) {
    const tok = argv[i];

    if (tok === "-h" || tok === "--help") {
      return { action: "help" };
    }
    if (tok === "-V" || tok === "--version") {
      return { action: "version" };
    }

    if (tok.startsWith("--") && tok.includes("=")) {
      const eqIdx = tok.indexOf("=");
      const flag = tok.slice(0, eqIdx);
      const val = tok.slice(eqIdx + 1);
      if (flag === "--help" || flag === "--version" || ALL_KNOWN_BOOL_FLAGS.has(flag)) {
        throw new CliUsageError(`Flag ${flag} does not take a value`);
      }
      if (!ALL_KNOWN_VALUE_FLAGS.has(flag)) {
        throw new CliUsageError(`Unknown option: ${flag}`);
      }
      if (values.has(flag)) {
        throw new CliUsageError(`Duplicate option: ${flag}`);
      }
      values.set(flag, val);
      i += 1;
      continue;
    }

    if (tok.startsWith("-")) {
      if (ALL_KNOWN_BOOL_FLAGS.has(tok)) {
        if (bools.has(tok)) {
          throw new CliUsageError(`Duplicate option: ${tok}`);
        }
        bools.add(tok);
        i += 1;
        continue;
      }
      if (ALL_KNOWN_VALUE_FLAGS.has(tok)) {
        if (values.has(tok)) {
          throw new CliUsageError(`Duplicate option: ${tok}`);
        }
        if (i + 1 >= argv.length) {
          throw new CliUsageError(`Missing value for ${tok}`);
        }
        values.set(tok, argv[i + 1]);
        i += 2;
        continue;
      }
      throw new CliUsageError(`Unknown option: ${tok}`);
    }

    if (command === null) {
      if (!COMMANDS.has(tok)) {
        throw new CliUsageError(`Unknown command: ${tok}`);
      }
      command = tok;
      i += 1;
      continue;
    }

    throw new CliUsageError(`Unexpected positional argument: ${tok}`);
  }

  if (command === null) {
    throw new CliUsageError("Missing command");
  }

  const allowedBools = CMD_BOOL_FLAGS[command];
  for (const b of bools) {
    if (!GLOBAL_BOOL_FLAGS.has(b) && !allowedBools.has(b)) {
      throw new CliUsageError(`Option ${b} is not valid for command ${command}`);
    }
  }
  const allowedVals = CMD_VALUE_FLAGS[command];
  for (const k of values.keys()) {
    if (!GLOBAL_VALUE_FLAGS.has(k) && !allowedVals.has(k)) {
      throw new CliUsageError(`Option ${k} is not valid for command ${command}`);
    }
  }

  const rawEndpoint = values.has("--endpoint")
    ? values.get("--endpoint")
    : (env && env.TITAN_MCP_ENDPOINT ? env.TITAN_MCP_ENDPOINT : DEFAULT_ENDPOINT);
  const endpointUrl = validateEndpoint(rawEndpoint);
  const timeoutMs = resolveTimeoutMs(env);
  const pubkeyB64 = values.has("--pubkey")
    ? validatePubkeyB64(values.get("--pubkey"))
    : DEFAULT_AUTHORITY_PUBKEY_B64;

  const opts = {
    action: "run",
    command,
    json: bools.has("--json"),
    verifySignature: bools.has("--verify-signature"),
    pubkeyB64,
    endpointUrl,
    timeoutMs,
    rpcPayload: null,
  };

  if (command === "catalog") {
    opts.rpcPayload = {
      jsonrpc: "2.0",
      method: "tools/list",
      params: {},
      id: 1,
    };
  } else if (command === "check-cbam") {
    if (!values.has("--cn-or-hs")) {
      throw new CliUsageError("Missing required option: --cn-or-hs");
    }
    const cnOrHs = validateHsCnCode(values.get("--cn-or-hs"));
    const regime = values.has("--regime")
      ? parseEnum("--regime", values.get("--regime"), ["cbam", "eudr", "both"])
      : "cbam";
    const annualMass = values.has("--annual-mass")
      ? parseBoundedFloat("--annual-mass", values.get("--annual-mass"), 0, 1e12)
      : null;
    const plotArea = values.has("--plot-area")
      ? parseBoundedFloat("--plot-area", values.get("--plot-area"), 0, 1e12)
      : null;
    const ringClosed = bools.has("--ring-closed");

    const rpcArgs = {
      regime,
      cn_or_hs_code: cnOrHs,
    };
    if (annualMass !== null) {
      rpcArgs.annual_mass_tonnes = annualMass;
    }
    if (plotArea !== null) {
      rpcArgs.plot_hectares = plotArea;
    }
    rpcArgs.geojson_ring_closed = ringClosed;
    rpcArgs.query_note = "CLI diagnostic";

    opts.rpcPayload = {
      jsonrpc: "2.0",
      method: "tools/call",
      params: {
        name: "check_eu_cbam_eudr_mandate",
        arguments: rpcArgs,
      },
      id: 1,
    };
  } else if (command === "check-179d") {
    if (!values.has("--sqft")) {
      throw new CliUsageError("Missing required option: --sqft");
    }
    const sqft = parseBoundedFloat("--sqft", values.get("--sqft"), 0, 1e12);
    const mandate = values.has("--mandate")
      ? parseEnum("--mandate", values.get("--mandate"), ["irs_179d", "cmmc_sprs", "both"])
      : "irs_179d";
    const wageMet = bools.has("--wage-met");
    const exempt = bools.has("--exempt");
    const sprs = values.has("--sprs")
      ? parseBoundedInt("--sprs", values.get("--sprs"), -203, 110)
      : null;
    const cuiFci = values.has("--cui-fci")
      ? parseEnum("--cui-fci", values.get("--cui-fci"), ["none", "fci", "cui"])
      : null;

    const rpcArgs = {
      mandate,
      building_sqft: sqft,
      prevailing_wage_met: wageMet,
      tax_exempt_allocation: exempt,
    };
    if (sprs !== null) {
      rpcArgs.sprs_score = sprs;
    }
    if (cuiFci !== null) {
      rpcArgs.handles_cui_or_fci = cuiFci;
    }
    rpcArgs.query_note = "CLI diagnostic";

    opts.rpcPayload = {
      jsonrpc: "2.0",
      method: "tools/call",
      params: {
        name: "check_irs_179d_cmmc_readiness",
        arguments: rpcArgs,
      },
      id: 1,
    };
  } else if (command === "check-einvoice" || command === "check-qfzp") {
    if (!values.has("--non-qual-pct")) {
      throw new CliUsageError("Missing required option: --non-qual-pct");
    }
    if (!values.has("--non-qual-aed")) {
      throw new CliUsageError("Missing required option: --non-qual-aed");
    }
    const pct = parseBoundedFloat("--non-qual-pct", values.get("--non-qual-pct"), 0, 100);
    const aed = parseBoundedFloat("--non-qual-aed", values.get("--non-qual-aed"), 0, 1e15);
    const excluded = bools.has("--excluded");
    const euSubjects = bools.has("--eu-subjects");
    const highRisk = bools.has("--high-risk");

    const rpcArgs = {
      regime: command === "check-einvoice" ? "uae_qfzp" : "both",
      non_qualifying_pct: pct,
      non_qualifying_aed: aed,
      excluded_activity: excluded,
      eu_data_subjects: euSubjects,
      high_risk_processing: highRisk,
      query_note: "CLI diagnostic",
    };

    opts.rpcPayload = {
      jsonrpc: "2.0",
      method: "tools/call",
      params: {
        name: "check_uae_qfzp_gdpr_trigger",
        arguments: rpcArgs,
      },
      id: 1,
    };
  }

  return opts;
}

function sendJsonRpc(endpointUrl, rpcPayload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const bodyBuf = Buffer.from(JSON.stringify(rpcPayload), "utf8");
    const transport = endpointUrl.protocol === "https:" ? https : http;
    const controller = new AbortController();
    let settled = false;

    const finishErr = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadlineTimer);
      reject(err);
    };

    const finishOk = (val) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadlineTimer);
      resolve(val);
    };

    const req = transport.request(
      endpointUrl,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "Content-Length": String(bodyBuf.length),
          "User-Agent": USER_AGENT,
          "Connection": "close",
        },
        signal: controller.signal,
      },
      (res) => {
        const status = res.statusCode || 0;
        if (status < 200 || status >= 300) {
          res.resume();
          req.destroy();
          finishErr(new UpstreamError(`HTTP ${status}`));
          return;
        }

        const clHeader = res.headers["content-length"];
        if (clHeader !== undefined) {
          const declaredLen = Number(clHeader);
          if (Number.isFinite(declaredLen) && declaredLen > MAX_BODY_BYTES) {
            req.destroy();
            finishErr(new UpstreamError("Response exceeds 2 MiB limit"));
            return;
          }
        }

        const chunks = [];
        let totalBytes = 0;

        res.on("data", (chunk) => {
          totalBytes += chunk.length;
          if (totalBytes > MAX_BODY_BYTES) {
            req.destroy();
            finishErr(new UpstreamError("Response exceeds 2 MiB limit"));
            return;
          }
          chunks.push(chunk);
        });

        res.on("error", () => {
          if (controller.signal.aborted) {
            finishErr(new UpstreamError("Request timed out"));
          } else {
            finishErr(new UpstreamError("Network read failure"));
          }
        });

        res.on("aborted", () => {
          if (controller.signal.aborted) {
            finishErr(new UpstreamError("Request timed out"));
          } else {
            finishErr(new UpstreamError("Upstream closed connection prematurely"));
          }
        });

        res.on("end", () => {
          if (settled) return;
          if (!res.complete) {
            finishErr(new UpstreamError("Upstream closed connection prematurely"));
            return;
          }
          const fullBuf = Buffer.concat(chunks, totalBytes);
          let text;
          try {
            const decoder = new TextDecoder("utf-8", { fatal: true });
            text = decoder.decode(fullBuf);
          } catch (_) {
            finishErr(new UpstreamError("Invalid JSON response"));
            return;
          }
          let parsed;
          try {
            parsed = JSON.parse(text);
          } catch (_) {
            finishErr(new UpstreamError("Invalid JSON response"));
            return;
          }
          finishOk(parsed);
        });
      }
    );

    const deadlineTimer = setTimeout(() => {
      controller.abort();
      req.destroy();
      finishErr(new UpstreamError("Request timed out"));
    }, timeoutMs);

    req.on("error", (err) => {
      if (controller.signal.aborted || (err && err.name === "AbortError")) {
        finishErr(new UpstreamError("Request timed out"));
      } else {
        finishErr(new UpstreamError("Network connection failure"));
      }
    });

    req.write(bodyBuf);
    req.end();
  });
}

function processEnvelope(envelope, opts) {
  if (!isPlainObject(envelope)) {
    throw new UpstreamError("Malformed JSON-RPC envelope");
  }
  if (Object.prototype.hasOwnProperty.call(envelope, "error") && envelope.error !== null && envelope.error !== undefined) {
    const errObj = envelope.error;
    const msg = isPlainObject(errObj) && typeof errObj.message === "string"
      ? sanitizeLogLine(errObj.message)
      : "RPC error";
    throw new UpstreamError(msg || "RPC error", "MCP Error");
  }
  if (!isPlainObject(envelope.result)) {
    throw new UpstreamError("Missing JSON-RPC result object");
  }
  const result = envelope.result;
  if (result.isError === true) {
    throw new UpstreamError("Tool reported execution error", "MCP Error");
  }

  if (opts.command === "catalog") {
    if (!Array.isArray(result.tools)) {
      throw new UpstreamError("Invalid tools catalog payload");
    }
    const cleanTools = [];
    for (const item of result.tools) {
      if (!isPlainObject(item) || typeof item.name !== "string") {
        throw new UpstreamError("Invalid tools catalog payload");
      }
      cleanTools.push(item);
    }
    if (opts.json) {
      return JSON.stringify({ tools: cleanTools }, null, 2) + "\n";
    }
    const lines = ["Available statutory tools:"];
    for (const tool of cleanTools) {
      const name = sanitizeLogLine(tool.name);
      const desc = typeof tool.description === "string" ? sanitizeLogLine(tool.description) : "";
      lines.push(`  - ${name}: ${desc}`);
    }
    return lines.join("\n") + "\n";
  }

  const payload = isPlainObject(result.structuredContent) ? result.structuredContent : result;

  if (opts.verifySignature || typeof payload.signature_b64 === "string") {
    const signedText = typeof payload.canonical_payload === "string"
      ? payload.canonical_payload
      : (typeof payload.gate_receipt_sha256 === "string" ? payload.gate_receipt_sha256 : null);
    const sigOk = signedText !== null && typeof payload.signature_b64 === "string"
      ? verifyEd25519(Buffer.from(signedText, "utf8"), payload.signature_b64, opts.pubkeyB64)
      : false;
    if (opts.verifySignature && !sigOk) {
      throw new UpstreamError("Ed25519 signature verification failed");
    }
  }

  const jsonBlock = JSON.stringify(payload, null, 2);
  if (opts.json) {
    return jsonBlock + "\n";
  }

  let checkoutUrl = "";
  if (isPlainObject(payload.settlement_routing) && typeof payload.settlement_routing.official_checkout_url === "string") {
    checkoutUrl = payload.settlement_routing.official_checkout_url;
  } else if (typeof payload.checkout_url === "string") {
    checkoutUrl = payload.checkout_url;
  }

  if (checkoutUrl.startsWith("https://") && !CONTROL_CHAR_RE.test(checkoutUrl)) {
    return `${jsonBlock}\n\nDirect Checkout URL: ${checkoutUrl}\n`;
  }
  return `${jsonBlock}\n`;
}

async function runCli(argv, env = process.env, io = { stdout: process.stdout, stderr: process.stderr }) {
  let opts;
  try {
    opts = parseCliArgs(argv, env);
  } catch (err) {
    if (err instanceof CliUsageError) {
      io.stderr.write(`Error: ${err.message}\n`);
      return 2;
    }
    io.stderr.write("Error: Invalid CLI arguments\n");
    return 2;
  }

  if (opts.action === "help") {
    io.stdout.write(`${USAGE_TEXT}\n`);
    return 0;
  }
  if (opts.action === "version") {
    io.stdout.write(`titan-statutory-cli ${CLI_VERSION}\n`);
    return 0;
  }

  try {
    const envelope = await sendJsonRpc(opts.endpointUrl, opts.rpcPayload, opts.timeoutMs);
    const outText = processEnvelope(envelope, opts);
    io.stdout.write(outText);
    return 0;
  } catch (err) {
    if (err instanceof UpstreamError) {
      io.stderr.write(`${err.prefix}: ${err.message}\n`);
      return 3;
    }
    io.stderr.write("Upstream Error: Unexpected transport failure\n");
    return 3;
  }
}

if (require.main === module) {
  runCli(process.argv.slice(2), process.env).then((code) => {
    process.exit(code);
  });
}

module.exports = {
  CLI_VERSION,
  DEFAULT_AUTHORITY_PUBKEY_B64,
  verifyEd25519,
  parseCliArgs,
  runCli,
};
