#!/usr/bin/env python3
"""TITAN Statutory Gate CLI (Standalone Zero-Dependency Python Implementation).

Entity: TITAN Capital Forensics LLC (Albuquerque, New Mexico, USA)

Security & Determinism Guarantees:
- 100% Python standard library (zero external dependencies, zero Node.js dependency).
- Identical CLI grammar, Decimal + math.isfinite bounds, and output parity with bin/cli.js.
- Streaming HTTPS / loopback-HTTP client with 10s wall-clock deadline, redirect block,
  and <= 2 MiB streaming response ceiling.
- Pure-stdlib RFC 8032 Ed25519 cryptographic signature verification.
- Deterministic exit codes: 0 = success, 2 = invalid CLI argument, 3 = upstream/network error.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import math
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Sequence, TextIO, Tuple

CLI_VERSION = "0.2.1"
DEFAULT_ENDPOINT = "https://mcp.titancapitalforensics.com/mcp"
DEFAULT_TIMEOUT_MS = 10000
MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB hard streaming ceiling
MAX_ARG_BYTES = 4096
MAX_SAFE_JS_INT = 9007199254740991
DEFAULT_AUTHORITY_PUBKEY_B64 = "Ub3/lGEK5NXfeyoxdb11R7s06hPixx4FLnzHQyAPJnc="
USER_AGENT = f"titan-statutory-cli/{CLI_VERSION}"

USAGE_TEXT = "\n".join(
    [
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
    ]
)

COMMANDS = {
    "check-cbam",
    "check-179d",
    "check-einvoice",
    "check-qfzp",
    "catalog",
}

GLOBAL_BOOL_FLAGS = {"--json", "--verify-signature"}
GLOBAL_VALUE_FLAGS = {"--endpoint", "--pubkey"}

CMD_BOOL_FLAGS: Dict[str, set[str]] = {
    "check-cbam": {"--ring-closed"},
    "check-179d": {"--wage-met", "--exempt"},
    "check-einvoice": {"--excluded", "--eu-subjects", "--high-risk"},
    "check-qfzp": {"--excluded", "--eu-subjects", "--high-risk"},
    "catalog": set(),
}

CMD_VALUE_FLAGS: Dict[str, set[str]] = {
    "check-cbam": {"--cn-or-hs", "--annual-mass", "--plot-area", "--regime"},
    "check-179d": {"--sqft", "--sprs", "--cui-fci", "--mandate"},
    "check-einvoice": {"--non-qual-pct", "--non-qual-aed"},
    "check-qfzp": {"--non-qual-pct", "--non-qual-aed"},
    "catalog": set(),
}

ALL_KNOWN_BOOL_FLAGS = (
    GLOBAL_BOOL_FLAGS
    | {"--ring-closed", "--wage-met", "--exempt", "--excluded", "--eu-subjects", "--high-risk"}
)

ALL_KNOWN_VALUE_FLAGS = (
    GLOBAL_VALUE_FLAGS
    | {
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
    }
)

CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
WHITESPACE_RE = re.compile(r"\s")
STRICT_FLOAT_RE = re.compile(r"\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z", re.ASCII)
STRICT_INT_RE = re.compile(r"\A-?(?:0|[1-9][0-9]*)\Z", re.ASCII)
STRICT_HSCN_RE = re.compile(r"\A[A-Za-z0-9]{2,12}(?:\.[A-Za-z0-9]{1,8}){0,4}\Z", re.ASCII)
STRICT_B64_32_RE = re.compile(r"\A[A-Za-z0-9+/]{43}=\Z", re.ASCII)
STRICT_B64_64_RE = re.compile(r"\A[A-Za-z0-9+/]{86}==\Z", re.ASCII)
STRICT_URL_CHARS_RE = re.compile(r"\A[A-Za-z0-9\-._~:/?&=[\]]+\Z", re.ASCII)
STRICT_PATH_RE = re.compile(r"\A[A-Za-z0-9\-._~/]+\Z", re.ASCII)
STRICT_QUERY_RE = re.compile(
    r"\A(?:[A-Za-z0-9\-._~]+=[A-Za-z0-9\-._~]*(?:&[A-Za-z0-9\-._~]+=[A-Za-z0-9\-._~]*)*)?\Z",
    re.ASCII,
)


class CliUsageError(Exception):
    """Raised when CLI arguments fail syntactic or semantic validation (exit code 2)."""


class UpstreamError(Exception):
    """Raised when network transport or MCP upstream response fails (exit code 3)."""

    def __init__(self, message: str, prefix: str = "Upstream Error") -> None:
        super().__init__(message)
        self.prefix = prefix


# ---------------------------------------------------------------------------
# Pure-Stdlib RFC 8032 Ed25519 Signature Verification (Zero External Packages)
# ---------------------------------------------------------------------------

_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _ED_P:
        return None
    x2 = ((y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P)) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_BX = _ed_recover_x(_ED_BY, 0)
assert _ED_BX is not None
_ED_B: Tuple[int, int, int, int] = (_ED_BX, _ED_BY, 1, (_ED_BX * _ED_BY) % _ED_P)


def _ed_point_add(
    p1: Tuple[int, int, int, int], p2: Tuple[int, int, int, int]
) -> Tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (t1 * 2 * _ED_D * t2) % _ED_P
    d = (z1 * 2 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return ((e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P)


def _ed_scalar_mult(s: int, pt: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    acc: Tuple[int, int, int, int] = (0, 1, 1, 0)
    cur = pt
    while s > 0:
        if s & 1:
            acc = _ed_point_add(acc, cur)
        cur = _ed_point_add(cur, cur)
        s >>= 1
    return acc


def _ed_point_eq(p1: Tuple[int, int, int, int], p2: Tuple[int, int, int, int]) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    if (x1 * z2 - x2 * z1) % _ED_P != 0:
        return False
    if (y1 * z2 - y2 * z1) % _ED_P != 0:
        return False
    return True


def _ed_point_decompress(buf: bytes) -> Optional[Tuple[int, int, int, int]]:
    if len(buf) != 32:
        return None
    y = int.from_bytes(buf, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _ED_P)


def verify_ed25519(
    message: bytes | str,
    signature_b64: str,
    pubkey_b64: str = DEFAULT_AUTHORITY_PUBKEY_B64,
) -> bool:
    """Verify an Ed25519 signature using pure Python stdlib RFC 8032 arithmetic."""
    try:
        if not isinstance(signature_b64, str) or not isinstance(pubkey_b64, str):
            return False
        if not STRICT_B64_64_RE.match(signature_b64) or not STRICT_B64_32_RE.match(pubkey_b64):
            return False
        pub_raw = base64.b64decode(pubkey_b64, validate=True)
        sig_raw = base64.b64decode(signature_b64, validate=True)
        if len(pub_raw) != 32 or len(sig_raw) != 64:
            return False
        msg_bytes = message if isinstance(message, bytes) else str(message).encode("utf-8")
        r_bytes = sig_raw[:32]
        s_int = int.from_bytes(sig_raw[32:], "little")
        if s_int >= _ED_L:
            return False
        a_pt = _ed_point_decompress(pub_raw)
        r_pt = _ed_point_decompress(r_bytes)
        if a_pt is None or r_pt is None:
            return False
        k_int = int.from_bytes(hashlib.sha512(r_bytes + pub_raw + msg_bytes).digest(), "little") % _ED_L
        lhs = _ed_scalar_mult(8, _ed_scalar_mult(s_int, _ED_B))
        rhs = _ed_scalar_mult(8, _ed_point_add(r_pt, _ed_scalar_mult(k_int, a_pt)))
        return _ed_point_eq(lhs, rhs)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Helpers & Strict Validators
# ---------------------------------------------------------------------------


def _is_plain_object(val: Any) -> bool:
    return isinstance(val, dict)


def _sanitize_log_line(text: Any) -> str:
    cleaned = CONTROL_CHAR_RE.sub(" ", str(text)).strip()
    return cleaned[:300]


def _fmt_bound(val: int | float) -> str:
    if isinstance(val, int) or (isinstance(val, float) and val.is_integer()):
        return str(int(val))
    return str(val)


def _normalize_js_numbers(obj: Any) -> Any:
    """Normalize parsed JSON whole-number floats so serialization matches Node JSON.stringify."""
    if isinstance(obj, bool) or obj is None:
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("Non-finite float in JSON")
        if obj == 0.0:
            return 0
        if obj.is_integer() and abs(int(obj)) <= MAX_SAFE_JS_INT:
            return int(obj)
        return obj
    if isinstance(obj, list):
        return [_normalize_js_numbers(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _normalize_js_numbers(v) for k, v in obj.items()}
    return obj


def _reject_json_constant(constant: str) -> Any:
    raise ValueError(f"Non-standard JSON constant rejected: {constant}")


def _json_dumps_pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


class ParsedEndpoint:
    def __init__(self, scheme: str, host: str, port: int, path_and_query: str, server_hostname: str) -> None:
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path_and_query = path_and_query
        self.server_hostname = server_hostname


def validate_endpoint(raw_url: str) -> ParsedEndpoint:
    if not isinstance(raw_url, str) or len(raw_url) == 0 or len(raw_url) > 2048:
        raise CliUsageError("Invalid endpoint URL")
    if (
        CONTROL_CHAR_RE.search(raw_url)
        or WHITESPACE_RE.search(raw_url)
        or not STRICT_URL_CHARS_RE.match(raw_url)
    ):
        raise CliUsageError("Invalid endpoint URL")
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except Exception as exc:
        raise CliUsageError("Invalid endpoint URL") from exc

    path_check = parsed.path if parsed.path else "/"
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.fragment != ""
        or not STRICT_PATH_RE.match(path_check)
        or not STRICT_QUERY_RE.match(parsed.query)
    ):
        raise CliUsageError("Invalid endpoint URL")

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if not host:
        raise CliUsageError("Invalid endpoint URL")

    is_loopback = host in {"127.0.0.1", "localhost", "::1"}
    if scheme == "https":
        default_port = 443
    elif scheme == "http" and is_loopback:
        default_port = 80
    else:
        raise CliUsageError("Invalid endpoint URL (HTTPS required for non-loopback hosts)")

    try:
        port_raw = parsed.port
    except ValueError as exc:
        raise CliUsageError("Invalid endpoint URL") from exc

    if port_raw is None:
        port = default_port
    else:
        if not (1 <= port_raw <= 65535):
            raise CliUsageError("Invalid endpoint URL")
        port = port_raw

    path = parsed.path if parsed.path else "/"
    path_and_query = f"{path}?{parsed.query}" if parsed.query else path
    return ParsedEndpoint(
        scheme=scheme,
        host=host,
        port=port,
        path_and_query=path_and_query,
        server_hostname=host,
    )


def validate_pubkey_b64(raw: str) -> str:
    if not isinstance(raw, str) or not STRICT_B64_32_RE.match(raw):
        raise CliUsageError("Invalid --pubkey (expected 32-byte Base64 Ed25519 public key)")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise CliUsageError("Invalid --pubkey (expected 32-byte Base64 Ed25519 public key)") from exc
    if len(decoded) != 32:
        raise CliUsageError("Invalid --pubkey (expected 32-byte Base64 Ed25519 public key)")
    return raw


def validate_hs_cn_code(raw: str) -> str:
    if not isinstance(raw, str) or len(raw) < 4 or len(raw) > 20 or not STRICT_HSCN_RE.match(raw):
        raise CliUsageError("Invalid --cn-or-hs (expected 4-20 char alphanumeric/dot HS or CN code)")
    return raw


def parse_bounded_float(flag: str, raw: Any, min_val: int | float, max_val: int | float) -> int | float:
    err_msg = f"Invalid {flag} (expected finite number in range {_fmt_bound(min_val)}..{_fmt_bound(max_val)})"
    if isinstance(raw, bool) or not isinstance(raw, str) or not STRICT_FLOAT_RE.match(raw):
        raise CliUsageError(err_msg)
    try:
        dec = Decimal(raw)
        flt = float(raw)
    except (InvalidOperation, ValueError, OverflowError) as exc:
        raise CliUsageError(err_msg) from exc
    if not dec.is_finite() or not math.isfinite(flt):
        raise CliUsageError(err_msg)
    if dec < Decimal(_fmt_bound(min_val)) or dec > Decimal(_fmt_bound(max_val)):
        raise CliUsageError(err_msg)
    if flt < min_val or flt > max_val:
        raise CliUsageError(err_msg)
    if flt == 0.0:
        return 0
    if flt.is_integer() and abs(int(flt)) <= MAX_SAFE_JS_INT:
        return int(flt)
    return flt


def parse_bounded_int(flag: str, raw: Any, min_val: int, max_val: int) -> int:
    err_msg = f"Invalid {flag} (expected integer in range {min_val}..{max_val})"
    if isinstance(raw, bool) or not isinstance(raw, str) or not STRICT_INT_RE.match(raw):
        raise CliUsageError(err_msg)
    try:
        val = int(raw, 10)
    except ValueError as exc:
        raise CliUsageError(err_msg) from exc
    if abs(val) > MAX_SAFE_JS_INT or val < min_val or val > max_val:
        raise CliUsageError(err_msg)
    return 0 if val == 0 else val


def parse_enum(flag: str, raw: str, allowed: Sequence[str]) -> str:
    if raw not in allowed:
        raise CliUsageError(f"Invalid {flag} (expected one of: {', '.join(allowed)})")
    return raw


def resolve_timeout_ms(env: Dict[str, str]) -> int:
    raw = env.get("TITAN_MCP_TIMEOUT_MS")
    if raw is None or raw == "":
        return DEFAULT_TIMEOUT_MS
    if not isinstance(raw, str) or not STRICT_INT_RE.match(raw):
        raise CliUsageError("Invalid TITAN_MCP_TIMEOUT_MS environment variable")
    ms = int(raw, 10)
    if ms < 100 or ms > 60000:
        raise CliUsageError("Invalid TITAN_MCP_TIMEOUT_MS environment variable")
    return ms


def parse_cli_args(argv: Sequence[str], env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    env_map = dict(os.environ) if env is None else env
    if not isinstance(argv, (list, tuple)):
        raise CliUsageError("Invalid argument vector")

    for tok in argv:
        if not isinstance(tok, str):
            raise CliUsageError("Invalid non-string argument")
        if len(tok.encode("utf-8", errors="surrogatepass")) > MAX_ARG_BYTES:
            raise CliUsageError(f"Argument exceeds maximum length of {MAX_ARG_BYTES} bytes")
        if CONTROL_CHAR_RE.search(tok):
            raise CliUsageError("Argument contains prohibited control characters")

    if len(argv) == 0:
        raise CliUsageError("Missing command")

    command: Optional[str] = None
    bools: set[str] = set()
    values: Dict[str, str] = {}

    i = 0
    n = len(argv)
    while i < n:
        tok = argv[i]

        if tok in ("-h", "--help"):
            return {"action": "help"}
        if tok in ("-V", "--version"):
            return {"action": "version"}

        if tok.startswith("--") and "=" in tok:
            flag, val = tok.split("=", 1)
            if flag in ("--help", "--version") or flag in ALL_KNOWN_BOOL_FLAGS:
                raise CliUsageError(f"Flag {flag} does not take a value")
            if flag not in ALL_KNOWN_VALUE_FLAGS:
                raise CliUsageError(f"Unknown option: {flag}")
            if flag in values:
                raise CliUsageError(f"Duplicate option: {flag}")
            values[flag] = val
            i += 1
            continue

        if tok.startswith("-"):
            if tok in ALL_KNOWN_BOOL_FLAGS:
                if tok in bools:
                    raise CliUsageError(f"Duplicate option: {tok}")
                bools.add(tok)
                i += 1
                continue
            if tok in ALL_KNOWN_VALUE_FLAGS:
                if tok in values:
                    raise CliUsageError(f"Duplicate option: {tok}")
                if i + 1 >= n:
                    raise CliUsageError(f"Missing value for {tok}")
                values[tok] = argv[i + 1]
                i += 2
                continue
            raise CliUsageError(f"Unknown option: {tok}")

        if command is None:
            if tok not in COMMANDS:
                raise CliUsageError(f"Unknown command: {tok}")
            command = tok
            i += 1
            continue

        raise CliUsageError(f"Unexpected positional argument: {tok}")

    if command is None:
        raise CliUsageError("Missing command")

    allowed_bools = CMD_BOOL_FLAGS[command]
    for b_flag in bools:
        if b_flag not in GLOBAL_BOOL_FLAGS and b_flag not in allowed_bools:
            raise CliUsageError(f"Option {b_flag} is not valid for command {command}")

    allowed_vals = CMD_VALUE_FLAGS[command]
    for v_flag in values:
        if v_flag not in GLOBAL_VALUE_FLAGS and v_flag not in allowed_vals:
            raise CliUsageError(f"Option {v_flag} is not valid for command {command}")

    raw_endpoint = values.get("--endpoint") or env_map.get("TITAN_MCP_ENDPOINT") or DEFAULT_ENDPOINT
    endpoint = validate_endpoint(raw_endpoint)
    timeout_ms = resolve_timeout_ms(env_map)
    pubkey_b64 = validate_pubkey_b64(values["--pubkey"]) if "--pubkey" in values else DEFAULT_AUTHORITY_PUBKEY_B64

    opts: Dict[str, Any] = {
        "action": "run",
        "command": command,
        "json": "--json" in bools,
        "verify_signature": "--verify-signature" in bools,
        "pubkey_b64": pubkey_b64,
        "endpoint": endpoint,
        "timeout_ms": timeout_ms,
        "rpc_payload": None,
    }

    if command == "catalog":
        opts["rpc_payload"] = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 1,
        }
    elif command == "check-cbam":
        if "--cn-or-hs" not in values:
            raise CliUsageError("Missing required option: --cn-or-hs")
        cn_or_hs = validate_hs_cn_code(values["--cn-or-hs"])
        regime = (
            parse_enum("--regime", values["--regime"], ["cbam", "eudr", "both"])
            if "--regime" in values
            else "cbam"
        )
        annual_mass = (
            parse_bounded_float("--annual-mass", values["--annual-mass"], 0, 1_000_000_000_000)
            if "--annual-mass" in values
            else None
        )
        plot_area = (
            parse_bounded_float("--plot-area", values["--plot-area"], 0, 1_000_000_000_000)
            if "--plot-area" in values
            else None
        )
        ring_closed = "--ring-closed" in bools

        rpc_args: Dict[str, Any] = {
            "regime": regime,
            "cn_or_hs_code": cn_or_hs,
        }
        if annual_mass is not None:
            rpc_args["annual_mass_tonnes"] = annual_mass
        if plot_area is not None:
            rpc_args["plot_hectares"] = plot_area
        rpc_args["geojson_ring_closed"] = ring_closed
        rpc_args["query_note"] = "CLI diagnostic"

        opts["rpc_payload"] = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "check_eu_cbam_eudr_mandate",
                "arguments": rpc_args,
            },
            "id": 1,
        }
    elif command == "check-179d":
        if "--sqft" not in values:
            raise CliUsageError("Missing required option: --sqft")
        sqft = parse_bounded_float("--sqft", values["--sqft"], 0, 1_000_000_000_000)
        mandate = (
            parse_enum("--mandate", values["--mandate"], ["irs_179d", "cmmc_sprs", "both"])
            if "--mandate" in values
            else "irs_179d"
        )
        wage_met = "--wage-met" in bools
        exempt = "--exempt" in bools
        sprs = parse_bounded_int("--sprs", values["--sprs"], -203, 110) if "--sprs" in values else None
        cui_fci = (
            parse_enum("--cui-fci", values["--cui-fci"], ["none", "fci", "cui"])
            if "--cui-fci" in values
            else None
        )

        rpc_args = {
            "mandate": mandate,
            "building_sqft": sqft,
            "prevailing_wage_met": wage_met,
            "tax_exempt_allocation": exempt,
        }
        if sprs is not None:
            rpc_args["sprs_score"] = sprs
        if cui_fci is not None:
            rpc_args["handles_cui_or_fci"] = cui_fci
        rpc_args["query_note"] = "CLI diagnostic"

        opts["rpc_payload"] = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "check_irs_179d_cmmc_readiness",
                "arguments": rpc_args,
            },
            "id": 1,
        }
    elif command in ("check-einvoice", "check-qfzp"):
        if "--non-qual-pct" not in values:
            raise CliUsageError("Missing required option: --non-qual-pct")
        if "--non-qual-aed" not in values:
            raise CliUsageError("Missing required option: --non-qual-aed")
        pct = parse_bounded_float("--non-qual-pct", values["--non-qual-pct"], 0, 100)
        aed = parse_bounded_float("--non-qual-aed", values["--non-qual-aed"], 0, 1_000_000_000_000_000)
        excluded = "--excluded" in bools
        eu_subjects = "--eu-subjects" in bools
        high_risk = "--high-risk" in bools

        rpc_args = {
            "regime": "uae_qfzp" if command == "check-einvoice" else "both",
            "non_qualifying_pct": pct,
            "non_qualifying_aed": aed,
            "excluded_activity": excluded,
            "eu_data_subjects": eu_subjects,
            "high_risk_processing": high_risk,
            "query_note": "CLI diagnostic",
        }

        opts["rpc_payload"] = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "check_uae_qfzp_gdpr_trigger",
                "arguments": rpc_args,
            },
            "id": 1,
        }

    return opts


def send_json_rpc(endpoint: ParsedEndpoint, rpc_payload: Dict[str, Any], timeout_ms: int) -> Any:
    timeout_sec = timeout_ms / 1000.0
    deadline = time.monotonic() + timeout_sec
    body_bytes = json.dumps(rpc_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    conn: Optional[http.client.HTTPConnection] = None
    try:
        if endpoint.scheme == "https":
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(
                endpoint.host,
                endpoint.port,
                timeout=timeout_sec,
                context=ctx,
            )
        else:
            conn = http.client.HTTPConnection(
                endpoint.host,
                endpoint.port,
                timeout=timeout_sec,
            )

        try:
            conn.request(
                "POST",
                endpoint.path_and_query,
                body=body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Content-Length": str(len(body_bytes)),
                    "User-Agent": USER_AGENT,
                    "Connection": "close",
                },
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UpstreamError("Request timed out")
            if conn.sock is not None:
                conn.sock.settimeout(remaining)
            resp = conn.getresponse()
        except UpstreamError:
            raise
        except (TimeoutError, socket.timeout) as exc:
            raise UpstreamError("Request timed out") from exc
        except (OSError, http.client.HTTPException) as exc:
            if time.monotonic() >= deadline:
                raise UpstreamError("Request timed out") from exc
            raise UpstreamError("Network connection failure") from exc

        status = resp.status
        if status < 200 or status >= 300:
            raise UpstreamError(f"HTTP {status}")

        cl_header = resp.getheader("Content-Length")
        if cl_header is not None:
            try:
                declared_len = int(cl_header.strip())
                if declared_len > MAX_BODY_BYTES:
                    raise UpstreamError("Response exceeds 2 MiB limit")
            except ValueError:
                pass

        chunks: List[bytes] = []
        total_bytes = 0

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UpstreamError("Request timed out")
            if conn.sock is not None:
                conn.sock.settimeout(remaining)
            try:
                chunk = resp.read(16384)
            except (TimeoutError, socket.timeout) as exc:
                raise UpstreamError("Request timed out") from exc
            except http.client.IncompleteRead as exc:
                if time.monotonic() >= deadline:
                    raise UpstreamError("Request timed out") from exc
                raise UpstreamError("Upstream closed connection prematurely") from exc
            except (OSError, http.client.HTTPException) as exc:
                if time.monotonic() >= deadline:
                    raise UpstreamError("Request timed out") from exc
                raise UpstreamError("Network read failure") from exc

            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_BODY_BYTES:
                raise UpstreamError("Response exceeds 2 MiB limit")
            chunks.append(chunk)

        if cl_header is not None:
            try:
                expected_len = int(cl_header.strip())
                if expected_len >= 0 and total_bytes < expected_len:
                    raise UpstreamError("Upstream closed connection prematurely")
            except ValueError:
                pass

        full_bytes = b"".join(chunks)
        try:
            text = full_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise UpstreamError("Invalid JSON response") from exc

        try:
            parsed = json.loads(text, parse_constant=_reject_json_constant)
            return _normalize_js_numbers(parsed)
        except Exception as exc:
            raise UpstreamError("Invalid JSON response") from exc
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def process_envelope(envelope: Any, opts: Dict[str, Any]) -> str:
    if not _is_plain_object(envelope):
        raise UpstreamError("Malformed JSON-RPC envelope")

    if "error" in envelope and envelope["error"] is not None:
        err_obj = envelope["error"]
        msg = (
            _sanitize_log_line(err_obj["message"])
            if _is_plain_object(err_obj) and isinstance(err_obj.get("message"), str)
            else "RPC error"
        )
        raise UpstreamError(msg or "RPC error", prefix="MCP Error")

    result = envelope.get("result")
    if not _is_plain_object(result):
        raise UpstreamError("Missing JSON-RPC result object")

    if result.get("isError") is True:
        raise UpstreamError("Tool reported execution error", prefix="MCP Error")

    if opts["command"] == "catalog":
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise UpstreamError("Invalid tools catalog payload")
        clean_tools: List[Dict[str, Any]] = []
        for item in tools:
            if not _is_plain_object(item) or not isinstance(item.get("name"), str):
                raise UpstreamError("Invalid tools catalog payload")
            clean_tools.append(item)
        if opts["json"]:
            return _json_dumps_pretty({"tools": clean_tools}) + "\n"
        lines = ["Available statutory tools:"]
        for tool in clean_tools:
            name = _sanitize_log_line(tool["name"])
            desc_raw = tool.get("description")
            desc = _sanitize_log_line(desc_raw) if isinstance(desc_raw, str) else ""
            lines.append(f"  - {name}: {desc}")
        return "\n".join(lines) + "\n"

    sc = result.get("structuredContent")
    payload = sc if _is_plain_object(sc) else result

    if opts["verify_signature"] or isinstance(payload.get("signature_b64"), str):
        canonical = payload.get("canonical_payload")
        receipt = payload.get("gate_receipt_sha256")
        signed_text = (
            canonical
            if isinstance(canonical, str)
            else (receipt if isinstance(receipt, str) else None)
        )
        sig_b64 = payload.get("signature_b64")
        sig_ok = (
            verify_ed25519(signed_text.encode("utf-8"), sig_b64, opts["pubkey_b64"])
            if signed_text is not None and isinstance(sig_b64, str)
            else False
        )
        if opts["verify_signature"] and not sig_ok:
            raise UpstreamError("Ed25519 signature verification failed")

    json_block = _json_dumps_pretty(payload)
    if opts["json"]:
        return json_block + "\n"

    checkout_url = ""
    routing = payload.get("settlement_routing")
    if _is_plain_object(routing) and isinstance(routing.get("official_checkout_url"), str):
        checkout_url = routing["official_checkout_url"]
    elif isinstance(payload.get("checkout_url"), str):
        checkout_url = payload["checkout_url"]

    if checkout_url.startswith("https://") and not CONTROL_CHAR_RE.search(checkout_url):
        return f"{json_block}\n\nDirect Checkout URL: {checkout_url}\n"
    return f"{json_block}\n"


def run_cli(
    argv: Sequence[str],
    env: Optional[Dict[str, str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    out_stream = sys.stdout if stdout is None else stdout
    err_stream = sys.stderr if stderr is None else stderr

    try:
        opts = parse_cli_args(argv, env)
    except CliUsageError as exc:
        err_stream.write(f"Error: {exc}\n")
        return 2
    except Exception:
        err_stream.write("Error: Invalid CLI arguments\n")
        return 2

    if opts["action"] == "help":
        out_stream.write(f"{USAGE_TEXT}\n")
        return 0
    if opts["action"] == "version":
        out_stream.write(f"titan-statutory-cli {CLI_VERSION}\n")
        return 0

    try:
        envelope = send_json_rpc(opts["endpoint"], opts["rpc_payload"], opts["timeout_ms"])
        out_text = process_envelope(envelope, opts)
        out_stream.write(out_text)
        return 0
    except UpstreamError as exc:
        err_stream.write(f"{exc.prefix}: {exc}\n")
        return 3
    except Exception:
        err_stream.write("Upstream Error: Unexpected transport failure\n")
        return 3


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    return run_cli(args)


def entry_check_cbam() -> int:
    return run_cli(["check-cbam", *sys.argv[1:]])


def entry_check_179d() -> int:
    return run_cli(["check-179d", *sys.argv[1:]])


def entry_check_einvoice() -> int:
    return run_cli(["check-einvoice", *sys.argv[1:]])


def entry_check_qfzp() -> int:
    return run_cli(["check-qfzp", *sys.argv[1:]])


def entry_catalog() -> int:
    return run_cli(["catalog", *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())
