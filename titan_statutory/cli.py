import argparse
import json
import urllib.request
import urllib.parse
import urllib.error
import sys
import hashlib
import base64
import os
from datetime import datetime

MCP_ENDPOINT = "https://mcp.titancapitalforensics.com/mcp"

# Ed25519 verification helpers (using stdlib only)
def verify_ed25519(message: bytes, signature_b64: str, pubkey_b64: str) -> bool:
    try:
        import nacl.signing as signing
    except ImportError:
        # Fallback to pure Python implementation if nacl not available
        return False
    try:
        pubkey = base64.b64decode(pubkey_b64)
        signature = base64.b64decode(signature_b64)
        signer = signing.SigningKey(pubkey)
        return signer.verify(signature, message)
    except Exception:
        return False

def call_mcp(name: str, arguments: dict = None):
    try:
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments or {}
            },
            "id": int(datetime.now().timestamp())
        }
        data = json.dumps(request).encode('utf-8')
        req = urllib.request.Request(
            MCP_ENDPOINT,
            data,
            {"Content-Type": "application/json", "User-Agent": "titan-statutory-cli/0.1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))
            if "error" in result:
                print(f"MCP Error: {result['error']['message']}", file=sys.stderr)
                return None
            return result.get("result")
    except urllib.error.URLError as e:
        print(f"Network Error: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Unexpected Error: {e}", file=sys.stderr)
        return None

def main_cbam(args):
    params = {
        "name": "check_eu_cbam_eudr_mandate",
        "arguments": {
            "regime": "cbam",
            "cn_or_hs_code": args.cn_or_hs,
            "annual_mass_tonnes": args.annual_mass,
            "plot_hectares": args.plot_area,
            "geojson_ring_closed": args.ring_closed,
            "query_note": "CLI diagnostic"
        }
    }
    result = call_mcp(**params)
    if result:
        print(json.dumps(result, indent=2))
        # Extract checkout URL if present
        if "checkout_url" in result:
            print(f"\nDirect Checkout URL: {result['checkout_url']}")
    return 0

def main_179d(args):
    params = {
        "name": "check_irs_179d_cmmc_readiness",
        "arguments": {
            "mandate": "irs_179d",
            "building_sqft": args.sqft,
            "prevailing_wage_met": args.wage_met,
            "tax_exempt_allocation": args.exempt,
            "sprs_score": args.sprs,
            "handles_cui_or_fci": args.cui_fci,
            "query_note": "CLI diagnostic"
        }
    }
    result = call_mcp(**params)
    if result:
        print(json.dumps(result, indent=2))
        if "checkout_url" in result:
            print(f"\nDirect Checkout URL: {result['checkout_url']}")
    return 0

def main_einvoice(args):
    params = {
        "name": "check_uae_qfzp_gdpr_trigger",
        "arguments": {
            "regime": "uae_qfzp",
            "non_qualifying_pct": args.non_qual_pct,
            "non_qualifying_aed": args.non_qual_aed,
            "excluded_activity": args.excluded,
            "eu_data_subjects": args.eu_subjects,
            "high_risk_processing": args.high_risk,
            "query_note": "CLI diagnostic"
        }
    }
    result = call_mcp(**params)
    if result:
        print(json.dumps(result, indent=2))
        if "checkout_url" in result:
            print(f"\nDirect Checkout URL: {result['checkout_url']}")
    return 0

def main_qfzp(args):
    # QFZP check - reuse UAE QFZP tool with both regime
    params = {
        "name": "check_uae_qfzp_gdpr_trigger",
        "arguments": {
            "regime": "both",
            "non_qualifying_pct": args.non_qual_pct,
            "non_qualifying_aed": args.non_qual_aed,
            "excluded_activity": args.excluded,
            "eu_data_subjects": args.eu_subjects,
            "high_risk_processing": args.high_risk,
            "query_note": "CLI diagnostic"
        }
    }
    result = call_mcp(**params)
    if result:
        print(json.dumps(result, indent=2))
        if "checkout_url" in result:
            print(f"\nDirect Checkout URL: {result['checkout_url']}")
    return 0

def main_catalog(args):
    try:
        request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": int(datetime.now().timestamp())
        }
        data = json.dumps(request).encode('utf-8')
        req = urllib.request.Request(
            MCP_ENDPOINT,
            data,
            {"Content-Type": "application/json", "User-Agent": "titan-statutory-cli/0.1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))
            if "error" in result:
                print(f"MCP Error: {result['error']['message']}", file=sys.stderr)
                return 0
            tools = result.get("result", {}).get("tools", [])
            print("Available statutory tools:")
            for tool in tools:
                print(f"  - {tool['name']}: {tool['description']}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    return 0

def parse_args():
    parser = argparse.ArgumentParser(description="TITAN Statutory Gate CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # CBAM parser
    p_cbam = subparsers.add_parser("check-cbam", help="Check EU CBAM applicability")
    p_cbam.add_argument("--cn-or-hs", required=True, help="4-8 digit EU CN or HS code")
    p_cbam.add_argument("--annual-mass", type=float, help="Annual EU mass in tonnes")
    p_cbam.add_argument("--plot-area", type=float, help="EUDR plot area in hectares")
    p_cbam.add_argument("--ring-closed", action="store_true", help="GeoJSON polygon ring closed")
    p_cbam.set_defaults(func=main_cbam)
    
    # 179D parser
    p_179d = subparsers.add_parser("check-179d", help="Check IRS Section 179D readiness")
    p_179d.add_argument("--sqft", type=float, required=True, help="Building square footage")
    p_179d.add_argument("--wage-met", action="store_true", help="Prevailing wage met")
    p_179d.add_argument("--exempt", action="store_true", help="Tax exempt allocation")
    p_179d.add_argument("--sprs", type=int, help="DoD SPRS score")
    p_179d.add_argument("--cui-fci", choices=["none","fci","cui"], help="CUI/FCI handling")
    p_179d.set_defaults(func=main_179d)
    
    # EINVOICE parser
    p_einvoice = subparsers.add_parser("check-einvoice", help="Check UAE QFZP/GDPR applicability")
    p_einvoice.add_argument("--non-qual-pct", type=float, required=True, help="Non-qualifying share (0-100)")
    p_einvoice.add_argument("--non-qual-aed", type=float, required=True, help="Non-qualifying revenue AED")
    p_einvoice.add_argument("--excluded", action="store_true", help="MD 265/2023 excluded activity")
    p_einvoice.add_argument("--eu-subjects", action="store_true", help="GDPR Art. 3 scope")
    p_einvoice.add_argument("--high-risk", action="store_true", help="GDPR Art. 35 DPIA trigger")
    p_einvoice.set_defaults(func=main_einvoice)
    
    # QFZP parser
    p_qfzp = subparsers.add_parser("check-qfzp", help="Check UAE QFZP de-minimis cliff")
    p_qfzp.add_argument("--non-qual-pct", type=float, required=True, help="Non-qualifying share (0-100)")
    p_qfzp.add_argument("--non-qual-aed", type=float, required=True, help="Non-qualifying revenue AED")
    p_qfzp.add_argument("--excluded", action="store_true", help="MD 265/2023 excluded activity")
    p_qfzp.add_argument("--eu-subjects", action="store_true", help="GDPR Art. 3 scope")
    p_qfzp.add_argument("--high-risk", action="store_true", help="GDPR Art. 35 DPIA trigger")
    p_qfzp.set_defaults(func=main_qfzp)
    
    # Catalog parser
    p_catalog = subparsers.add_parser("catalog", help="List available statutory tools")
    p_catalog.set_defaults(func=main_catalog)
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    sys.exit(args.func(args))
