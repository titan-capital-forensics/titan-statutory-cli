# TITAN Statutory Gate CLI

Zero-dependency statutory applicability diagnostics for TITAN Capital Forensics LLC.

## Installation
```bash
# Clone the repository
# Make it executable
chmod +x bin/cli.js
# Test it
npx titan-statutory catalog
```

## Usage
```bash
npx titan-statutory catalog                    # List available tools
npx titan-statutory check-cbam --cn-or-hs 7208  # Check EU CBAM applicability
npx titan-statutory check-179d --sqft 5000     # Check IRS Section 179D readiness
npx titan-statutory check-einvoice --non-qual-pct 25 --non-qual-aed 50000  # UAE QFZP/GDPR
npx titan-statutory check-qfzp --non-qual-pct 25 --non-qual-aed 50000      # UAE QFZP de-minimis
```

## CLI Commands
- `check-cbam`: EU Carbon Border Adjustment Mechanism (Reg 2023/956)
- `check-179d`: IRS Section 179D tax readiness (Form 7205)
- `check-einvoice`: UAE QFZP/GDPR applicability diagnostics
- `check-qfzp`: UAE QFZP 0% de-minimis cliff check
- `catalog`: List all available statutory tools

All commands call the live MCP endpoint `https://mcp.titancapitalforensics.com/mcp` and return strictly diagnostic applicability/penalty alerts with zero freebies cannibalizing paid deliverables.

## Architecture
- Python implementation at `titan_statutory/cli.py` using only stdlib
- Node wrapper `bin/cli.js` for cross-platform compatibility
- Direct MCP JSON-RPC 2.0 communication
- Ed25519 verification support (optional)
- Zero external dependencies