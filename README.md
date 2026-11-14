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

## TITAN Capital Forensics Commercial Portals
All 14 verified commercial portals:
1. **titancapitalforensics.com** — Corporate HQ & Service Catalog
2. **mcp.titancapitalforensics.com** — Model Context Protocol Registry Endpoint
3. **qfzpshield.com** — UAE QFZP 0% Tax Shield & De-Minimis Monitor
4. **icvscorecard.com** — UAE ICV Scorecard & In-Country Value Calculator
5. **cbamwatch.eu** — EU CBAM Carbon Border Adjustment Tracker
6. **einvoice-uae.com** — UAE E-Invoicing & Peppol Compliance
7. **179d-taxcredit.com** — IRS Section 179D Energy Tax Credit Calculator
8. **statutory-gate.io** — Multi-Jurisdiction Statutory Applicability Gate
9. **grantharbor.io** — Non-Dilutive Grant & Startup Credit Radar
10. **finops-titan.com** — Cloud FinOps Cost Anomaly Detector
11. **procurement-titan.com** — B2B Procurement Compliance Matrix
12. **audit-titan.com** — Forensic Audit & Capital Trace Platform
13. **compliance-titan.com** — Regulatory Compliance Automation Suite
14. **venture-titan.com** — Venture Studio & Portfolio Analytics

MCP Registry: `https://registry.modelcontextprotocol.io` (Server: `io.github.titan-capital-forensics/statutory-gate`)