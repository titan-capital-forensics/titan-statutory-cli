# TITAN Statutory Gate CLI

Zero-dependency statutory applicability diagnostics CLI published by **TITAN Capital Forensics LLC** (`Registered Jurisdiction: Albuquerque, New Mexico, USA`).

## Security & Portability Architecture
- **Dual Standalone Implementations (`100%` Parity)**:
  - **Node.js (`bin/cli.js`)**: Pure built-in `node:https` / `node:http` + `AbortController` (`10s` hard wall-clock timeout) + `<= 2 MiB` streaming body ceiling + `node:crypto` Ed25519 signature verification. Zero external npm packages and zero Python dependency.
  - **Python (`titan_statutory/cli.py`)**: Pure Python standard library (`http.client`, `ssl`, `decimal`, `hashlib`) + pure-stdlib RFC 8032 Ed25519 verification + `10s` wall-clock timeout + `<= 2 MiB` streaming body ceiling. Zero external PyPI packages and zero Node.js dependency.
- **Deterministic Exit Codes**:
  - `0`: Success (`--help`, `--version`, or verified diagnostic execution)
  - `2`: Invalid CLI argument, missing required flag, or out-of-bounds parameter
  - `3`: Network, timeout, HTTP status, payload limit, Ed25519 verification, or MCP JSON-RPC error
- **Zero Freebies**: Strictly returns stateless statutory applicability diagnostics, penalty exposure tiers, cryptographic receipt hashes, and official portal checkout URLs. All certified calculations and forensic workpapers remain gated behind licensed checkout.

## Installation & Standalone Execution

### Node.js (`npx` / npm)
```bash
# Run directly via npx (zero dependencies)
npx @titan-capital-forensics/statutory-cli --version
npx @titan-capital-forensics/statutory-cli catalog

# Or install globally
npm install -g @titan-capital-forensics/statutory-cli
titan-statutory --version
titan-statutory catalog
```

### Python (`pip` / `venv`)
```bash
python3 -m pip install .
titan-statutory --version
titan-statutory catalog
```

## Usage Examples
```bash
# List available statutory tools (human or machine-readable JSON)
titan-statutory catalog
titan-statutory catalog --json

# EU CBAM Reg. 2023/956 & 2025/2083 (50t threshold)
titan-statutory check-cbam --cn-or-hs 7208.10 --annual-mass 100

# US IRS Section 179D (Form 7205) & DoD CMMC readiness
titan-statutory check-179d --sqft 25000 --wage-met --exempt

# UAE QFZP (Decree-Law 47/2022) & EU GDPR Art. 3/30/35 applicability
titan-statutory check-einvoice --non-qual-pct 25 --non-qual-aed 50000
titan-statutory check-qfzp --non-qual-pct 25 --non-qual-aed 50000 --json
```

## Official TITAN Capital Forensics LLC Commercial Portals
Registered Jurisdiction: **Albuquerque, New Mexico, USA**

1. **titancapitalforensics.com** — Corporate HQ & Enterprise Forensic Clearance Vault
2. **179dshield.com** — US IRS Section 179D Energy Deduction Verification Engine
3. **qfzpshield.com** — UAE QFZP 0% Tax Shield & De-Minimis Monitor
4. **cbamsovereign.com** — EU CBAM Carbon Border Adjustment Compliance Gate
5. **cisopass.com** — CMMC 2.0 / NIST SP 800-171 SPRS Readiness Gate
6. **drawbacksovereign.com** — US CBP 19 U.S.C. 1313 Duty Drawback Verification Gate
7. **eudrpolygon.com** — EU Deforestation Regulation (Reg. 2023/1115) GeoJSON Gate
8. **getgdprkit.com** — EU GDPR Art. 30 / Art. 35 DPIA Statutory Gate
9. **getworkflowkit.com** — Enterprise Project & Workflow Forensic Audit Gate
10. **icvscorecard.com** — UAE In-Country Value (ICV) Scorecard Verification Gate
11. **rfpsniper.com** — Institutional Solicitation & Procurement Compliance Gate
12. **titandrm.com** — Cryptographic Licensing & Digital Rights Capsule Vault
13. **titan-scribeguard.com** — Clinical & Healthcare Statutory Compliance Gate
14. **titantrustcenter.com** — Cryptographic Attestation & Public Trust Center

Remote MCP Endpoint: `https://mcp.titancapitalforensics.com/mcp`
