<div align="center">

# ThreatLens

### Intelligent Web Threat Intelligence & Trust Infrastructure Platform

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue?logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-47%20Passed%20(100%25)-success?logo=pytest&logoColor=white)](https://pytest.org)
[![Security](https://img.shields.io/badge/SSRF%20Guard-Enforced-green?logo=shield&logoColor=white)](#defensive-engineering--ssrf-safety)
[![PKI](https://img.shields.io/badge/PKI-eMudhra%20Incident%20Detection-orange?logo=lock&logoColor=white)](#the-emudhra-incident--web-pki-trust-infrastructure)
[![Architecture](https://img.shields.io/badge/Pillars-4%20Integrated%20Engines-blueviolet)](#system-architecture--the-four-pillars)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

**A defensive cyber intelligence platform that unifies phishing and impersonation detection, web security posture evaluation, cryptographic certificate validation, and collaborative threat intelligence into an accessible, real-time command center.**

[Features](#key-capabilities) • [Architecture](#system-architecture--the-four-pillars) • [eMudhra Incident](#the-emudhra-incident--web-pki-trust-infrastructure) • [Quickstart](#quickstart) • [Web UI](#interactive-web-dashboard) • [API Reference](#api-reference) • [Test Suite](#testing--verification)

---

</div>

## Executive Summary

The modern internet underpins everyday societal infrastructure: banking, digital payments, recruitment, higher education, e-commerce, and governance. However, this dependence has introduced unprecedented systemic risks:

1. **Sophisticated Phishing & Social Engineering**: Attackers clone legitimate banking portals, payment links, and university recruitment boards using lookalike domains, Cyrillic/Greek homoglyphs, and nested subdomains to harvest net banking passwords, OTPs, MPINs, Aadhaar numbers, and credit card CVVs.
2. **Fragile Web PKI & Compromised Trust**: Digital certificates establish encrypted HTTPS connections and verify server identity. The recent **eMudhra Global TLS Incident** revealed how flawed Certificate Authority (CA) key-generation ceremonies can produce intermediate CAs with predictable private keys, potentially enabling malicious actors to forge valid certificates for any domain on earth.
3. **Application Security Misconfigurations**: Sites often leak source code or environment variables (`.git`, `.env`), run end-of-life software stacks, or omit foundational security headers (HSTS, CSP, Frame defense), leaving users vulnerable to clickjacking, session hijacking, and downgrade attacks.

Existing security tools examine these threat vectors in silos: a reputation blacklist does not analyze TLS certificate math, and a header scanner cannot detect whether a form is exfiltrating passwords to a rogue server.

**ThreatLens bridges this gap.** It evaluates websites across four independent angles and decouples the **Threat Score** (0–100, detecting fraud and harm) from the **Hardening Posture Grade** (A+ to F, evaluating defense-in-depth).

---

## System Architecture & The Four Pillars

```
                                    +-----------------------+
                                    |   Target URL / Host   |
                                    +-----------+-----------+
                                                |
                                    +-----------v-----------+
                                    |   Safe Network Fetch  |
                                    | (SSRF Guard, IP Audit)|
                                    +-----------+-----------+
                                                |
        +-----------------------+---------------+---------------+-----------------------+
        |                       |                               |                       |
+-------v-------+       +-------v-------+               +-------v-------+       +-------v-------+
|  1. THREAT &  |       |    2. WEB     |               | 3. CERTIFICATE|       |   4. THREAT   |
|   PHISHING    |       |   SECURITY    |               |  VALIDATION   |       | INTELLIGENCE  |
+---------------+       +---------------+               +---------------+       +---------------+
| • Typosquats  |       | • HSTS & CSP  |               | • Full Chain  |       | • Salted HMAC |
| • Homoglyphs  |       | • Frame Def.  |               | • Fermat Fact.|       | • Time Decay  |
| • IDN Punycode|       | • MIME Sniff  |               | • ROCA Check  |       | • Confirm/    |
| • Form Harvest|       | • Referrer &  |               | • Batch GCD   |       |   Dispute     |
|   (PAN/OTP)   |       |   Permissions |               | • eMudhra CA  |       | • Anti-Abuse  |
| • Cross-Domain|       | • Cross-Origin|               | • RFC 6962 CT |       | • Threat Feed |
| • APK Trojans |       | • EOL Banners |               | • CABF Limits |       |   Export      |
| • Job Scams   |       | • Gated Expos.|               | • Safe Curves |       |   (CSV/JSON)  |
+-------+-------+       +-------+-------+               +-------+-------+       +-------+-------+
        |                       |                               |                       |
        +-----------------------+---------------+---------------+-----------------------+
                                                |
                                    +-----------v-----------+
                                    |  ThreatLens Scoring   |
                                    |  Engine & Correlator  |
                                    +-----------+-----------+
                                                |
                       +------------------------+------------------------+
                       |                                                 |
             +---------v---------+                             +---------v---------+
             |   Threat Score    |                             |  Hardening Grade  |
             |   (0 - 100 Risk)  |                             |   (A+ through F)  |
             +-------------------+                             +-------------------+
```

---

## The eMudhra Incident & Web PKI Trust Infrastructure

### Incident Forensics & Context
In October 2026, **eMudhra** publicly disclosed that **eight intermediate Certificate Authorities** in its global Web PKI TLS hierarchy were issued using weak, predictable private keys. The root cause was traced back to a flawed key-generation ceremony conducted on 30 April 2025 where the cryptographic pseudo-random number generator (PRNG) lacked adequate physical entropy.

Because intermediate CAs possess subordinate signing authority, compromised or predictable intermediate keys represent a critical risk to the global web:
- **Global Impersonation**: Anyone possessing the predictable private key can forge valid, browser-trusted TLS certificates for any domain (e.g. `google.com`, `onlinesbi.sbi`, `chase.com`) without the domain owner's knowledge or consent.
- **Bypassing Traditional Controls**: Because the certificate appears cryptographically signed by an intermediate chaining to a trusted root, standard browser validation passes silently.
- **Root Store Distrust**: In response, Google Chrome Root Program and Mozilla OneCRL actively blocked the affected intermediate certificates, and eMudhra announced its phased departure from the global public TLS business.

### How ThreatLens Protects Against CA Compromises
1. **Chain-Wide Traversal**: ThreatLens inspects every certificate in the chain (leaf, intermediates, and roots), parsing RFC 4514 Subject and Issuer DNs and calculating SubjectPublicKeyInfo (SPKI) SHA-256 digests.
2. **Dynamic Distrust Engine (`distrusted.json`)**: Real-time pattern matching flags certificates chaining to intermediate CAs under public incident scrutiny (eMudhra, WoSign, StartCom, DigiNotar, CNNIC, TrustCor).
3. **Fermat Factorization & Close-Prime Audit**: Automatically tests RSA moduli for Fermat factorability ($|p - q| < 2^{b/2}$), which cracks moduli in milliseconds when prime generators are flawed.
4. **Batch GCD Shared-Prime Detection**: Cross-references new public keys against historical certificates in ThreatLens SQLite storage. If $\gcd(n_1, n_2) > 1$, both private keys can be calculated via Euclidean division, flagging broken PRNGs across unrelated certificates.
5. **Certificate Transparency (CT) Auditing**: Enforces RFC 6962 embedded Signed Certificate Timestamps (SCTs) and queries public CT log indices (crt.sh).

---

## Key Capabilities

### 1. Phishing & Threat Analysis Engine
- **Address & Domain Heuristics**:
  - Typosquatting detection using Levenshtein distance metrics against major brand names.
  - Cyrillic and Greek lookalike homoglyph replacement detection (e.g. `pаypal.com` with Cyrillic `а`).
  - Punycode IDN decoding (`xn--`).
  - Brand-in-subdomain deceptive nesting (`www.sbi.co.in.kyc-update.top`).
  - IP hostnames (decimal, octal, hex, dword representations).
  - High-risk disposable TLDs (`.top`, `.xyz`, `.buzz`, `.online`).
- **Comprehensive Brand Registry**:
  - **Banking & Finance**: State Bank of India, HDFC Bank, ICICI Bank, Axis Bank, Kotak Mahindra, Punjab National Bank, Bank of Baroda, Chase, Wells Fargo, Bank of America, Citibank, Barclays.
  - **Digital Payments**: Paytm, PhonePe, UPI/NPCI, Razorpay, Stripe, PayPal, Binance, Coinbase.
  - **Education & Employment**: Naukri, Indeed, Foundit, Coursera, National Scholarship Portal.
  - **Government Services**: Aadhaar (UIDAI), Income Tax India, Passport Seva, Parivahan, GST Portal, IRCTC, India Post, EPFO, DigiLocker.
  - **E-Commerce & Tech**: Amazon, Flipkart, Meesho, Myntra, Google, Microsoft, Apple, Meta, Netflix.
- **Page Content & Harvesting Heuristics**:
  - Input fields capturing net banking credentials, OTPs, MPINs, PAN, Aadhaar, credit card numbers, and CVVs.
  - **Cross-Domain Exfiltration**: Login forms hosted on one domain that submit credentials to an external host or downgrade from HTTPS to HTTP.
  - **Advance-Fee Recruitment Scams**: Detects job offers demanding registration fees, refundable deposits, or laptop training fees.
  - **Deceptive Mobile APKs**: Identifies prompts instructing targets to sideload unverified `.apk` packages (banking Trojans / remote access tools).
  - **Coercion & Urgency Language**: "Account suspended within 24 hours", "KYC expired", "Immediate action required".
  - Obfuscated JavaScript detection (`eval()`, `unescape()`, `String.fromCharCode`, hex escapes).

### 2. Web Security Posture Assessment
- **HTTP Security Headers Audit**:
  - `Strict-Transport-Security` (HSTS): Enforces minimum max-age of 15,552,000s (180 days), checks `includeSubDomains` and `preload`.
  - `Content-Security-Policy` (CSP): Audits for `default-src`, `script-src`, `object-src`, `frame-ancestors`, and flags `'unsafe-inline'` / `'unsafe-eval'`.
  - `X-Frame-Options`: Anti-clickjacking verification (`DENY`, `SAMEORIGIN`).
  - `X-Content-Type-Options`: Enforces `nosniff` MIME-type protection.
  - `Referrer-Policy`: Validates strict origin referrer handling.
  - `Permissions-Policy`: Audits camera, microphone, and geolocation restrictions.
  - `Cross-Origin-Opener-Policy` (COOP) & `Cross-Origin-Resource-Policy` (CORP).
  - CORS security: Flags wildcard origins combined with credentials (`Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`).
- **Authorization-Gated Sensitive File Audit**:
  - Checks for publicly readable `.env`, `.git/HEAD`, `wp-config.php.bak`, `server-status`, `phpinfo.php`, and `.DS_Store`.
  - *Safety constraint: Only executes when the `--authorized` flag is explicitly set.*
- **Software End-of-Life (EOL) Discovery**:
  - Scans server banners (`Server`, `X-Powered-By`) to identify obsolete, unsupported software (Apache < 2.4, PHP < 8.2, IIS < 10, OpenSSL < 1.1.1, Python < 3).
- **Cookie Security Flags**:
  - Verifies `Secure`, `HttpOnly`, and `SameSite` attributes on sensitive session cookies.

### 3. Certificate & Cryptographic Health
- **Full X.509 Chain Verification**: Traverses and verifies leaf, intermediate, and root certificates against modern CA stores using `certifi`.
- **Fermat Factorization**: Rapidly detects RSA keys with close prime factors ($|p - q| < 2^{b/2}$).
- **ROCA Fingerprint (CVE-2017-15361)**: Subgroup residue testing across primes $p_i \le 167$ for the Infineon flawed key generator.
- **Trial Division Small Prime Factors**: Tests moduli against primes up to 10,000 to identify broken RNGs.
- **CAB Forum Validity Limits**: Flags public leaf certificates with lifetimes exceeding 398 days or newly minted certificates ($\le 3$ days old).
- **Safe Elliptic Curves**: Verifies that ECC keys strictly utilize approved curves (`secp256r1`, `secp384r1`, `secp521r1`).

### 4. Collaborative Threat Intelligence
- **Privacy-Preserving Reporter Hashing**: Reporters are hashed with keyed HMAC-SHA256 (`THREATLENS_SALT`), preventing tracking while blocking ballot-stuffing.
- **Bayesian Time Decay**: Report influence decays via a 14-day half-life formula:
  $$\text{weight} = 0.5^{\frac{\Delta t}{14 \times 86400}}$$
  Ensures stale reports fade as sites remediate issues.
- **Community Consensus**: Supports independent community reports and confirm/dispute voting.
- **Anti-Brigading Brand Protection**: Verified brand domains cannot be brigaded into malicious status without technical corroboration.
- **Threat Feed Export**: Live export of high-confidence indicators of compromise (IOCs) in CSV and JSON formats.

---

## Defensive Engineering & SSRF Safety

ThreatLens follows strict security-first principles when communicating with third-party web targets:

| Control | Implementation Detail |
| :--- | :--- |
| **SSRF Prevention** | Resolves hosts before connecting and validates that IP addresses do not belong to private (RFC 1918), carrier-grade NAT (RFC 6598), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), multicast, or cloud metadata endpoints (`169.254.169.254`). Sockets connect directly to the validated IP with SNI preserved. |
| **Port Allowlist** | Restricts outbound scanning strictly to standard web ports: `80`, `443`, `8080`, and `8443`. |
| **Redirect Limits** | Caps redirects at 5 hops. Each redirect target is independently resolved and validated against SSRF rules before following. |
| **Resource Caps** | Enforces a strict 6-second connection/read timeout and truncates HTTP response bodies at 2 MB to prevent memory exhaustion (decompression bombs). |
| **Zero Sensitive Caching** | Does not store raw passwords, tokens, or personal data. URLs are stripped of query parameters and fragments before persisting to the intelligence database. |

---

## Quickstart

### Prerequisites
- Python 3.10 or higher
- Supported OS: Windows, Linux, macOS

### 1. Installation
```bash
git clone https://github.com/ssohini/hackmatrix.git
cd hackmatrix
python -m pip install -r requirements.txt
```

### 2. Run the Web Dashboard
```bash
# Set a random salt for privacy-preserving reporter hashing
export THREATLENS_SALT="use-a-strong-random-salt-here"

# Start the Flask web application
python run.py serve --host 127.0.0.1 --port 8080
```
Open **`http://127.0.0.1:8080`** in your browser.

### 3. Command-Line Scanning
```bash
# Standard URL scan
python run.py scan https://example.com

# Structured JSON output
python run.py scan https://example.com --json

# Authorized deep scan (with exposed sensitive files audit)
python run.py scan https://yoursite.com --deep --authorized

# Import third-party threat feed
python run.py import-feed feed.txt --source openphish --category phishing
```

---

## Interactive Web Dashboard

The web dashboard is built using pure, accessible vanilla JavaScript and semantic HTML5 (zero bloat, zero heavy frameworks):

- **Quick-Click Test Presets**:
  - `[🏦 SBI KYC Phish]`: Demonstrates brand spoofing, urgent suspension threats, and OTP/PAN credential harvesting.
  - `[💼 Fake Job Offer]`: Demonstrates recruitment advance-fee scams and deceptive APK download prompts.
  - `[🔐 eMudhra Incident]`: Demonstrates detection of distrusted intermediate CAs and unlogged certificates.
  - `[🧮 Weak Fermat Key]`: Demonstrates detection of an RSA-2048 modulus factorable via Fermat's algorithm ($|p - q| < 2000$).
  - `[🛡️ Hardened Bank]`: Clean reference baseline with TLS 1.3, HSTS preloading, and an A+ posture rating.
- **Certificate & Cryptography Lab**: Inspect any live host or paste raw PEM certificate text to evaluate cryptographic public key strength and check against distrust blocklists.
- **Collaborative Threat Feed Explorer**: Filter the live community threat feed by category (Phishing, Payment Scams, Recruitment) and click **Export CSV** to download the feed directly.
- **Web Security Hardening Guide**: Production-ready Nginx and Apache configuration snippets to remediate headers and achieve an A+ posture score.

---

## API Reference

### `POST /api/scan`
Scan any URL across all four engines.
```bash
curl -X POST http://127.0.0.1:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "deep": false, "authorized": false}'
```

<details>
<summary>Sample Response</summary>

```json
{
  "url": "https://example.com",
  "host": "example.com",
  "verdict": {
    "label": "Low risk",
    "level": "ok",
    "threat_score": 0,
    "confidence": "high",
    "summary": "No strong signs of phishing or malicious behaviour were found.",
    "advice": []
  },
  "posture": {
    "grade": "D",
    "score": 62
  },
  "findings": [
    {
      "id": "sec.no_hsts",
      "severity": "medium",
      "title": "Strict-Transport-Security header is missing",
      "detail": "Browsers can be tricked into using HTTP on first visit."
    }
  ],
  "certificate": {
    "trusted": true,
    "key": "EC secp256r1",
    "transparency": { "embedded_scts": 2 }
  }
}
```
</details>

### `POST /api/cert/inspect`
Cryptographically audit any live host or raw PEM certificate chain.
```bash
curl -X POST http://127.0.0.1:8080/api/cert/inspect \
  -H "Content-Type: application/json" \
  -d '{"pem": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"}'
```

### `POST /api/demo/run`
Execute any built-in threat scenario.
```bash
curl -X POST http://127.0.0.1:8080/api/demo/run \
  -H "Content-Type: application/json" \
  -d '{"scenario": "emudhra_compromised_ca"}'
```

### `GET /api/feed/export`
Export the verified threat intelligence feed as CSV or JSON.
```bash
# Export as RFC 4180 CSV
curl "http://127.0.0.1:8080/api/feed/export?format=csv" -o threatlens-feed.csv

# Export as JSON
curl "http://127.0.0.1:8080/api/feed/export?format=json"
```

### `POST /api/report`
Submit an indicator to the community database.
```bash
curl -X POST http://127.0.0.1:8080/api/report \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.xyz/login", "category": "phishing", "comment": "Asks for SBI NetBanking password"}'
```

### `POST /api/vote`
Vote to confirm harm or dispute a false positive.
```bash
curl -X POST http://127.0.0.1:8080/api/vote \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.xyz/login", "vote": "confirm"}'
```

### `GET /api/stats`
Retrieve platform metrics and threat counters.
```bash
curl http://127.0.0.1:8080/api/stats
```

---

## Testing & Verification

ThreatLens includes a test suite covering unit tests, live local HTTPS end-to-end tests, and enhancement verifications.

```powershell
python -m pytest
```

```
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\user\Downloads\HackMatrix\HackMatrix
configfile: pytest.ini
testpaths: tests
collected 47 items

tests\test_e2e.py ................                                       [ 34%]
tests\test_enhancements.py ......                                        [ 46%]
tests\test_unit.py .........................                             [100%]

======================== 47 passed in 72.43s (0:01:12) ========================
```

- **`tests/test_e2e.py`**: Spins up real local HTTPS servers generating live RSA and EC keys to test Fermat factorization ($|p - q| < 2000$), shared primes across certificates (Batch GCD), untrusted roots, self-signed certificates, and hostname mismatches.
- **`tests/test_unit.py`**: Unit tests for brand matching, typosquatting distance, Cyrillic homoglyphs, SSRF IP filtering, rate limiting, and reputation time-decay.
- **`tests/test_enhancements.py`**: Verifies expanded brand matching (banking, payments, education), fake government schemes, demo scenario data integrity, and CSV feed export.

---

## Repository Structure

```
hackmatrix/
├── run.py                     # Unified CLI: serve, scan, import-feed
├── requirements.txt           # Production dependencies
├── pytest.ini                 # Pytest configuration
├── README.md                  # Complete documentation & architecture guide
├── index.html                 # Root frontend single-page dashboard
├── styles.css                 # Root stylesheet (light & dark mode)
├── app.js                     # Root client-side application logic
├── threatlens.db              # Seeded SQLite threat intelligence database
├── threatlens/                # Core ThreatLens package
│   ├── __init__.py            # Package metadata & version
│   ├── config.py              # Environment configuration & paths
│   ├── models.py              # Finding data classes & severity ordering
│   ├── scoring.py             # Threat score & posture grade algorithms
│   ├── engine.py              # Multi-engine scan orchestrator
│   ├── netsafe.py             # SSRF prevention, IP validator & safe fetcher
│   ├── providers.py           # Optional Google Safe Browsing API provider
│   ├── domains.py             # Registered domain parser & brand matcher
│   ├── url_analyzer.py        # Typosquats, homoglyphs, Punycode & URL signals
│   ├── content_analyzer.py    # Credential harvest, forms, APK lures, urgency
│   ├── keychecks.py           # Fermat factorability, ROCA, trial division
│   ├── cert_analyzer.py       # Chain validator, eMudhra tracking, CT proofs
│   ├── web_security.py        # HTTP security headers, EOL software, exposures
│   ├── intel.py               # SQLite collaborative store, decay, voting, feeds
│   ├── demo.py                # 5 pre-configured realistic threat scenarios
│   ├── server.py              # Flask server, rate limiting, REST API routes
│   ├── data/
│   │   ├── brands.json        # 55+ verified brand rules & keyword mappings
│   │   └── distrusted.json    # eMudhra incident & distrusted CA watchlist
│   └── static/                # Packaged web assets
│       ├── index.html
│       ├── style.css
│       └── app.js
├── tests/                     # Automated test suite (47 tests)
│   ├── helpers.py             # CA creation, key generation & HTTPS test servers
│   ├── test_unit.py           # Unit tests for core algorithms
│   ├── test_e2e.py            # Live HTTPS server end-to-end tests
│   └── test_enhancements.py   # Tests for new brands, scams & export
└── backend/                   # Alternative FastAPI / SQLAlchemy microservice
    ├── main.py
    ├── models.py
    ├── schemas.py
    ├── database.py
    └── services/
```

---

## Configuration & Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `THREATLENS_SALT` | `change-me-in-production` | Secret salt used for privacy-preserving HMAC reporter hashing. |
| `THREATLENS_DB` | `./threatlens.db` | File path for the SQLite threat intelligence database. |
| `THREATLENS_CT_LOOKUP` | `0` | Set to `1` to query crt.sh for public Certificate Transparency logs. |
| `SAFE_BROWSING_API_KEY` | *(None)* | Optional API key to query Google Safe Browsing v4. |
| `THREATLENS_CA_FILE` | *(None)* | Path to an internal enterprise or lab CA bundle. |
| `THREATLENS_ALLOW_PRIVATE`| `0` | Disables SSRF protection. **Strictly for local testing / lab networks.** |

---

## Ethical Use & Responsible Security

ThreatLens is designed exclusively for defensive research, system administration, and personal protection.
- Active exposure testing (checking `.git/HEAD`, `.env`, etc.) sends additional probe requests and is gated behind an explicit `--authorized` confirmation flag.
- Never use ThreatLens to probe third-party infrastructure without explicit authorization.
- Threat verdicts are automated heuristics designed for decision support and risk triage, not definitive legal determinations.

---

## License

This project is licensed under the [MIT License](LICENSE).
