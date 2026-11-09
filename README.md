# ThreatLens: Intelligent Threat Detection & Trust Platform

**ThreatLens** is an advanced, defensive web threat intelligence platform that detects phishing, scam, and malicious websites by integrating four independent security pillars:

1. **Threat & Impersonation Analysis**: Address lookalikes, typosquatting, Cyrillic/Greek homoglyphs, brand-in-subdomain nesting, disposable TLDs, and credential-harvesting behavioral patterns (banking, recruitment, e-commerce, digital payments, and government services).
2. **Web Security Assessment**: Automated auditing of modern HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin isolation), protocol versions, cipher suites, cookie security flags, and authorization-gated sensitive file exposure tests (`.env`, `.git/HEAD`, `server-status`, `phpinfo.php`).
3. **Certificate Validation & Trust Infrastructure**: Deep cryptographic validation of leaf and intermediate X.509 certificates. Structural checks for RSA key size, Fermat factorability ($|p - q| < 2^{b/2}$), trial division small factor detection, ROCA fingerprinting (CVE-2017-15361), batch GCD shared-prime discovery across historical certificates, Certificate Transparency (RFC 6962 embedded SCTs and crt.sh query), and **active tracking of distrusted CAs including the eMudhra TLS Certificate incident**.
4. **Collaborative Threat Intelligence**: Decentralized community threat reporting and voting with privacy-preserving salted HMAC reporter hashing, mathematical Bayesian time decay ($2^{-\Delta t / t_{1/2}}$), anti-brigading protections for verified domains, and real-time exportable threat feeds.

---

## The Four Pillars of Intelligence

```
+---------------------------------------------------------------------------------------+
|                                      THREATLENS                                       |
+---------------------------+---------------------------+-------------------------------+
|  1. THREAT & PHISHING     |   2. WEB SECURITY         | 3. CERTIFICATE VALIDATION     |
|     DETECTION             |      ASSESSMENT           |    & CRYPTOGRAPHIC HEALTH     |
+---------------------------+---------------------------+-------------------------------+
| • Brand spoofing & typos  | • HSTS, CSP, Frame defense| • Fermat close-prime test     |
| • IDN Punycode homoglyphs | • X-Content-Type, Referrer| • Trial division small primes |
| • PAN / Aadhaar / OTP /   | • Permissions & COOP/CORP | • ROCA (Infineon RSALib) test |
|   MPIN harvest forms      | • TLS 1.3 vs legacy TLS   | • Batch GCD shared RSA primes |
| • Cross-domain exfiltration| • Secure / HttpOnly /     | • eMudhra incident detection  |
| • Advance-fee job scams   |   SameSite cookie flags   | • Distrusted CA watchlist     |
| • Deceptive APK lures     | • Exposed .git / .env     | • RFC 6962 embedded SCTs      |
+---------------------------+---------------------------+-------------------------------+
|                          4. COLLABORATIVE THREAT INTELLIGENCE                         |
|   • Privacy-preserving salted HMAC reporter hashes                                    |
|   • Bayesian half-life score decay • Community confirm/dispute consensus              |
|   • Anti-brigading protection for verified brands • Exportable feeds (CSV/JSON)       |
+---------------------------------------------------------------------------------------+
```

---

## eMudhra TLS Certificate Incident Case Study

In October 2026, **eMudhra** disclosed that **eight intermediate Certificate Authorities** in its global TLS hierarchy had weak private keys resulting from a flawed key-generation ceremony on 30 April 2025. The ceremony suffered from defective pseudo-random number generation (PRNG) entropy, rendering private keys mathematically predictable.

### Why This Matters for Web PKI
When an intermediate CA private key is compromised:
- Attackers can forge cryptographically valid TLS certificates for **any domain** on the internet.
- Browsers would trust these rogue certificates without raising warnings.
- The domain owner is bypassed unless monitored via Certificate Transparency (CT).

### How ThreatLens Protects Against Compromised CAs
1. **Full Chain Traversal**: Analyzes every intermediate and root certificate, not just the leaf.
2. **Distrust Watchlist (`distrusted.json`)**: Real-time pattern matching for flagged issuers and SHA-256 SubjectPublicKeyInfo (SPKI) blocklists.
3. **Certificate Transparency Verification**: Validates embedded Signed Certificate Timestamps (SCTs) according to RFC 6962 and checks crt.sh public log indices.
4. **Historical Batch-GCD**: Compares public keys against an SQLite store of seen certificates to catch shared primes and weak PRNG entropy across unrelated certificates.

---

## Quickstart

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Dependencies: `flask`, `requests`, `cryptography`, `pytest`, `certifi`

### 1. Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### 2. Launch the Web Platform
```powershell
$env:THREATLENS_SALT = "a-secure-random-salt-for-production"
python run.py serve --port 8080
```
Open **`http://127.0.0.1:8080`** in your browser.

### 3. Command-Line Scanning
```powershell
# Scan a live website
python run.py scan https://example.com

# Output complete structured JSON
python run.py scan https://example.com --json

# Authorized deep scan (includes exposed file checks)
python run.py scan https://yoursite.com --deep --authorized
```

### 4. Run the Full Test Suite
```powershell
python -m pytest
```

---

## Interactive Features in the Web UI

- **One-Click Threat Scenarios**:
  - 🏦 **SBI KYC Phish**: Demonstrates credential harvesting (PAN, OTP, NetBanking password), urgent suspension threats, and cross-domain form exfiltration.
  - 💼 **Fake Job Offer**: Demonstrates employment scam soliciting ₹2,500 advance deposit and malicious APK downloads.
  - 🔐 **eMudhra Incident**: Demonstrates detection of distrusted intermediate CAs with flawed key generation ceremonies.
  - 🧮 **Weak Fermat Key**: Demonstrates detection of an RSA-2048 modulus factorable via Fermat's algorithm ($|p - q| < 2000$).
  - 🛡️ **Hardened Bank**: Demonstrates a clean reference baseline with A+ hardening posture and TLS 1.3.
- **Certificate & Cryptography Lab**: Paste any raw PEM certificate or enter any live domain to run cryptographic factorization, safe curve checks, and eMudhra incident detection.
- **Collaborative Threat Feed Explorer**: Search and filter community-reported threats by category, view reputation scores, and export intelligence to CSV or JSON with one click.
- **Hardening Guide**: Production-ready Nginx, Apache, and Cloudflare configuration snippets to achieve an A+ security posture.

---

## API Reference

### 1. Scan a Target URL
`POST /api/scan`
```json
{
  "url": "https://example.com",
  "deep": false,
  "authorized": false
}
```
**Response:** Complete structured verdict (threat score, posture grade, findings list, certificate analysis, security headers table, and community reputation).

### 2. Inspect Raw Certificate or Domain
`POST /api/cert/inspect`
```json
{
  "pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "host": "optional-host.com"
}
```
*Or via host:*
```json
{
  "host": "google.com:443"
}
```

### 3. Submit Community Threat Report
`POST /api/report`
```json
{
  "url": "https://suspicious-site.xyz/login",
  "category": "phishing",
  "comment": "Asks for SBI OTP and PAN card number"
}
```
*Categories:* `phishing`, `payment_scam`, `fake_recruitment`, `impersonation`, `malware`, `other`.

### 4. Community Vote (Confirm or Dispute)
`POST /api/vote`
```json
{
  "url": "https://suspicious-site.xyz/login",
  "vote": "confirm"
}
```
*(vote can be `"confirm"` or `"dispute"`)*

### 5. Export Threat Intelligence Feed
`GET /api/feed/export?format=csv` or `GET /api/feed/export?format=json`
Returns corroborated malicious indicators of compromise (IOCs) with reputation scores and categories.

### 6. Platform Health & Statistics
`GET /api/health` and `GET /api/stats`
Returns system status, active version, total reported hosts, verified threats, and key registry count.

---

## Defensive Engineering & SSRF Safety

ThreatLens follows strict security-first principles when communicating with third-party web targets:
- **SSRF Prevention**: Every resolved IP address is validated against private, multicast, loopback, link-local, carrier-grade NAT, and cloud metadata ranges (`169.254.169.254`). Socket connections are made directly to the validated IP with SNI preserved.
- **Port Allowlist**: Only standard web ports (80, 443, 8080, 8443) are contacted.
- **Redirect Limits**: Maximum 5 hops; each redirect destination is re-validated for SSRF.
- **Response Caps**: Strict timeouts (default 6 seconds) and 2 MB maximum body limits to prevent resource exhaustion attacks.
- **Privacy**: No query parameters or tokens are stored in the database. Reporter identity is preserved strictly as a keyed HMAC hash (`THREATLENS_SALT`).
