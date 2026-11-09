from urllib.parse import urlparse
from .url_utils import registered_domain, is_ip, homoglyph_check, suspicious_tld, BRANDS, KNOWN_OFFICIAL

SUSPICIOUS_KEYWORDS = ["login", "signin", "verify", "secure", "update", "account", "payment", "bank",
                       "password", "credential", "wallet", "invoice", "reset", "confirm", "auth"]

def analyze(url: str):
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    rd = registered_domain(host)
    signals = []
    score = 100

    # IP host
    if is_ip(host):
        score -= 25
        signals.append({"name": "IP-based host", "detail": "URL uses a raw IP address", "state": "bad", "category": "Threat", "impact": -25})

    # Punycode / homoglyph
    if homoglyph_check(host):
        score -= 30
        signals.append({"name": "Homoglyph / IDN", "detail": "Non-ASCII or punycode characters detected", "state": "bad", "category": "Threat", "impact": -30})

    # Suspicious TLD
    if suspicious_tld(host):
        score -= 15
        signals.append({"name": "Suspicious TLD", "detail": "Top-level domain frequently abused", "state": "warn", "category": "Threat", "impact": -15})

    # Subdomains
    sub_count = host.count(".")
    if sub_count > 2:
        score -= 12
        signals.append({"name": "Excessive subdomains", "detail": f"{sub_count} dot segments in hostname", "state": "warn", "category": "Threat", "impact": -12})

    # Length
    if len(host) > 40:
        score -= 10
        signals.append({"name": "Long hostname", "detail": f"Hostname length {len(host)}", "state": "warn", "category": "Threat", "impact": -10})

    # Hyphens
    if host.count("-") >= 3:
        score -= 12
        signals.append({"name": "Hyphenated domain", "detail": "Multiple hyphens (common in phishing)", "state": "warn", "category": "Threat", "impact": -12})

    # Suspicious keywords
    kw_hits = [k for k in SUSPICIOUS_KEYWORDS if k in host or k in (parsed.path or "").lower()]
    if kw_hits:
        score -= min(24, 8 * len(kw_hits))
        signals.append({"name": "Suspicious keywords", "detail": ", ".join(kw_hits[:5]), "state": "warn", "category": "Threat", "impact": -min(24, 8*len(kw_hits))})

    # Brand impersonation
    impersonated = None
    for brand, official in BRANDS.items():
        if brand in host.replace("-", "").replace(".", "") and rd != official and official not in host:
            impersonated = brand
            break
    if impersonated:
        score -= 35
        signals.append({"name": "Brand impersonation", "detail": f"Possible impersonation of {impersonated}", "state": "bad", "category": "Threat", "impact": -35})

    # Userinfo / port
    if parsed.username or parsed.password:
        score -= 20
        signals.append({"name": "Embedded credentials", "detail": "URL contains username/password", "state": "bad", "category": "Threat", "impact": -20})
    if parsed.port and parsed.port not in (80, 443):
        score -= 8
        signals.append({"name": "Non-standard port", "detail": f"Port {parsed.port}", "state": "warn", "category": "Threat", "impact": -8})

    # Path depth / query
    if (parsed.path or "").count("/") > 6:
        score -= 6
        signals.append({"name": "Deep path", "detail": "Unusually deep URL path", "state": "warn", "category": "Threat", "impact": -6})

    # URL length
    if len(url) > 120:
        score -= 6
        signals.append({"name": "Long URL", "detail": f"URL length {len(url)}", "state": "warn", "category": "Threat", "impact": -6})

    # Registered domain is known official -> bonus
    if rd in KNOWN_OFFICIAL:
        score = min(100, score + 15)
        signals.append({"name": "Known official domain", "detail": f"{rd} is a recognized brand domain", "state": "good", "category": "Threat", "impact": 15})

    if not signals:
        signals.append({"name": "Domain structure", "detail": "No structural anomalies detected", "state": "good", "category": "Threat", "impact": 0})

    return {"score": score, "signals": signals, "registered_domain": rd, "hostname": host}
