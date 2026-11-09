import re
from urllib.parse import urlparse, urlunparse

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link", ".work", ".zip", ".mov", ".country", ".stream", ".download", ".racing", ".win", ".bid", ".trade", ".date", ".faith", ".loan", ".men", ".party", ".review", ".science", ".accountant"}

BRANDS = {
    "paypal": "paypal.com", "apple": "apple.com", "google": "google.com", "microsoft": "microsoft.com",
    "amazon": "amazon.com", "facebook": "facebook.com", "netflix": "netflix.com", "bankofamerica": "bankofamerica.com",
    "chase": "chase.com", "wellsfargo": "wellsfargo.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com", "dropbox": "dropbox.com", "dhl": "dhl.com", "fedex": "fedex.com",
    "irs": "irs.gov", "hmrc": "gov.uk",
}

KNOWN_OFFICIAL = set(BRANDS.values())


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty url")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError("invalid hostname")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("unsupported scheme")
    return raw


def registered_domain(hostname: str) -> str:
    hostname = hostname.lower().rstrip(".")
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    # crude: last two labels, handle common second-level TLDs
    second_level = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if len(parts) >= 3 and parts[-2] in second_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)) or ":" in host


def homoglyph_check(host: str) -> bool:
    # detect non-ascii or punycode
    try:
        host.encode("ascii")
        ascii_only = True
    except UnicodeEncodeError:
        ascii_only = False
    if not ascii_only:
        return True
    if "xn--" in host:
        return True
    # confusable common substitutions
    confusables = {"0": "o", "1": "l", "rn": "m"}
    return False


def suspicious_tld(host: str) -> bool:
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return True
    return False
