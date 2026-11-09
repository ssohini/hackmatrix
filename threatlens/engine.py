"""Orchestrates all analysis engines for one URL and merges their findings."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import cert_analyzer, content_analyzer, domains, netsafe, providers, scoring, url_analyzer, web_security
from .intel import IntelStore
from .models import SEVERITY_ORDER, Finding


def _intel_findings(host: str, store: IntelStore | None) -> tuple[list[Finding], dict | None]:
    if store is None:
        return [], None
    findings: list[Finding] = []
    rep = store.reputation(host)
    level = rep["level"]
    protected = domains.legit_brand_for_host(host) is not None
    if protected and level == "confirmed":
        level = "reported"  # block brigading of well-known brands; corroboration must come from technical evidence
        rep["note"] = "Community level capped because this is a well-known brand domain."
    rep["effective_level"] = level
    if level == "confirmed":
        findings.append(Finding(
            "intel.community_confirmed", "intel", "threat", "high",
            f"Confirmed by {rep['unique_reporters']} independent community reports",
            "Reports: " + ", ".join(f"{k} ({v})" for k, v in rep["categories"].items()),
            "Do not use this site. If you already entered details, change those passwords.", weight=45, floor=70))
    elif level == "reported":
        findings.append(Finding("intel.community_reported", "intel", "threat", "medium",
                                "Reported by the community", f"{rep['reports']} report(s), reputation {rep['score']}.", weight=18))
    elif level == "weak":
        findings.append(Finding("intel.community_weak", "intel", "threat", "low",
                                "A community report exists for this host", f"{rep['reports']} report(s), not yet corroborated.", weight=7))
    for m in store.feed_matches(host):
        findings.append(Finding(
            "intel.feed_match", "intel", "threat", "critical", f"Listed in imported threat feed '{m['source']}'",
            f"Feed category: {m['category']}.", "Do not use this site.", weight=65, floor=80))
        break
    return findings, rep


def _run_cert(host: str, port: int, store, ct_lookup):
    return cert_analyzer.analyze_certificate(host, port, store=store, ct_lookup=ct_lookup)


def scan(raw_url: str, *, deep: bool = False, authorized: bool = False, store: IntelStore | None = None,
         ct_lookup: bool | None = None) -> dict:
    started = time.time()
    url = url_analyzer.normalize_url(raw_url)
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    findings: list[Finding] = []
    coverage: list[dict] = []
    notes: list[str] = []

    def done(engine, status, note=""):
        coverage.append({"engine": engine, "status": status, "note": note})

    # 1. URL analysis (offline)
    f, features = url_analyzer.analyze_url(url)
    findings += f
    done("url", "ok")

    # 2. Collaborative intelligence (local database)
    f, community = _intel_findings(host, store)
    findings += f
    done("intel", "ok" if store is not None else "skipped", "" if store is not None else "No intelligence database attached")

    # 3. Network engines, run concurrently
    https_port = (parts.port or 443) if parts.scheme == "https" else 443
    with ThreadPoolExecutor(max_workers=3) as pool:
        fut_fetch = pool.submit(netsafe.safe_fetch, url)
        fut_cert = pool.submit(_run_cert, host, https_port, store, ct_lookup)
        fut_sb = pool.submit(providers.safe_browsing_lookup, url)
        fetch = fut_fetch.result()
        try:
            cert_findings, cert_info = fut_cert.result()
        except netsafe.BlockedTarget as exc:
            cert_findings, cert_info = [], None
            done("certificate", "blocked", str(exc))
        except Exception as exc:  # network failures are expected for dead or non-TLS hosts
            cert_findings, cert_info = [], None
            if parts.scheme == "http":
                cert_findings = [Finding("sec.no_https", "security", "posture", "high", "Site does not offer HTTPS",
                                         "No TLS service answered on port 443.", "Enable HTTPS with a certificate from a public CA.",
                                         weight=0, posture_weight=25)]
                done("certificate", "failed", "No HTTPS service on port 443")
            else:
                done("certificate", "failed", f"{type(exc).__name__}: {str(exc)[:160]}")
        else:
            done("certificate", "ok")
        sb = fut_sb.result()
    findings += cert_findings

    # Page content and web security
    content_findings, page = content_analyzer.analyze_content(fetch, features)
    findings += content_findings
    headers_table: list[dict] = []
    if fetch.status is not None and not fetch.error:
        sec_findings, headers_table = web_security.analyze_headers(fetch, page)
        findings += sec_findings
        done("content", "ok" if page else "partial", "" if page else "Response was not an HTML page")
        done("security", "ok")
    else:
        done("content", "failed", fetch.error or "No response")
        done("security", "failed", fetch.error or "No response")

    # Safe Browsing (optional)
    if sb is None:
        done("safe_browsing", "skipped", "No API key configured or provider unreachable")
    else:
        done("safe_browsing", "ok")
        if sb:
            findings.append(Finding("intel.safe_browsing", "intel", "threat", "critical",
                                    "Flagged by Google Safe Browsing: " + ", ".join(t.replace("_", " ").title() for t in sb),
                                    advice="Do not use this site.", weight=65, floor=80))

    # Active exposure checks need explicit authorisation
    if deep and authorized and fetch.status is not None:
        findings += web_security.check_exposures(fetch.final_url or url)
        done("exposure", "ok")
    elif deep:
        notes.append("Exposure checks were skipped because authorisation to test this site was not confirmed.")
        done("exposure", "skipped", "Authorisation not confirmed")

    # 4. Scoring
    seen, unique = set(), []
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            unique.append(f)
    unique.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -(f.weight or 0)))
    threat = scoring.threat_score(unique)
    label, level = scoring.verdict_for(threat)
    have_posture = bool(headers_table or cert_info)
    pscore, grade = scoring.posture(unique) if have_posture else (None, None)

    ok_engines = {c["engine"] for c in coverage if c["status"] == "ok"}
    confidence = "high" if {"content", "certificate"} <= ok_engines else "medium" if ok_engines & {"content", "certificate"} else "low"
    if confidence != "high":
        notes.append("Some engines could not run, so this verdict rests on less evidence. See coverage below.")

    top = [f.title for f in unique if f.axis in ("threat", "both") and (f.weight or 0) >= 15][:3]
    if top:
        summary = "; ".join(top) + "."
    elif label == "Low risk":
        summary = "No strong signs of phishing or malicious behaviour were found."
    else:
        summary = "Several weak signals add up."
    advice = {
        "danger": ["Do not enter passwords, card details or OTPs.", "If you already did, change the password and contact your bank or provider.",
                   "Report the page so others are warned."],
        "high": ["Treat this site as unsafe until verified.", "Reach the real service by typing its address or using its official app."],
        "warn": ["Double-check the address before signing in.", "Look at the findings to see what raised concern."],
        "ok": [],
    }[level]

    return {
        "url": url, "host": host, "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": int((time.time() - started) * 1000),
        "verdict": {"label": label, "level": level, "threat_score": threat, "confidence": confidence,
                    "summary": summary, "advice": advice},
        "posture": {"grade": grade, "score": pscore},
        "findings": [f.to_dict() for f in unique],
        "certificate": cert_info, "headers": headers_table,
        "page": page.public() if page else None,
        "http": {"status": fetch.status, "final_url": fetch.final_url, "redirects": fetch.redirects,
                 "elapsed_ms": fetch.elapsed_ms, "error": fetch.error},
        "features": features, "community": community, "coverage": coverage, "notes": notes,
    }
