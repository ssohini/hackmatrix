import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

COMMON_PATHS = ["/.git/HEAD", "/.env", "/admin", "/phpmyadmin", "/wp-admin", "/.well-known/security.txt", "/robots.txt", "/sitemap.xml"]

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-embedder-policy": "COEP",
    "cross-origin-resource-policy": "CORP",
}

def analyze(url: str):
    signals = []
    score = 100
    details = {"status_code": None, "final_url": url, "redirects": [], "headers": {}, "server": None, "cookies": [], "exposed_paths": [], "mixed_content": [], "forms": []}

    client = httpx.Client(timeout=12, follow_redirects=True, verify=False, headers={"User-Agent": "AegisScanner/1.0"})
    try:
        resp = client.get(url)
        details["status_code"] = resp.status_code
        details["final_url"] = str(resp.url)
        details["redirects"] = [str(r.url) for r in resp.history] if hasattr(resp, "history") else []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        details["headers"] = {k: v for k, v in headers.items()}
        details["server"] = headers.get("server")
        if headers.get("x-powered-by"):
            details["x_powered_by"] = headers.get("x-powered-by")

        # Redirect chain
        if len(details["redirects"]) >= 3:
            score -= 8
            signals.append({"name": "Long redirect chain", "detail": f"{len(details['redirects'])} redirects", "state": "warn", "category": "Web Security", "impact": -8})

        # HTTPS
        parsed = urlparse(url)
        if parsed.scheme != "https":
            score -= 25
            signals.append({"name": "No HTTPS", "detail": "Site served over HTTP", "state": "bad", "category": "Web Security", "impact": -25})

        # Security headers
        missing = []
        for h, label in SECURITY_HEADERS.items():
            if h in headers:
                signals.append({"name": label, "detail": headers[h][:80], "state": "good", "category": "Web Security", "impact": 0})
            else:
                missing.append(label)
        if missing:
            score -= min(20, 4 * len(missing))
            signals.append({"name": "Missing security headers", "detail": ", ".join(missing[:6]), "state": "warn", "category": "Web Security", "impact": -min(20, 4*len(missing))})

        # Server leakage
        if headers.get("server"):
            score -= 4
            signals.append({"name": "Server banner", "detail": headers.get("server"), "state": "warn", "category": "Web Security", "impact": -4})
        if headers.get("x-powered-by"):
            score -= 4
            signals.append({"name": "Technology leakage", "detail": headers.get("x-powered-by"), "state": "warn", "category": "Web Security", "impact": -4})

        # Cookies
        cookies = []
        for c in resp.cookies.jar if hasattr(resp.cookies, "jar") else []:
            cookies.append(c.name)
        # inspect set-cookie headers
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            sc_lower = set_cookie.lower()
            if "secure" not in sc_lower:
                score -= 6
                signals.append({"name": "Cookie without Secure", "detail": "Set-Cookie missing Secure flag", "state": "warn", "category": "Web Security", "impact": -6})
            if "httponly" not in sc_lower:
                score -= 6
                signals.append({"name": "Cookie without HttpOnly", "detail": "Set-Cookie missing HttpOnly flag", "state": "warn", "category": "Web Security", "impact": -6})
            if "samesite" not in sc_lower:
                score -= 4
                signals.append({"name": "Cookie SameSite", "detail": "Set-Cookie missing SameSite", "state": "warn", "category": "Web Security", "impact": -4})

        # Parse HTML
        content_type = headers.get("content-type", "")
        if "text/html" in content_type:
            soup = BeautifulSoup(resp.text, "html.parser")
            # mixed content
            for tag in soup.find_all(["img", "script", "link", "iframe"]):
                src = tag.get("src") or tag.get("href")
                if src and src.startswith("http://"):
                    details["mixed_content"].append(src)
            if details["mixed_content"]:
                score -= min(12, 3 * len(details["mixed_content"]))
                signals.append({"name": "Mixed content", "detail": f"{len(details['mixed_content'])} insecure resources", "state": "warn", "category": "Web Security", "impact": -min(12, 3*len(details['mixed_content']))})
            # forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                inputs = [i.get("type") for i in form.find_all("input")]
                has_pw = "password" in inputs
                cross = False
                if action:
                    try:
                        if urlparse(action).netloc and urlparse(action).netloc != urlparse(url).netloc:
                            cross = True
                    except Exception:
                        pass
                details["forms"].append({"action": action, "has_password": has_pw, "cross_origin": cross})
                if has_pw and cross:
                    score -= 25
                    signals.append({"name": "Credential form posts cross-origin", "detail": action, "state": "bad", "category": "Web Security", "impact": -25})
                elif has_pw:
                    signals.append({"name": "Login form detected", "detail": "Page collects passwords", "state": "info", "category": "Web Security", "impact": 0})
            # external scripts count
            ext_scripts = [s.get("src") for s in soup.find_all("script") if s.get("src", "").startswith("http")]
            if len(ext_scripts) > 10:
                score -= 4
                signals.append({"name": "Many external scripts", "detail": f"{len(ext_scripts)} external scripts", "state": "warn", "category": "Web Security", "impact": -4})

        # Exposed paths
        base = f"{parsed.scheme}://{parsed.netloc}"
        for p in COMMON_PATHS:
            try:
                r = client.head(base + p, timeout=5)
                if r.status_code < 400:
                    details["exposed_paths"].append({"path": p, "status": r.status_code})
            except Exception:
                pass
        if details["exposed_paths"]:
            score -= min(15, 5 * len(details["exposed_paths"]))
            signals.append({"name": "Exposed paths", "detail": ", ".join(e["path"] for e in details["exposed_paths"]), "state": "warn", "category": "Web Security", "impact": -min(15, 5*len(details['exposed_paths']))})

    except Exception as e:
        score -= 20
        signals.append({"name": "Fetch failed", "detail": str(e)[:120], "state": "bad", "category": "Web Security", "impact": -20})
        details["error"] = str(e)
    finally:
        client.close()

    if not signals:
        signals.append({"name": "Web posture", "detail": "No issues detected", "state": "good", "category": "Web Security", "impact": 0})

    score = max(0, min(100, score))
    return {"score": score, "signals": signals, "details": details}
