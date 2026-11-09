"""Flask application: JSON API plus the single-page UI."""
from __future__ import annotations

import csv
import io
import logging
import threading
import time
from collections import defaultdict, deque

from flask import Flask, Response, jsonify, request, send_from_directory

from . import __version__, cert_analyzer, config, demo, engine
from .intel import CATEGORIES, CONFIRMED_SCORE, IntelStore, reporter_id

log = logging.getLogger("threatlens")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


class RateLimiter:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float) -> bool:
        now = time.time()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


def create_app(store: IntelStore | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    store = store or IntelStore(config.db_path())
    limiter = RateLimiter()
    if config.salt() == "change-me-in-production":
        log.warning("THREATLENS_SALT is not set; reporter hashes use the default salt.")

    def client_id() -> str:
        return reporter_id(config.salt(), request.remote_addr or "unknown")

    def body() -> dict:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValueError("Send a JSON object")
        return data

    @app.after_request
    def secure(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(ValueError)
    def bad_request(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(404)
    def not_found(_exc):
        return jsonify(error="Not found"), 404

    @app.errorhandler(Exception)
    def server_error(exc):
        log.exception("unhandled error")
        return jsonify(error="Internal error while processing the request"), 500

    @app.get("/")
    def index():
        return send_from_directory(config.STATIC_DIR, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(config.STATIC_DIR, name)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", version=__version__, **store.stats())

    @app.post("/api/scan")
    def scan():
        data = body()
        if not limiter.allow("scan:" + client_id(), config.scan_rate_per_min(), 60):
            return jsonify(error="Too many scans. Wait a minute and try again."), 429
        url = data.get("url")
        if not isinstance(url, str):
            raise ValueError("Provide a 'url' string")
        result = engine.scan(url, deep=bool(data.get("deep")), authorized=bool(data.get("authorized")), store=store)
        return jsonify(result)

    @app.post("/api/report")
    def report():
        data = body()
        if not limiter.allow("report:" + client_id(), config.report_rate_per_hour(), 3600):
            return jsonify(error="Report limit reached. Try again later."), 429
        category = data.get("category", "other")
        if category not in CATEGORIES:
            raise ValueError("Unknown category. Use one of: " + ", ".join(sorted(CATEGORIES)))
        return jsonify(store.add_report(str(data.get("url", "")), category, str(data.get("comment", "")), client_id()))

    @app.post("/api/vote")
    def vote():
        data = body()
        if not limiter.allow("report:" + client_id(), config.report_rate_per_hour() * 3, 3600):
            return jsonify(error="Vote limit reached. Try again later."), 429
        return jsonify(store.vote(str(data.get("url", "")), str(data.get("vote", "")), client_id()))

    @app.get("/api/reputation")
    def reputation():
        url = request.args.get("url", "")
        if not url:
            raise ValueError("Provide a 'url' query parameter")
        return jsonify(store.reputation(url))

    @app.get("/api/feed")
    def feed():
        try:
            min_score = float(request.args.get("min_score", CONFIRMED_SCORE))
            limit = min(5000, int(request.args.get("limit", 1000)))
        except ValueError:
            raise ValueError("min_score and limit must be numbers")
        return jsonify(generated_at=time.time(), entries=store.feed(min_score, limit))

    @app.get("/api/feed/export")
    def feed_export():
        try:
            min_score = float(request.args.get("min_score", CONFIRMED_SCORE))
        except ValueError:
            min_score = CONFIRMED_SCORE
        fmt = request.args.get("format", "csv").lower()
        entries = store.feed(min_score, limit=5000)
        if fmt == "json":
            return jsonify(entries=entries)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["host", "score", "reporters", "category", "last_report_iso"])
        for e in entries:
            lr = e.get("last_report")
            lr_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(lr)) if lr else ""
            writer.writerow([e["host"], e["score"], e["reporters"], e["category"], lr_iso])
        csv_data = output.getvalue()
        return Response(csv_data, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=threatlens-feed.csv"})

    @app.get("/api/demo/scenarios")
    def demo_scenarios():
        return jsonify(scenarios=demo.list_scenarios())

    @app.post("/api/demo/run")
    def demo_run():
        data = body()
        sid = data.get("scenario")
        if not sid:
            raise ValueError("Provide 'scenario' ID")
        res = demo.get_scenario(str(sid))
        if not res:
            raise ValueError(f"Unknown scenario: {sid}")
        return jsonify(res)

    @app.post("/api/cert/inspect")
    def cert_inspect():
        data = body()
        pem = data.get("pem")
        host = data.get("host") or data.get("url")
        if pem:
            findings, cert_info = cert_analyzer.analyze_pem_text(str(pem), host=str(host or "custom.domain"), store=store)
        elif host:
            import urllib.parse
            target = str(host).strip()
            if "://" in target:
                parsed = urllib.parse.urlsplit(target)
                h_name = parsed.hostname or target
                h_port = parsed.port or (443 if parsed.scheme == "https" else 443)
            else:
                h_name = target.split(":", 1)[0]
                h_port = int(target.split(":", 1)[1]) if ":" in target else 443
            findings, cert_info = cert_analyzer.analyze_certificate(h_name, h_port, store=store)
        else:
            raise ValueError("Provide 'pem' certificate text or 'host' string")
        return jsonify(findings=[f.to_dict() for f in findings], certificate=cert_info)

    @app.get("/api/stats")
    def stats():
        st = store.stats()
        feed_count = len(store.feed(CONFIRMED_SCORE, limit=10000))
        return jsonify(status="ok", version=__version__, confirmed_threats=feed_count, **st)

    return app
