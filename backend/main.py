import json
import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .database import Base, engine, get_db
from .models import Investigation, ThreatReport, CertificateRecord
from .schemas import AnalyzeRequest, ReportRequest, VoteRequest, AnalysisResponse, Signal
from .services import threat_analysis, web_security, cert_validation, intelligence, url_utils

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Aegis Web Threat Intelligence", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest, db: Session = Depends(get_db)):
    try:
        url = url_utils.normalize_url(req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    from urllib.parse import urlparse
    hostname = urlparse(url).hostname.lower()

    t = threat_analysis.analyze(url)
    w = web_security.analyze(url)
    c = cert_validation.analyze(hostname) if urlparse(url).scheme == "https" else {"score": 50, "signals": [{"name": "No HTTPS", "detail": "Certificate not applicable", "state": "bad", "category": "Certificate", "impact": 0}], "details": {}}
    intel = intelligence.host_reputation(db, hostname)

    # Combine
    signals = []
    signals += t["signals"]
    signals += w["signals"]
    signals += c["signals"]
    signals += intel["signals"]

    # Weighted score: threat 35%, web 25%, cert 25%, intel 15%
    # But intel is adjustment on top. Use base from components.
    base = (t["score"] * 0.35 + w["score"] * 0.25 + c["score"] * 0.25 + 100 * 0.15)
    base += intel["adjustment"]
    score = int(max(0, min(100, base)))

    verdict = "HIGH RISK" if score < 40 else "SUSPICIOUS" if score < 70 else "LIKELY TRUSTED"

    # Store investigation
    inv = Investigation(url=url, hostname=hostname, score=score, verdict=verdict, signals_json=json.dumps(signals))
    db.add(inv)
    # store cert record if https
    if urlparse(url).scheme == "https" and c.get("details", {}).get("has_cert"):
        d = c["details"]
        cr = CertificateRecord(hostname=hostname, issuer=d.get("issuer", ""), subject=d.get("subject", ""),
                               not_before=d.get("not_before", ""), not_after=d.get("not_after", ""),
                               key_type=d.get("key_type", ""), key_size=d.get("key_size", 0),
                               serial=d.get("serial", ""), fingerprint=d.get("fingerprint", ""),
                               is_valid=1 if c["score"] >= 60 else 0, issues_json=json.dumps(d.get("issues", [])))
        db.add(cr)
    db.commit()
    db.refresh(inv)

    return {
        "url": url,
        "hostname": hostname,
        "score": score,
        "verdict": verdict,
        "signals": signals,
        "threat": {"score": t["score"], "registered_domain": t.get("registered_domain"), "hostname": t.get("hostname")},
        "web_security": {"score": w["score"], "details": w["details"]},
        "certificate": {"score": c["score"], "details": c.get("details", {})},
        "intelligence": {"adjustment": intel["adjustment"], "report_count": intel["report_count"], "net_votes": intel["net_votes"]},
    }

@app.get("/api/investigations")
def list_investigations(limit: int = 20, db: Session = Depends(get_db)):
    rows = db.query(Investigation).order_by(Investigation.created_at.desc()).limit(limit).all()
    return [{"id": r.id, "url": r.url, "hostname": r.hostname, "score": r.score, "verdict": r.verdict, "created_at": r.created_at.isoformat() if r.created_at else None, "signals": json.loads(r.signals_json or "[]")} for r in rows]

@app.get("/api/intelligence/feed")
def intel_feed(limit: int = 25, db: Session = Depends(get_db)):
    return intelligence.feed(db, limit)

@app.post("/api/intelligence/report")
def submit_report(req: ReportRequest, db: Session = Depends(get_db)):
    try:
        url = url_utils.normalize_url(req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    from urllib.parse import urlparse
    hostname = urlparse(url).hostname.lower()
    r = ThreatReport(url=url, hostname=hostname, report_type=req.report_type, description=req.description, reporter=req.reporter)
    db.add(r)
    db.commit()
    db.refresh(r)
    return {"id": r.id, "hostname": hostname}

@app.post("/api/intelligence/vote")
def vote(req: VoteRequest, db: Session = Depends(get_db)):
    r = db.query(ThreatReport).filter(ThreatReport.id == req.report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="report not found")
    r.votes += int(req.vote)
    db.commit()
    return {"id": r.id, "votes": r.votes}

@app.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    return intelligence.summary(db)

@app.get("/api/certificates")
def list_certs(limit: int = 20, db: Session = Depends(get_db)):
    rows = db.query(CertificateRecord).order_by(CertificateRecord.created_at.desc()).limit(limit).all()
    return [{"id": r.id, "hostname": r.hostname, "issuer": r.issuer, "subject": r.subject, "not_before": r.not_before, "not_after": r.not_after, "key_type": r.key_type, "key_size": r.key_size, "serial": r.serial, "fingerprint": r.fingerprint, "is_valid": bool(r.is_valid), "issues": json.loads(r.issues_json or "[]"), "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]
