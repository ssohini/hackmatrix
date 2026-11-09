from sqlalchemy.orm import Session
from ..models import ThreatReport, Investigation, CertificateRecord
from datetime import datetime, timezone, timedelta
from collections import Counter

REPORT_TYPE_WEIGHT = {"phishing": 25, "malware": 30, "scam": 20, "defacement": 15, "spam": 10}

def summary(db: Session):
    total_reports = db.query(ThreatReport).count()
    total_inv = db.query(Investigation).count()
    last_24h = db.query(ThreatReport).filter(ThreatReport.created_at >= datetime.now(timezone.utc) - timedelta(hours=24)).count()
    # top reported hosts
    rows = db.query(ThreatReport.hostname).all()
    c = Counter(r[0] for r in rows)
    top = [{"hostname": h, "count": n} for h, n in c.most_common(8)]
    # verdict distribution
    invs = db.query(Investigation.verdict).all()
    vdist = Counter(v[0] for v in invs)
    return {
        "total_reports": total_reports,
        "total_investigations": total_inv,
        "reports_last_24h": last_24h,
        "top_reported": top,
        "verdict_distribution": dict(vdist),
    }

def host_reputation(db: Session, hostname: str):
    rd = hostname
    reports = db.query(ThreatReport).filter(ThreatReport.hostname == hostname).all()
    votes = sum(r.votes for r in reports)
    count = len(reports)
    # recent investigations
    recent = db.query(Investigation).filter(Investigation.hostname == hostname).order_by(Investigation.created_at.desc()).limit(5).all()
    avg_score = (sum(i.score for i in recent) / len(recent)) if recent else None
    # score adjustment
    adjustment = 0
    signals = []
    if count > 0:
        adjustment -= min(30, 8 * count + votes * 2)
        signals.append({"name": "Community reports", "detail": f"{count} reports, {votes} net votes", "state": "bad" if count >= 2 else "warn", "category": "Intelligence", "impact": -min(30, 8*count)})
    if avg_score is not None and avg_score < 50:
        adjustment -= 10
        signals.append({"name": "Historical low trust", "detail": f"Avg past score {avg_score:.0f}", "state": "warn", "category": "Intelligence", "impact": -10})
    if count == 0 and avg_score is None:
        signals.append({"name": "No community reports", "detail": "No prior reports for this host", "state": "good", "category": "Intelligence", "impact": 0})
    return {"adjustment": adjustment, "signals": signals, "report_count": count, "net_votes": votes}

def feed(db: Session, limit: int = 25):
    items = []
    reports = db.query(ThreatReport).order_by(ThreatReport.created_at.desc()).limit(limit).all()
    for r in reports:
        items.append({"type": "report", "id": r.id, "hostname": r.hostname, "url": r.url, "report_type": r.report_type, "description": r.description, "reporter": r.reporter, "votes": r.votes, "created_at": r.created_at.isoformat() if r.created_at else None})
    invs = db.query(Investigation).order_by(Investigation.created_at.desc()).limit(limit).all()
    for i in invs:
        items.append({"type": "investigation", "id": i.id, "hostname": i.hostname, "url": i.url, "verdict": i.verdict, "score": i.score, "created_at": i.created_at.isoformat() if i.created_at else None})
    items.sort(key=lambda x: x["created_at"] or "", reverse=True)
    return items[:limit]
