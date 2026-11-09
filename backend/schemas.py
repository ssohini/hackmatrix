from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any


class Signal(BaseModel):
    name: str
    detail: str
    state: str  # good | warn | bad | info
    category: str = "General"
    impact: int = 0


class AnalyzeRequest(BaseModel):
    url: str


class ReportRequest(BaseModel):
    url: str
    report_type: str = "phishing"
    description: str = ""
    reporter: str = "anonymous"


class VoteRequest(BaseModel):
    report_id: int
    vote: int  # +1 or -1


class AnalysisResponse(BaseModel):
    url: str
    hostname: str
    score: int
    verdict: str
    signals: List[Signal]
    threat: Dict[str, Any]
    web_security: Dict[str, Any]
    certificate: Dict[str, Any]
    intelligence: Dict[str, Any]
