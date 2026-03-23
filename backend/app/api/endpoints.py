from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.features.security_agent import analyze_threat_ml
from app.features.summarizer import generate_safe_summary
from app.features.semantic_cache import check_semantic_cache, add_to_semantic_cache 
from app.core.security import detect_malicious_intent, analyze_domain_reputation
from app.features.dlp_engine import dlp_manager
import time
from app.core.database import log_event
from typing import List
import aiosqlite
from app.core.database import DB_PATH

router = APIRouter()

class EmailRequest(BaseModel):
    sender: str
    body: str

class EmailResponse(BaseModel):
    is_malicious: bool
    confidence_score: float
    threat_type: str
    reasoning: str
    summary: str

@router.post("/summarize", response_model=EmailResponse)
async def summarize_email(request: EmailRequest):
    start_time = time.time()
    
    # NEW TIER 0: Dynamic Domain & DNS Firewall
    domain_report = await analyze_domain_reputation(request.sender)
    if not domain_report["is_safe"]:
        raise HTTPException(
            status_code=403, 
            detail=f"Domain Security Block: {domain_report['profile']}. {domain_report['reason']}"
        )

    # NEW TIER 0.5: Data Loss Prevention (PII Redaction)
    # We redact sensitive data before ANY AI or Database sees it.
    safe_body = dlp_manager.redact_pii(request.body)

    # TIER 1: Static Heuristics (0ms)
    fast_check = detect_malicious_intent(request.body)
    if not fast_check["is_safe"]:
        ml_report = {
            "is_malicious": True,
            "confidence_score": 1.0,
            "threat_type": fast_check["flags"][0],
            "reasoning": "Tier-1 Heuristics: Known malicious syntax detected."
        }
    else:
        # TIER 2: Pinecone Semantic Cache
        cached_threat = await check_semantic_cache(request.body)
        if cached_threat:
            ml_report = cached_threat
        else:
            # TIER 3: The ML Semantic Firewall
            ml_report = await analyze_threat_ml(request.sender, request.body)
            
            # Auto-Learning Loop
            if ml_report.get("is_malicious") and ml_report.get("confidence_score", 0.0) > 0.85:
                await add_to_semantic_cache(request.body, ml_report)

    # ENFORCEMENT ENGINE
    if ml_report.get("is_malicious") and ml_report.get("confidence_score", 0.0) > 0.80:
        raise HTTPException(
            status_code=403, 
            detail=f"ML Firewall Block: {ml_report.get('threat_type')} detected (Confidence: {ml_report.get('confidence_score')}). Reason: {ml_report.get('reasoning')}"
        )
     
    # Pass to Sandbox Summarizer
    summary = await generate_safe_summary(
        safe_body, 
        ml_report.get("is_malicious", False)
    )
    
    duration = (time.time() - start_time) * 1000 # Latency in ms
    # LOG THE EVENT CONCURRENTLY (Background)
    await log_event(
        request.sender, 
        ml_report.get("is_malicious"), 
        ml_report.get("threat_type"), 
        ml_report.get("confidence_score"),
        duration
    )
    
    return EmailResponse(
        is_malicious=ml_report.get("is_malicious", False),
        confidence_score=ml_report.get("confidence_score", 0.0),
        threat_type=ml_report.get("threat_type", "None"),
        reasoning=f"PII Redacted: Yes. Domain: {domain_report['profile']}. {ml_report.get('reasoning', '')}",
        summary=summary
    )
    
class LogEntry(BaseModel):
    id: int
    timestamp: str
    sender: str
    is_malicious: bool
    threat_type: str
    confidence: float = Field(..., alias='confidence_score')
    latency_ms: float

@router.get("/logs")
async def get_security_logs():
    """Provides the latest 100 security events. Robust version."""
    logs = []
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            # Fetch data
            async with db.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100") as cursor:
                rows = await cursor.fetchall()
                for row in rows:
                    # Convert row to dict and ensure keys match what JS expects
                    log_dict = dict(row)
                    # Mapping 'confidence' from DB to 'confidence_score' for JS
                    log_dict['confidence_score'] = log_dict.get('confidence', 0.0)
                    logs.append(log_dict)
        return logs
    except Exception as e:
        print(f"DATABASE ERROR: {e}")
        return [] # Return empty list instead of crashing