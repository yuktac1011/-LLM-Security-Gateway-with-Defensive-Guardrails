from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.features.security_agent import analyze_threat_ml
from app.features.summarizer import generate_safe_summary
from app.features.semantic_cache import check_semantic_cache, add_to_semantic_cache 
from app.core.security import detect_malicious_intent, analyze_domain_reputation

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
    
    # NEW TIER 0: Dynamic Domain & DNS Firewall
    domain_report = await analyze_domain_reputation(request.sender)
    if not domain_report["is_safe"]:
        raise HTTPException(
            status_code=403, 
            detail=f"Domain Security Block: {domain_report['profile']}. {domain_report['reason']}"
        )

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
    summary = await generate_safe_summary(request.body, domain_report["profile"])
    
    return EmailResponse(
        is_malicious=ml_report.get("is_malicious", False),
        confidence_score=ml_report.get("confidence_score", 0.0),
        threat_type=ml_report.get("threat_type", "Unknown"),
        reasoning=f"Domain Status: {domain_report['profile']}. {ml_report.get('reasoning', 'Processed Cleanly')}",
        summary=summary
    )