from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.features.security_agent import analyze_threat_ml
from app.features.summarizer import generate_safe_summary

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
    
    # 1. Pass data through the ML Semantic Firewall
    ml_report = await analyze_threat_ml(request.sender, request.body)
    
    # 2. Dynamic Decision Engine
    # If the ML model is highly confident (>80%) that this is an attack, block it entirely.
    if ml_report.get("is_malicious") and ml_report.get("confidence_score", 0.0) > 0.80:
        raise HTTPException(
            status_code=403, 
            detail=f"ML Firewall Block: {ml_report.get('threat_type')} detected (Confidence: {ml_report.get('confidence_score')}). Reason: {ml_report.get('reasoning')}"
        )
    
    # 3. If it passes the firewall, send it to the sandbox for summarization
    # We still use the XML fencing as a backup layer of defense!
    summary = await generate_safe_summary(request.body, "DYNAMIC_USER")
    
    return EmailResponse(
        is_malicious=ml_report.get("is_malicious", False),
        confidence_score=ml_report.get("confidence_score", 0.0),
        threat_type=ml_report.get("threat_type", "Unknown"),
        reasoning=ml_report.get("reasoning", "Processed"),
        summary=summary
    )