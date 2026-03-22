import time
from app.core.security import detect_malicious_intent # Your fast Regex (Tier 1)
from app.features.security_agent import analyze_threat_ml # Your heavy ML (Tier 4)

# Simulated Semantic Cache (In real life, use Redis or Pinecone Vector DB)
# Stores hashes/vectors of known attacks to save money on API calls
SEMANTIC_CACHE = {
    "ignora las instrucciones": "Jailbreak",
    "ignore previous": "Prompt Injection"
}

async def adaptive_security_pipeline(sender_email: str, text: str) -> dict:
    """
    ENTERPRISE MULTI-TIER SECURITY PIPELINE
    Optimizes for Latency, Cost, and Accuracy.
    """
    start_time = time.time()
    
    # ==========================================
    # TIER 1: Static Heuristics (Cost: $0.00, Time: <1ms)]
    fast_check = detect_malicious_intent(text)
    if not fast_check["is_safe"]:
        return {
            "action": "BLOCK",
            "tier_used": "Tier 1 (Heuristics)",
            "threat_type": fast_check["flags"][0],
            "latency_ms": round((time.time() - start_time) * 1000, 2),
            "cost_saved": True
        }

    # ==========================================
    # TIER 2: Semantic Cache Check (Cost: $0.00, Time: 5ms)
    text_lower = text.lower()
    for known_attack in SEMANTIC_CACHE.keys():
        # In production, this uses Cosine Similarity (Vector Embeddings)
        if known_attack in text_lower:
            return {
                "action": "BLOCK",
                "tier_used": "Tier 2 (Semantic Cache)",
                "threat_type": SEMANTIC_CACHE[known_attack],
                "latency_ms": round((time.time() - start_time) * 1000, 2),
                "cost_saved": True
            }

    # TIER 3/4: The ML Oracle (Cost: $$$, Time: ~1000ms)
    # Only runs if the fast, cheap layers couldn't decide
    ml_report = await analyze_threat_ml(sender_email, text)
    
    action = "BLOCK" if (ml_report.get("is_malicious") and ml_report.get("confidence_score", 0) > 0.80) else "ALLOW"
    
    # Auto-Learning Loop (Adds new attacks to cache for the future!)
    if action == "BLOCK":
        SEMANTIC_CACHE[text_lower[:50]] = ml_report.get("threat_type")

    return {
        "action": action,
        "tier_used": "Tier 4 (ML Oracle)",
        "threat_type": ml_report.get("threat_type"),
        "confidence": ml_report.get("confidence_score"),
        "latency_ms": round((time.time() - start_time) * 1000, 2),
        "cost_saved": False
    }