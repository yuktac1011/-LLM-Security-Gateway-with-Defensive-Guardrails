import re
from fastapi import HTTPException

def analyze_domain_reputation(sender_email: str) -> str:
    """
    DYNAMIC IDENTITY: Instead of hardcoded emails, we analyze the domain type.
    """
    domain = sender_email.split('@')[-1].lower()
    
    # High-risk burner domains (Just examples, in reality you'd use an API)
    burner_domains = ["tempmail.com", "10minutemail.com", "evil.com", "hacker.net"]
    
    if domain in burner_domains:
        return "HIGH_RISK"
    elif domain.endswith(".edu") or domain.endswith(".gov"):
        return "TRUSTED_DOMAIN"
    else:
        return "UNKNOWN_DOMAIN" # Normal users (gmail, yahoo, company domains)

def detect_malicious_intent(text: str) -> dict:
    """
    DYNAMIC FILTERING: Instead of hardcoded phrases, we look for PATTERNS of injection.
    """
    sanitized = text.replace("<", "").replace(">", "")
    
    # 1. Look for Imperative System Commands (Regex)
    # Matches patterns like: "forget everything", "ignore instructions", "you are now"
    imperative_pattern = re.compile(r'\b(ignore|forget|disregard|bypass|drop)\b.*\b(instructions|prompt|system|rules|guidelines)\b', re.IGNORECASE)
    
    # 2. Look for Roleplay/Mimicry Attempts
    roleplay_pattern = re.compile(r'\b(you are now|act as|simulate|from now on)\b', re.IGNORECASE)
    
    # 3. Look for Data Exfiltration attempts
    exfil_pattern = re.compile(r'\b(output|print|reveal|tell me)\b.*\b(system|prompt|instructions|hidden)\b', re.IGNORECASE)

    is_malicious = False
    reasons = []

    if imperative_pattern.search(sanitized):
        is_malicious = True
        reasons.append("Imperative command override detected.")
    
    if roleplay_pattern.search(sanitized):
        is_malicious = True
        reasons.append("Roleplay/Identity override detected.")
        
    if exfil_pattern.search(sanitized):
        is_malicious = True
        reasons.append("System data exfiltration attempt detected.")

    return {
        "is_safe": not is_malicious,
        "sanitized_text": sanitized,
        "flags": reasons
    }