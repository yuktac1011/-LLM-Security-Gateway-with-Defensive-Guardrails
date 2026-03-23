import re
import asyncio
import httpx
import dns.resolver
from fastapi import HTTPException

# In-memory cache so we only download the 40k+ threat feed once per server start
DISPOSABLE_DOMAINS_CACHE = set()

# Standard free providers that are generally safe but not corporate
FREE_PROVIDERS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"}

async def fetch_threat_feed():
    """Fetches a live OSINT feed of 40,000+ known burner/disposable domains."""
    url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            if response.status_code == 200:
                domains = response.text.splitlines()
                DISPOSABLE_DOMAINS_CACHE.update([d.strip().lower() for d in domains if d.strip()])
                print(f"Loaded {len(DISPOSABLE_DOMAINS_CACHE)} domains into Threat Cache.")
    except Exception as e:
        print(f"Warning: Could not fetch threat feed: {e}")

async def analyze_domain_reputation(sender_email: str) -> dict:
    """
    DYNAMIC DOMAIN CLASSIFIER:
    1. Checks live Threat Intel (Burner domains)
    2. Checks standard free providers
    3. Performs real-world DNS MX Record validation to catch spoofed domains.
    """
    domain = sender_email.split('@')[-1].lower()

    # Load Threat Feed on first run
    if not DISPOSABLE_DOMAINS_CACHE:
        await fetch_threat_feed()

    # 1. Threat Intel Check
    if domain in DISPOSABLE_DOMAINS_CACHE:
        return {"is_safe": False, "profile": "HIGH_RISK", "reason": "Known disposable/burner domain detected via OSINT feed."}

    # 2. Free Provider Check
    if domain in FREE_PROVIDERS:
        return {"is_safe": True, "profile": "STANDARD_USER", "reason": "Verified public free email provider."}

    # 3. DNS MX Validation (Checks if the domain actually has active mail servers)
    try:
        loop = asyncio.get_running_loop()
        # Query global DNS for Mail Exchange records
        answers = await loop.run_in_executor(None, dns.resolver.resolve, domain, 'MX')
        if answers:
            # If it has MX records and isn't on a blocklist, it's a valid corporate/custom domain
            return {"is_safe": True, "profile": "CORPORATE_OR_CUSTOM", "reason": "Valid DNS Mail Exchange records found."}
    except Exception:
        # If DNS fails, the domain doesn't exist or cannot receive email
        return {"is_safe": False, "profile": "INVALID_OR_SPOOFED", "reason": "Domain has no valid DNS records. Likely spoofed."}

    return {"is_safe": True, "profile": "UNKNOWN", "reason": "Domain exists but profile is unknown."}


def detect_malicious_intent(text: str) -> dict:
    """TIER 1 HEURISTICS: Fast regex checks (Keeping your existing logic)."""
    sanitized = text.replace("<", "").replace(">", "")
    imperative_pattern = re.compile(r'\b(ignore|forget|disregard|bypass|drop)\b.*\b(instructions|prompt|system|rules|guidelines)\b', re.IGNORECASE)
    
    if imperative_pattern.search(sanitized):
        return {"is_safe": False, "flags": ["Regex: Imperative command override detected"]}
    return {"is_safe": True, "flags": []}