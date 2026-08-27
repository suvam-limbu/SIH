import re
from typing import Dict, Any

def analyze_text(subject: str, body: str) -> Dict[str, Any]:
    text = f"{subject} {body}".lower()
    
    urgency_patterns = [r"immediately", r"within 24 hours", r"urgent", r"account suspended", r"action required"]
    financial_patterns = [r"invoice", r"wire transfer", r"payment", r"billing", r"transaction"]
    credential_patterns = [r"verify", r"confirm", r"login", r"password", r"credential"]
    impersonation_patterns = [r"ceo", r"it department", r"hr", r"human resources", r"admin"]
    
    findings = []
    
    if any(re.search(p, text) for p in urgency_patterns):
        findings.append("Urgency cues detected")
        
    if any(re.search(p, text) for p in financial_patterns):
        findings.append("Financial manipulation detected")
        
    if any(re.search(p, text) for p in credential_patterns):
        findings.append("Credential harvesting language detected")
        
    if any(re.search(p, text) for p in impersonation_patterns):
        findings.append("Authority impersonation detected")
        
    status = "Suspicious" if findings else "Clean"
    detail = "NLP detected: " + ", ".join(findings) if findings else "No phishing language patterns detected."
    
    return {
        "status": status,
        "detail": detail,
        "findings_count": len(findings)
    }
