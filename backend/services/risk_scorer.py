from backend.models.schemas import ScanResponse, CheckResult, GeoLocation, DomainIntel
from typing import Dict, Any, List

def calculate_risk(
    url_result: Dict[str, Any],
    domain_result: DomainIntel,
    nlp_result: Dict[str, Any],
    auth_result: Dict[str, Any],
    ip_result: Dict[str, Any]
) -> ScanResponse:
    score = 0.0
    checks: List[CheckResult] = []
    
    # URL Reputation (25%)
    url_score = 0
    if url_result["status"] == "Malicious":
        url_score = 25
    score += url_score
    checks.append(CheckResult(name="URL Reputation", status=url_result["status"], detail=url_result["detail"]))
    
    # Domain Spoof (20%)
    domain_score = 0
    if domain_result.is_spoofed:
        domain_score = 20
        checks.append(CheckResult(name="Domain Intelligence", status="Spoofed", detail=f"Likely spoofing {domain_result.target_brand} (Similarity: {domain_result.similarity_score:.2f})"))
    else:
        checks.append(CheckResult(name="Domain Intelligence", status="Clean", detail=f"Domain {domain_result.domain} appears legitimate."))
    score += domain_score
    
    # NLP Phishing Signals (20%)
    nlp_score = 0
    if nlp_result["findings_count"] > 0:
        nlp_score = min(20, nlp_result["findings_count"] * 5)
    score += nlp_score
    checks.append(CheckResult(name="Language Analysis", status=nlp_result["status"], detail=nlp_result["detail"]))
    
    # SPF/DKIM/DMARC (15%)
    auth_score = 0
    if auth_result["status"] == "Fail":
        auth_score = 15
    score += auth_score
    checks.append(CheckResult(name="Email Authentication", status=auth_result["status"], detail=auth_result["detail"]))
    
    # IP Reputation (10%)
    ip_score = 0
    if ip_result:
        if ip_result["reputation"] == "Malicious":
            ip_score = 10
        elif ip_result["reputation"] == "Suspicious":
            ip_score = 5
        checks.append(CheckResult(name="IP Reputation", status=ip_result["reputation"], detail=ip_result["detail"]))
    
    # Header anomalies (10%) - Not fully implemented in parser, giving default 0
    
    # Risk Classification
    if score >= 75:
        risk_level = "Critical"
    elif score >= 50:
        risk_level = "High"
    elif score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"
        
    return ScanResponse(
        risk_score=score,
        risk_level=risk_level,
        checks=checks,
        geolocation=ip_result["geolocation"] if ip_result else None,
        domain_intel=domain_result
    )
