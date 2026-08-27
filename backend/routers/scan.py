from fastapi import APIRouter
from backend.models.schemas import ScanRequest, ScanResponse
from backend.services.header_parser import extract_ips
from backend.services.url_checker import check_urls
from backend.services.domain_intel import analyze_domain
from backend.services.ip_intel import analyze_ip
from backend.services.spf_dkim_dmarc import analyze_auth_headers
from backend.services.nlp_engine import analyze_text
from backend.services.risk_scorer import calculate_risk

router = APIRouter()

@router.post("/api/scan", response_model=ScanResponse)
async def scan_email(request: ScanRequest):
    # 1. Header parsing & IP extraction
    ips = extract_ips(request.headers)
    
    # 2. IP Intel on the first extracted IP (or mock if none)
    ip_result = None
    if ips:
        ip_result = analyze_ip(ips[0])
    else:
        ip_result = analyze_ip("8.8.8.8") # Fallback for demo
        
    # 3. Domain Intelligence
    domain_result = analyze_domain(request.sender)
    
    # 4. URL Checking
    url_result = check_urls(request.urls)
    
    # 5. Email Authentication
    auth_result = analyze_auth_headers(request.headers)
    
    # 6. NLP Engine
    nlp_result = analyze_text(request.subject, request.body)
    
    # 7. Risk Scoring
    response = calculate_risk(url_result, domain_result, nlp_result, auth_result, ip_result)
    
    return response
