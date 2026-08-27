from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any

class ScanRequest(BaseModel):
    sender: str
    subject: str
    body: str
    urls: List[str] = []
    headers: str

class CheckResult(BaseModel):
    name: str
    status: str
    detail: str

class GeoLocation(BaseModel):
    ip: str
    country: str
    city: str
    isp: str
    is_vpn: bool = False

class DomainIntel(BaseModel):
    domain: str
    is_spoofed: bool
    similarity_score: Optional[float] = None
    target_brand: Optional[str] = None
    age_days: Optional[int] = None
    whois_privacy: bool = False
    mx_records_valid: bool = True

class ScanResponse(BaseModel):
    risk_score: float
    risk_level: str
    checks: List[CheckResult]
    geolocation: Optional[GeoLocation] = None
    domain_intel: Optional[DomainIntel] = None
