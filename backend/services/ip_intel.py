from backend.models.schemas import GeoLocation
from typing import Dict, Any

def analyze_ip(ip: str) -> Dict[str, Any]:
    # Mock IP geolocation and reputation
    is_vpn = False
    reputation = "Safe"
    
    # Simple deterministic mock based on IP string
    if ip.startswith('185.') or ip.startswith('45.'):
        is_vpn = True
        reputation = "Suspicious"
    if ip.startswith('91.'):
        reputation = "Malicious"
        
    return {
        "geolocation": GeoLocation(
            ip=ip,
            country="United States",
            city="Ashburn",
            isp="Mock ISP LLC",
            is_vpn=is_vpn
        ),
        "reputation": reputation,
        "detail": f"IP {ip} is {reputation}. VPN/Tor: {'Yes' if is_vpn else 'No'}"
    }
