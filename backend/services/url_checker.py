from typing import List, Dict, Any

def check_urls(urls: List[str]) -> Dict[str, Any]:
    # Stub for VirusTotal / Google Safe Browsing
    status = "Safe"
    details = "No malicious URLs detected."
    malicious_urls = []
    
    for url in urls:
        # Mock detection
        if "bit.ly" in url or "evil" in url or "login" in url and "paypal" in url:
            status = "Malicious"
            malicious_urls.append(url)
            
    if status == "Malicious":
        details = f"Detected malicious URLs: {', '.join(malicious_urls)}"
        
    return {
        "status": status,
        "detail": details,
        "malicious_count": len(malicious_urls)
    }
