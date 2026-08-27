from typing import Dict, Any

def analyze_auth_headers(headers: str) -> Dict[str, Any]:
    # Mock analysis of Authentication-Results header
    spf_pass = True
    dkim_pass = True
    dmarc_pass = True
    
    auth_header = ""
    for line in headers.split('\n'):
        if line.lower().startswith('authentication-results:'):
            auth_header = line.lower()
            break
            
    if auth_header:
        if 'spf=fail' in auth_header or 'spf=softfail' in auth_header:
            spf_pass = False
        if 'dkim=fail' in auth_header:
            dkim_pass = False
        if 'dmarc=fail' in auth_header:
            dmarc_pass = False
            
    status = "Pass"
    details = "SPF, DKIM, and DMARC checks passed."
    
    if not (spf_pass and dkim_pass and dmarc_pass):
        status = "Fail"
        failed = []
        if not spf_pass: failed.append("SPF")
        if not dkim_pass: failed.append("DKIM")
        if not dmarc_pass: failed.append("DMARC")
        details = f"Authentication failed for: {', '.join(failed)}"
        
    return {
        "status": status,
        "detail": details,
        "spf": spf_pass,
        "dkim": dkim_pass,
        "dmarc": dmarc_pass
    }
