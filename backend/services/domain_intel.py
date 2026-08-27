import re
from backend.models.schemas import DomainIntel

# A simple Levenshtein distance implementation
def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def analyze_domain(sender: str) -> DomainIntel:
    # Extract domain from sender email
    domain_match = re.search(r'@([\w.-]+)', sender)
    if not domain_match:
        return DomainIntel(domain="unknown", is_spoofed=False)
        
    domain = domain_match.group(1).lower()
    tld_stripped = domain.split('.')[0] if '.' in domain else domain
    
    known_brands = {
        "paypal": "paypal",
        "google": "google",
        "microsoft": "microsoft",
        "apple": "apple",
        "amazon": "amazon",
        "netflix": "netflix",
        "facebook": "facebook",
        "bankofamerica": "bankofamerica",
        "chase": "chase",
        "wellsfargo": "wellsfargo"
    }
    
    is_spoofed = False
    similarity_score = 0.0
    target_brand = None
    
    if tld_stripped not in known_brands:
        for brand in known_brands:
            distance = levenshtein_distance(tld_stripped, brand)
            max_len = max(len(tld_stripped), len(brand))
            sim = (max_len - distance) / max_len if max_len > 0 else 0
            
            # If similarity is between 75% and 99%, it might be a spoof
            if 0.75 <= sim < 1.0:
                is_spoofed = True
                similarity_score = sim
                target_brand = brand
                break
                
    return DomainIntel(
        domain=domain,
        is_spoofed=is_spoofed,
        similarity_score=similarity_score,
        target_brand=target_brand,
        age_days=15, # Stub for WHOIS age
        whois_privacy=True, # Stub
        mx_records_valid=True # Stub
    )
