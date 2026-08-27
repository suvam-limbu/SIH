import re
from typing import List

def extract_ips(headers: str) -> List[str]:
    # Extract IP addresses from Received headers
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = []
    
    for line in headers.split('\n'):
        if line.lower().startswith('received:'):
            matches = re.findall(ip_pattern, line)
            ips.extend(matches)
            
    # Filter out local IPs
    filtered_ips = []
    for ip in ips:
        if not ip.startswith('10.') and not ip.startswith('192.168.') and not ip.startswith('127.'):
            if not re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip):
                filtered_ips.append(ip)
                
    return list(set(filtered_ips))
