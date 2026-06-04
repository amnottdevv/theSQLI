# core/recon_subdomain.py
import socket
import dns.resolver
from lib.requester import send_request
from lib.utils import load_wordlist

def resolve_dns(subdomain):
    """Coba resolve DNS, return IP atau None"""
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except:
        return None

def scan_subdomains(domain, wordlist='wordlist/common_subdomain.txt', method='http'):
    """
    Brute-force subdomain dengan DNS lookup dan HTTP check.
    method: 'dns', 'http', atau 'both'
    Kembalikan list dict: {'subdomain': ..., 'status': ..., 'ip': ...}
    """
    subs = load_wordlist(wordlist)
    found = []
    
    for sub in subs:
        full_domain = f"{sub}.{domain}"
        result = {'subdomain': full_domain}
        
        # DNS lookup
        ip = resolve_dns(full_domain)
        if ip:
            result['ip'] = ip
            result['status'] = 'DNS resolved'
            found.append(result)
            continue  # jika sudah resolve, skip HTTP check? Bisa juga tetap cek HTTP
        
        # Jika DNS gagal, coba HTTP
        if method in ('http', 'both'):
            for scheme in ['http', 'https']:
                url = f"{scheme}://{full_domain}"
                resp = send_request(url, timeout=5)
                if resp and resp.status_code < 400:
                    result['ip'] = resolve_dns(full_domain) or 'unknown'
                    result['status'] = resp.status_code
                    result['url'] = url
                    found.append(result)
                    break
    return found