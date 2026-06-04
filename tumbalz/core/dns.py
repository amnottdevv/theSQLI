# core/dns.py
import socket
import dns.resolver
import dns.reversename

def dns_lookup(domain, record_type='A'):
    """
    Melakukan DNS lookup untuk berbagai tipe record.
    Support: A, AAAA, MX, TXT, NS, CNAME, SOA, PTR
    Return: dict dengan key record_type dan list nilai, atau pesan error.
    """
    results = {}
    try:
        answers = dns.resolver.resolve(domain, record_type)
        results[record_type] = [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        results[record_type] = [f"No {record_type} record found"]
    except dns.resolver.NXDOMAIN:
        results[record_type] = ["Domain does not exist"]
    except Exception as e:
        results[record_type] = [f"Error: {str(e)}"]
    return results

def dns_reverse_lookup(ip):
    """Reverse DNS lookup: IP -> hostname"""
    try:
        addr = dns.reversename.from_address(ip)
        hostname = dns.resolver.resolve(addr, "PTR")[0].to_text()
        return hostname
    except:
        return None

def comprehensive_dns(domain):
    """
    Melakukan lookup untuk beberapa tipe record sekaligus.
    Return: dict dengan berbagai record.
    """
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
    all_results = {}
    for rt in record_types:
        all_results.update(dns_lookup(domain, rt))
    return all_results