# core/urlip.py
import socket
import re
from urllib.parse import urlparse

def url_to_ip(url_or_host):
    """
    Mengubah URL atau hostname menjadi IP address.
    Support: http://example.com, https://example.com, atau example.com
    Return: (ip_address, hostname) atau (None, error_message)
    """
    # Ekstrak hostname dari URL jika perlu
    if url_or_host.startswith(('http://', 'https://')):
        parsed = urlparse(url_or_host)
        hostname = parsed.hostname
    else:
        hostname = url_or_host
    
    if not hostname:
        return None, "Invalid URL/hostname"
    
    try:
        ip = socket.gethostbyname(hostname)
        return ip, hostname
    except socket.gaierror:
        return None, f"Cannot resolve: {hostname}"
    except Exception as e:
        return None, str(e)