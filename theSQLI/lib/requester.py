import requests
import time

def send_request(url, params=None, method='GET', headers=None, timeout=10, allow_redirects=True):
    """
    Kirim request HTTP dengan handling error sederhana.
    Return response object jika sukses, None jika gagal.
    """
    if headers is None:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    try:
        if method.upper() == 'GET':
            resp = requests.get(url, params=params, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        elif method.upper() == 'POST':
            resp = requests.post(url, data=params, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        else:
            return None
        return resp
    except Exception:
        return None

def extract_params_from_url(url):
    """Ekstrak parameter GET dari URL."""
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # kembalikan list parameter name (tanpa nilai)
    return list(params.keys()) if params else []

def build_url_with_param(url, param, value):
    """Bangun URL dengan mengganti nilai parameter tertentu."""
    from urllib.parse import urlparse, parse_qs, urlunparse
    parsed = urlparse(url)
    query_dict = parse_qs(parsed.query)
    query_dict[param] = [value]
    # rebuild query
    from urllib.parse import urlencode
    new_query = urlencode(query_dict, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)