# core/param_scanner.py
from lib.requester import send_request, build_url_with_param
from lib.utils import load_wordlist

def scan_parameters(base_url, wordlist='wordlist/params.txt'):
    """
    Mencari parameter GET yang aktif pada URL.
    Mengembalikan list parameter yang menghasilkan response bukan 404.
    """
    params = load_wordlist(wordlist)
    active = []
    for param in params[:100]:  # batasi 100 untuk kecepatan
        test_url = build_url_with_param(base_url, param, 'test123')
        resp = send_request(test_url, timeout=5)
        if resp and resp.status_code != 404:
            active.append(param)
    return active