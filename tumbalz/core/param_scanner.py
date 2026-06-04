from lib.requester import send_request, build_url_with_param
from lib.utils import load_wordlist

def scan_parameters(base_url, params_list=None):
    """Cek parameter mana yang menghasilkan respon berbeda (potensi injeksi)."""
    if params_list is None:
        params_list = load_wordlist('wordlist/params.txt')
    active_params = []
    for param in params_list[:50]:
        test_url = build_url_with_param(base_url, param, 'test123')
        resp = send_request(test_url)
        if resp and resp.status_code != 404:
            active_params.append(param)
    return active_params