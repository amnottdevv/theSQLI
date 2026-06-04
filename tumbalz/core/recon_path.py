# core/recon_path.py
from lib.requester import send_request
from lib.utils import load_wordlist

def scan_paths(base_url, wordlist='wordlist/path.txt', extensions=None):
    """
    Bruteforce direktori/file berdasarkan wordlist.
    extensions: list ekstensi yang akan ditambahkan (contoh: ['.php', '.html'])
    Kembalikan list dict: {'path': ..., 'status': ..., 'url': ...}
    """
    paths = load_wordlist(wordlist)
    found = []
    
    for path in paths:
        # Coba path tanpa ekstensi dulu
        test_url = base_url.rstrip('/') + '/' + path.lstrip('/')
        resp = send_request(test_url, timeout=5)
        if resp and resp.status_code in [200, 301, 302, 403, 401]:
            found.append({
                'path': path,
                'status': resp.status_code,
                'url': test_url
            })
            continue  # jika sudah ketemu, skip ekstensi (optional)
        
        # Jika ada ekstensi yang ditentukan
        if extensions:
            for ext in extensions:
                ext_url = test_url + ext
                resp_ext = send_request(ext_url, timeout=5)
                if resp_ext and resp_ext.status_code in [200, 301, 302, 403, 401]:
                    found.append({
                        'path': path + ext,
                        'status': resp_ext.status_code,
                        'url': ext_url
                    })
    return found