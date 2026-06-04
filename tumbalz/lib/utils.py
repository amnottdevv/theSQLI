import os

def load_wordlist(filepath):
    """Load wordlist dari file, return list baris non-kosong."""
    wordlist = []
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                wordlist.append(line)
    return wordlist

def ensure_dir(directory):
    """Buat direktori jika belum ada."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def detect_dbms_from_error(error_text):
    """Deteksi DBMS dari pesan error SQL."""
    error_lower = error_text.lower()
    if 'mysql' in error_lower:
        return 'MySQL'
    elif 'sqlite' in error_lower:
        return 'SQLite'
    elif 'postgresql' in error_lower or 'pg_' in error_lower:
        return 'PostgreSQL'
    elif 'microsoft' in error_lower or 'odbc' in error_lower:
        return 'MSSQL'
    elif 'oracle' in error_lower:
        return 'Oracle'
    else:
        return 'Unknown'