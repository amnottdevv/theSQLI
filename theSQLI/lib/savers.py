import json
import csv
import os
from lib.utils import ensure_dir

def save_json(data, filename):
    """Simpan data ke file JSON di folder output/"""
    ensure_dir('output')
    filepath = os.path.join('output', filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def save_csv(data, filename):
    """Simpan list of dict ke file CSV."""
    if not data:
        return
    ensure_dir('output')
    filepath = os.path.join('output', filename)
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

def save_text(text, filename):
    """Simpan teks ke file txt."""
    ensure_dir('output')
    filepath = os.path.join('output', filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(text)