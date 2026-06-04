
# 🔍 What is TheSQLI?

## 📖 Definisi

**TheSQLI** adalah toolkit **professional untuk security testing** yang dirancang khusus untuk mendeteksi dan mengeksploitasi kerentanan **SQL Injection** pada aplikasi web. Dikembangkan dengan bahasa Python, TheSQLI menggabungkan kekuatan deteksi otomatis dengan antarmuka pengguna yang elegan dan profesional.

---

## 🎯 Tujuan Utama

| Tujuan | Deskripsi |
|--------|-----------|
| **Deteksi Dini** | Mengidentifikasi celah SQL injection sebelum dieksploitasi pihak tidak bertanggung jawab |
| **Security Assessment** | Membantu profesional keamanan dalam melakukan penetration testing |
| **Edukasi** | Media pembelajaran bagi developer dan security enthusiast tentang SQL injection |
| **Otomatisasi** | Mempercepat proses testing yang biasanya dilakukan manual |

---

## 🧠 Filosofi Desain

TheSQLI dibangun dengan filosofi **"Simple but Powerful"**:

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   🎨 Profesional   ≠   🎮 Seperti Tools Kiddie         │
│   🚀 Powerful      ≠   🐌 Lambat dan Rumit             │
│   📊 Informatif    ≠   📄 Output Berantakan            │
│   🔒 Etis          ≠   💀 Untuk Kejahatan              │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Prinsip Utama:

1. **User-Friendly** → Antarmuka interaktif dengan warna biru profesional
2. **Comprehensive** → Mendukung 4 teknik SQL injection (error, union, boolean, time)
3. **Adaptif** → Menyesuaikan payload berdasarkan struktur query target
4. **Edukatif** → Output jelas, membantu memahami celah keamanan

---

## 🏗️ Arsitektur

```
┌─────────────────────────────────────────────────────────────┐
│                        MAIN.PY                              │
│                   (UI + Orchestrator)                       │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   CORE/       │     │    LIB/       │     │   WORDLIST/   │
│               │     │               │     │               │
│ • detector    │◄────│ • requester   │────►│ • payloads    │
│ • enumerator  │     │ • savers      │     │ • subdomains  │
│ • dumper      │     │ • utils       │     │ • paths       │
│ • recon_*     │     │               │     │ • params      │
└───────────────┘     └───────────────┘     └───────────────┘
```

---

## 🔬 Teknik SQL Injection yang Didukung

### 1. Error-Based Injection
Memaksa database mengeluarkan pesan error yang mengandung data sensitif.

```sql
1' AND extractvalue(1,concat(0x7e,version()))--
```

### 2. Union-Based Injection
Menggabungkan hasil query asli dengan query yang diinjeksikan.

```sql
-1' UNION SELECT username,password FROM users--
```

### 3. Boolean-Based Blind
Menyimpulkan data berdasarkan perbedaan respons (true/false).

```sql
1' AND SUBSTRING(database(),1,1)='a'--
```

### 4. Time-Based Blind
Mengukur waktu respons untuk menyimpulkan kebenaran kondisi.

```sql
1' AND IF(1=1, SLEEP(5), 0)--
```

---

## 📊 Perbandingan TheSQLI vs Tools Lain

| Fitur | TheSQLI | SQLMap | Manual Testing |
|-------|---------|--------|----------------|
| **Deteksi Otomatis** | ✅ | ✅ | ❌ |
| **UI Profesional** | ✅ (Blue Theme) | ❌ (CLI biasa) | N/A |
| **Multi-Risk Level** | ✅ (1,2,3) | ✅ (1-5) | N/A |
| **Dump Database** | ✅ (CSV/JSON) | ✅ | ✅ (manual) |
| **Subdomain Discovery** | ✅ | ❌ | ✅ |
| **Path Brute-Force** | ✅ | ❌ | ✅ |
| **DNS Lookup** | ✅ | ❌ | ✅ |
| **Mudah Dipelajari** | ✅ | ❌ (ribuan opsi) | ❌ |
| **Kecepatan Scan** | Cepat | Lambat (full test) | N/A |

---

## 🎯 Target Pengguna

| Pengguna | Kegunaan |
|----------|----------|
| **Security Engineer** | Penetration testing cepat dan efisien |
| **Bug Hunter** | Identifikasi SQL injection di program bug bounty |
| **Developer** | Validasi keamanan aplikasi sendiri |
| **Student** | Belajar SQL injection secara praktis |
| **QA Tester** | Menemukan celah sebelum production |

---

## ⚖️ Aspek Etis dan Legal

### ✅ Boleh Digunakan Untuk:
- Testing aplikasi milik sendiri
- Testing dengan izin tertulis dari pemilik
- Platform latihan resmi (DVWA, PortSwigger, VulnHub)
- Program bug bounty yang mengizinkan automated tools

### ❌ Dilarang Digunakan Untuk:
- Menyerang sistem tanpa izin
- Mencuri data orang lain
- Aktivitas ilegal lainnya

---

## 🧪 Use Cases

### Case 1: Security Engineer melakukan audit internal
```bash
# Scan semua parameter di aplikasi internal perusahaan
python main.py -u "https://internal-app.com/products.php?id=1" --scan --risk 3
```

### Case 2: Bug Hunter menguji program bounty
```bash
# Deteksi cepat parameter vulnerable
python main.py -u "https://target.com/page?item=123" --scan
python main.py -u "https://target.com/page?item=123" --dbs
```

### Case 3: Developer memvalidasi kode sendiri
```bash
# Pastikan aplikasi yang baru deploy aman
python main.py -u "http://localhost:8080/user?id=1" --scan
```

---

## 🚀 Status Pengembangan

| Komponen | Status |
|----------|--------|
| MySQL Support | ✅ Full |
| MSSQL Support | ⚠️ Partial |
| PostgreSQL Support | ❌ Planned |
| Oracle Support | ❌ Planned |
| POST Parameter | ⚠️ Limited |
| COOKIE Injection | ❌ Planned |

---

## 📞 Dukungan

- **Developer:** alzzmaret
- **Dokumentasi:** `/docs/` directory
- **Lisensi:** MIT

---

<div align="center">

**TheSQLI — Professional Security Testing Toolkit**

*"Know your vulnerabilities before the attackers do"*

</div>
