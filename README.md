# 🛡️ TheSQLI - SQL Injection Toolkit

<div align="center"><img width="1111" height="619" alt="dx" src="https://github.com/user-attachments/assets/b8290860-42aa-4244-8162-bf4b0fda8df5" />


![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-brightblue)
![License](https://img.shields.io/badge/license-MIT-red)
![Status](https://img.shields.io/badge/status-stable-green)

**Professional SQL Injection & Web Security Testing Toolkit**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Modules](#modules) • [Documentation](#documentation)

</div>

---

## 📋 Overview

**TheSQLI** is a comprehensive web security testing toolkit developed by **alzzmaret**. It provides automated SQL injection detection, database enumeration, subdomain discovery, path brute-forcing, DNS lookup, and IP resolution tools — all wrapped in a professional blue-themed CLI interface.

> ⚠️ **Disclaimer**: This tool is for educational purposes and authorized security testing only. Use only on systems you own or have explicit permission to test.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **SQL Injection Scanner** | Multi-level scanning (1-3) with 500+ payloads |
| 💾 **Database Enumeration** | Extract database names, tables, columns |
| 📤 **Data Dumper** | Export data to CSV/JSON format |
| 🌐 **Subdomain Discovery** | DNS + HTTP brute-force with wordlist |
| 📂 **Path Brute-Forcer** | Directory/file discovery (admin panel, config, etc.) |
| 🔎 **Parameter Scanner** | Detect GET/POST injection points |
| 🏠 **URL to IP** | Resolve domains to IPv4/IPv6 |
| 🔧 **DNS Lookup** | Query A, MX, TXT, NS, CNAME, SOA records |

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Step 1: Clone or Download

```bash
git clone https://github.com/alzzmaret/theSQLI.git
cd theSQLI
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
requests>=2.28.0
rich>=13.0.0
pyfiglet>=0.8.post1
dnspython>=2.3.0
```

### Step 3: Verify Installation

```bash
python main.py
```

You should see the banner and interactive menu.

---

## 📁 Project Structure

```
theSQLI/
├── main.py                 # Main entry point (CLI + Interactive)
├── core/                   # Core modules
│   ├── detector.py         # SQL injection detection
│   ├── enumerator.py       # Database enumeration
│   ├── dumper.py           # Data extraction & export
│   ├── param_scanner.py    # Parameter discovery
│   ├── recon_subdomain.py  # Subdomain brute-force
│   ├── recon_path.py       # Directory/path brute-force
│   ├── urlip.py            # URL to IP resolver
│   └── dns.py              # DNS record lookup
├── lib/                    # Utility libraries
│   ├── requester.py        # HTTP request handler
│   ├── savers.py           # CSV/JSON export
│   └── utils.py            # Common utilities
├── wordlist/               # Payload & wordlist files
│   ├── common_sqli.txt     # Basic SQLi payloads
│   ├── common_sqli2.txt    # Medium SQLi payloads
│   ├── common_sqli3.txt    # Advanced/WAF bypass payloads
│   ├── common_subdomain.txt # Subdomain wordlist
│   ├── path.txt            # Directory/file wordlist
│   └── params.txt          # Parameter wordlist
└── output/                 # Dumped data storage
```

---

## 🎮 Usage

### Interactive Mode (Default)

Simply run without arguments:

```bash
python main.py
```

Navigate using number keys (0-8) and follow prompts.

### Command Line Mode

```bash
# SQL Injection Scan
python main.py -u "http://target.com/page.php?id=1" --scan --risk 3

# Enumerate Databases
python main.py -u "http://target.com/page.php?id=1" --dbs

# Search Parameters
python main.py -u "http://target.com/page.php" --params

# Subdomain Discovery
python main.py --subdomain target.com

# Path Brute-Forcing
python main.py --path https://target.com

# URL to IP
python main.py --url2ip google.com

# DNS Lookup
python main.py --dns google.com
python main.py --dns google.com --record MX
```

---

## 📋 Modules Guide

### 1. Scan Vulnerability (`--scan`)

Detects SQL injection with 3 risk levels:

| Level | Description | Payloads Used |
|-------|-------------|---------------|
| 1 (Ringan) | Basic detection | `common_sqli.txt` (error-based) |
| 2 (Medium) | Extended testing | `common_sqli2.txt` (+time-based) |
| 3 (Berat) | Advanced bypass | `common_sqli3.txt` (+WAF bypass) |

**Output:** Vulnerable parameters, technique (error/union/boolean/time), DBMS type.

### 2. Enumerate Databases (`--dbs`)

Lists all databases after detecting vulnerability.

### 3. Search Parameters

Brute-forces common parameter names (`id`, `page`, `q`, `cat`, etc.).

### 4. Dump Database

Extracts table data and exports to `output/{db}_{table}.csv` and `.json`.

### 5. Search Subdomain

DNS + HTTP enumeration of subdomains. Supports `common_subdomain.txt`.

### 6. Search Path

Directory brute-forcing with `path.txt` wordlist.

### 7. URL to IP

Resolves hostname to IPv4/IPv6 address.

### 8. DNS Lookup

Query DNS records: A, AAAA, MX, TXT, NS, CNAME, SOA.

---

## 🛠️ Configuration

### Custom Wordlists

Place custom wordlists in `/wordlist/` directory:

- `common_sqli.txt` - SQL injection payloads
- `common_sqli2.txt` - Medium payloads
- `common_sqli3.txt` - Advanced bypass payloads
- `common_subdomain.txt` - Subdomain names
- `path.txt` - Directory/file paths
- `params.txt` - Parameter names

### Output Directory

All dumped data is saved to `/output/` folder (auto-created).

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| `No vulnerable parameter found` | Ensure URL has parameters (e.g., `?id=1`) |
| `No databases found` | Target may have WAF; try risk level 3 |
| `Connection timeout` | Increase timeout in `lib/requester.py` |

---

## 📝 Example Walkthrough

**Target:** `http://testphp.vulnweb.com/artists.php?artist=1`

```bash
python main.py

# Interactive Menu:
# 1. Scan Vulnerability (Level: 3)
# Output: ✓ Vulnerable! id parameter (error-based, MySQL)

# 2. Enumerate Databases
# Output: acuart, information_schema, mysql

# 3. Dump Database
# Database: acuart
# Table: users
# Columns: uname, pass
# Output saved to output/acuart_users.csv
```

---

## 🔒 Legal & Ethics

- **Only test systems you own or have written permission to test.**
- Unauthorized access is illegal in most jurisdictions.
- The developer assumes no liability for misuse.

---

## 📞 Contact & Support

- **Developer:** alzzmaret
- **Project:** TheSQLI - ZAMZZZ SQL Injection Toolkit

---

## 📄 License

MIT License - Use freely, modify responsibly.

---

<div align="center">
  <sub>Built with 🔥 by alzzmaret</sub>
</div>
