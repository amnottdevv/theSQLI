#!/usr/bin/env python3
"""
ZAMZZZ SQLi Toolkit – Professional Blue UI
Fully restructured UI with dominant blue theme, no gaudy elements.
Integrasi penuh dengan modul core/ dan lib/
Fitur: SQLi, Subdomain, Path, URL to IP, DNS Lookup
"""

import sys
import argparse
import time
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.text import Text
from pyfiglet import Figlet

# Import modul internal
from lib.requester import extract_params_from_url, build_url_with_param, send_request
from lib.utils import load_wordlist, ensure_dir
from lib.savers import save_json, save_csv
from core.detector import scan_vulnerability as core_scan_vuln
from core.enumerator import Enumerator
from core.dumper import Dumper
from core.recon_subdomain import scan_subdomains
from core.recon_path import scan_paths
from core.param_scanner import scan_parameters
from core.urlip import url_to_ip
from core.dns import dns_lookup, comprehensive_dns

console = Console()

# ===============================
#  Warna & Tema
# ===============================
TITLE_COLOR   = "bold bright_blue"
HEADER_COLOR  = "bold cyan"
NORMAL_COLOR  = "white"
DIM_COLOR     = "dim"
ACCENT_COLOR  = "blue"
SUCCESS_COLOR = "green"
ERROR_COLOR   = "bold red"
INFO_COLOR    = "bright_blue"

# Global variable untuk menyimpan hasil scan sementara
last_vuln_info = None

# ===============================
#  BANNER PROFESIONAL – BLUE
# ===============================
def show_banner():
    f = Figlet(font='small')
    banner_text = f.renderText('TheSQLI')
    panel = Panel(
        Text(banner_text, style="bold bright_blue"),
        border_style="blue",
        box=box.ROUNDED,
        padding=(1, 2)
    )
    console.print(panel)
    console.print(f"[{TITLE_COLOR}]SQL Injection Toolkit[/{TITLE_COLOR}]  "
                  f"[{DIM_COLOR}]Developed by : alzzmaret[/{DIM_COLOR}]\n")
    console.print(f"[{DIM_COLOR}]Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/{DIM_COLOR}]\n")

# ===============================
#  MENU – RINGKAS & ELEGAN
# ===============================
def show_menu():
    table = Table(
        title=f"[{TITLE_COLOR}]AVAILABLE MODULES[/{TITLE_COLOR}]",
        box=box.SIMPLE_HEAVY,
        header_style=HEADER_COLOR,
        border_style="blue",
        show_edge=False,
        pad_edge=False
    )
    table.add_column("Option", justify="center", style=DIM_COLOR, width=8)
    table.add_column("Module", style="bold bright_blue")
    table.add_column("Description", style=NORMAL_COLOR)

    items = [
        ("1", "Scan Vulnerability", "Detect SQL injection on target URL (with risk level)"),
        ("2", "Enumerate Databases", "List all databases (--dbs equivalent)"),
        ("3", "Search Parameters", "Discover injectable GET/POST parameters"),
        ("4", "Dump Database", "Extract & export table data"),
        ("5", "Search Subdomain", "Brute-force subdomains of a domain"),
        ("6", "Search Path", "Brute-force directories and files"),
        ("7", "URL to IP", "Resolve domain/URL to IP address"),
        ("8", "DNS Lookup", "Query DNS records (A, MX, TXT, etc.)"),
        ("0", "Exit", "Quit the toolkit")
    ]
    for opt, mod, desc in items:
        table.add_row(opt, mod, desc)

    console.print(table)

# ===============================
#  FUNGSI UTAMA (SQL INJECTION)
# ===============================

def scan_vulnerability(url):
    global last_vuln_info
    console.print(f"\n[{INFO_COLOR}]► Starting vulnerability scan on:[/{INFO_COLOR}] {url}")
    
    risk = Prompt.ask(f"[{INFO_COLOR}]Pilih risk level (1=ringan, 2=medium, 3=berat)[/{INFO_COLOR}]", default="1")
    try:
        risk_level = int(risk)
        if risk_level not in [1,2,3]:
            risk_level = 1
    except:
        risk_level = 1
    
    results = core_scan_vuln(url, risk_level)
    
    for res in results:
        if res['vulnerable']:
            last_vuln_info = {
                'url': url,
                'param': res['parameter'],
                'technique': res['technique'],
                'dbms': res['dbms']
            }
            console.print(f"[{SUCCESS_COLOR}]✓ Vulnerable parameter: {res['parameter']} ({res['technique']})[/{SUCCESS_COLOR}]")
            break
    else:
        console.print(f"[{ERROR_COLOR}]No SQL injection vulnerability found.[/{ERROR_COLOR}]\n")

def enumerate_databases(url):
    global last_vuln_info
    console.print(f"\n[{INFO_COLOR}]► Enumerating databases on:[/{INFO_COLOR}] {url}")
    
    if last_vuln_info and last_vuln_info['url'] == url:
        param = last_vuln_info['param']
        technique = last_vuln_info['technique']
        dbms = last_vuln_info['dbms']
        console.print(f"[{INFO_COLOR}]Using previously found vulnerable parameter: {param} (technique: {technique})[/{INFO_COLOR}]")
    else:
        results = core_scan_vuln(url, risk_level=1)
        found = False
        for res in results:
            if res['vulnerable']:
                param = res['parameter']
                technique = res['technique']
                dbms = res['dbms']
                found = True
                last_vuln_info = {'url': url, 'param': param, 'technique': technique, 'dbms': dbms}
                break
        if not found:
            console.print(f"[{ERROR_COLOR}]No vulnerable parameter detected. Run Scan Vulnerability first.[/{ERROR_COLOR}]\n")
            return
    
    enumerator = Enumerator(url, param, technique, dbms, debug=False)
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_blue"),
        TextColumn(f"[{INFO_COLOR}]{{task.description}}[/{INFO_COLOR}]"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task(description="Enumerating databases...", total=None)
        databases = enumerator.list_databases()
    
    if not databases:
        console.print(f"[{ERROR_COLOR}]No databases found or enumeration failed.[/{ERROR_COLOR}]\n")
        return
    
    table = Table(title="Database List", box=box.SIMPLE, border_style="blue")
    table.add_column("#", style=DIM_COLOR, width=4)
    table.add_column("Database Name", style="bright_blue")
    for i, db in enumerate(databases, 1):
        table.add_row(str(i), db)
    console.print(table)
    console.print(f"[{SUCCESS_COLOR}]Found {len(databases)} database(s).[/{SUCCESS_COLOR}]\n")

def search_parameters(url):
    console.print(f"\n[{INFO_COLOR}]► Searching parameters on:[/{INFO_COLOR}] {url}")
    console.print(f"[{DIM_COLOR}]  Method: GET parameter brute-force[/{DIM_COLOR}]")
    
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_blue"),
        TextColumn(f"[{INFO_COLOR}]{{task.description}}[/{INFO_COLOR}]"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task(description="Scanning common parameters...", total=None)
        active_params = scan_parameters(url)
    
    if not active_params:
        console.print(f"[{DIM_COLOR}]No common parameters found.[/{DIM_COLOR}]\n")
        return
    
    table = Table(title="Discovered Parameters", box=box.SIMPLE, border_style="blue")
    table.add_column("Parameter", style="bright_blue")
    table.add_column("Status", style=INFO_COLOR)
    for p in active_params:
        table.add_row(p, f"[{DIM_COLOR}]Unknown - run scan[/{DIM_COLOR}]")
    console.print(table)
    console.print(f"[{INFO_COLOR}]→ Use Scan Vulnerability (menu 1) to test these parameters[/{INFO_COLOR}]\n")

def dump_database(url):
    global last_vuln_info
    console.print(f"\n[{INFO_COLOR}]► Dump database from:[/{INFO_COLOR}] {url}")
    
    if not last_vuln_info or last_vuln_info['url'] != url:
        console.print(f"[{ERROR_COLOR}]No vulnerable parameter known. Please run Scan Vulnerability (menu 1) first.[/{ERROR_COLOR}]\n")
        return
    
    param = last_vuln_info['param']
    technique = last_vuln_info['technique']
    dbms = last_vuln_info['dbms']
    console.print(f"[{INFO_COLOR}]Using vulnerable parameter: {param} (technique: {technique})[/{INFO_COLOR}]")
    
    enumerator = Enumerator(url, param, technique, dbms, debug=False)
    
    db_name = Prompt.ask(f"[{INFO_COLOR}]Database name to dump[/{INFO_COLOR}]")
    if not db_name:
        console.print(f"[{ERROR_COLOR}]Database name required.[/{ERROR_COLOR}]\n")
        return
    
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_blue"),
        TextColumn(f"[{INFO_COLOR}]{{task.description}}[/{INFO_COLOR}]"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task(description="Enumerating tables...", total=None)
        tables = enumerator.list_tables(db_name)
    
    if not tables:
        console.print(f"[{ERROR_COLOR}]No tables found in '{db_name}'.[/{ERROR_COLOR}]\n")
        return
    
    table_table = Table(title=f"Tables in {db_name}", box=box.SIMPLE, border_style="blue")
    table_table.add_column("#", style=DIM_COLOR)
    table_table.add_column("Table Name", style="bright_blue")
    for i, t in enumerate(tables, 1):
        table_table.add_row(str(i), t)
    console.print(table_table)
    
    table_name = Prompt.ask(f"[{INFO_COLOR}]Table name to dump[/{INFO_COLOR}]")
    if not table_name:
        console.print(f"[{ERROR_COLOR}]Table name required.[/{ERROR_COLOR}]\n")
        return
    
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_blue"),
        TextColumn(f"[{INFO_COLOR}]{{task.description}}[/{INFO_COLOR}]"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task(description="Enumerating columns...", total=None)
        columns = enumerator.list_columns(db_name, table_name)
    
    if not columns:
        console.print(f"[{INFO_COLOR}]No columns found, using all columns (*)[/{INFO_COLOR}]")
        columns = ['*']
    
    cols_table = Table(title=f"Columns in {table_name}", box=box.SIMPLE, border_style="blue")
    cols_table.add_column("#", style=DIM_COLOR)
    cols_table.add_column("Column Name", style="bright_blue")
    for i, c in enumerate(columns, 1):
        cols_table.add_row(str(i), c)
    console.print(cols_table)
    
    if not Confirm.ask(f"[{INFO_COLOR}]Dump {db_name}.{table_name}?[/{INFO_COLOR}]", default=False):
        console.print(f"[{ERROR_COLOR}]Cancelled.[/{ERROR_COLOR}]\n")
        return
    
    def get_prefix_suffix():
        return enumerator._get_clean_prefix_suffix() if hasattr(enumerator, '_get_clean_prefix_suffix') else ("1' AND ", "-- -")
    
    dumper = Dumper(url, param, technique, dbms, prefix_suffix_getter=get_prefix_suffix)
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_blue"),
        TextColumn(f"[{INFO_COLOR}]{{task.description}}[/{INFO_COLOR}]"),
        transient=False,
        console=console
    ) as progress:
        task = progress.add_task(description=f"Dumping {table_name}...", total=None)
        data = dumper.dump_table(db_name, table_name, columns)
    
    if data:
        console.print(f"[{SUCCESS_COLOR}]✓ Data saved to output/{db_name}_{table_name}.csv and .json[/{SUCCESS_COLOR}]")
    else:
        console.print(f"[{ERROR_COLOR}]Dump failed or no data returned.[/{ERROR_COLOR}]")
    console.print()

def search_subdomain(domain):
    console.print(f"\n[{INFO_COLOR}]► Subdomain discovery for:[/{INFO_COLOR}] {domain}")
    
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_blue"),
        TextColumn(f"[{INFO_COLOR}]{{task.description}}[/{INFO_COLOR}]"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task(description="Scanning subdomains...", total=None)
        results = scan_subdomains(domain)
    
    if not results:
        console.print(f"[{DIM_COLOR}]No active subdomains found.[/{DIM_COLOR}]\n")
        return
    
    table = Table(title="Active Subdomains", box=box.SIMPLE, border_style="blue")
    table.add_column("Subdomain", style="bright_blue")
    table.add_column("Status", style=INFO_COLOR)
    table.add_column("IP", style=INFO_COLOR)
    for r in results:
        table.add_row(r['subdomain'], str(r['status']), r.get('ip', 'unknown'))
    console.print(table)
    console.print(f"[{SUCCESS_COLOR}]Found {len(results)} active subdomain(s).[/{SUCCESS_COLOR}]\n")

def search_path(base_url):
    console.print(f"\n[{INFO_COLOR}]► Directory/path discovery on:[/{INFO_COLOR}] {base_url}")
    
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_blue"),
        TextColumn(f"[{INFO_COLOR}]{{task.description}}[/{INFO_COLOR}]"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task(description="Bruteforcing paths...", total=None)
        results = scan_paths(base_url)
    
    if not results:
        console.print(f"[{DIM_COLOR}]No paths found.[/{DIM_COLOR}]\n")
        return
    
    table = Table(title="Paths Found", box=box.SIMPLE, border_style="blue")
    table.add_column("Path", style="bright_blue")
    table.add_column("Status", style=INFO_COLOR)
    table.add_column("URL", style=DIM_COLOR)
    for r in results:
        table.add_row(r['path'], str(r['status']), r['url'])
    console.print(table)
    console.print(f"[{SUCCESS_COLOR}]Found {len(results)} accessible path(s).[/{SUCCESS_COLOR}]\n")

def url_to_ip_menu():
    target = Prompt.ask(f"[{INFO_COLOR}]Enter URL or domain (e.g. google.com or https://google.com)[/{INFO_COLOR}]")
    if not target:
        console.print(f"[{ERROR_COLOR}]Input required.[/{ERROR_COLOR}]")
        return
    ip, host = url_to_ip(target)
    if ip:
        console.print(f"[{SUCCESS_COLOR}]✓ {host} -> {ip}[/{SUCCESS_COLOR}]")
    else:
        console.print(f"[{ERROR_COLOR}]Failed: {host}[/{ERROR_COLOR}]")

def dns_lookup_menu():
    domain = Prompt.ask(f"[{INFO_COLOR}]Enter domain (e.g. google.com)[/{INFO_COLOR}]")
    if not domain:
        console.print(f"[{ERROR_COLOR}]Domain required.[/{ERROR_COLOR}]")
        return
    record_type = Prompt.ask(f"[{INFO_COLOR}]Record type (A/MX/TXT/NS/CNAME/SOA/ALL)[/{INFO_COLOR}]", default="A")
    if record_type.upper() == 'ALL':
        results = comprehensive_dns(domain)
    else:
        results = dns_lookup(domain, record_type.upper())
    
    table = Table(title=f"DNS Lookup: {domain}", box=box.SIMPLE, border_style="blue")
    table.add_column("Record", style="bright_blue")
    table.add_column("Value(s)", style=INFO_COLOR)
    for rec, values in results.items():
        display = "\n".join(values[:5])
        if len(values) > 5:
            display += f"\n... and {len(values)-5} more"
        table.add_row(rec, display)
    console.print(table)

# ===============================
#  MODE INTERAKTIF
# ===============================
def interactive_mode():
    global last_vuln_info
    show_banner()     
    while True:
        show_menu()
        choice = Prompt.ask(
            f"\n[{INFO_COLOR}]Select module[/{INFO_COLOR}]",
            choices=["0","1","2","3","4","5","6","7","8"],
            default="0"
        )

        if choice == "0":
            console.print(f"\n[{TITLE_COLOR}]Exiting ZAMZZZ Toolkit. Goodbye![/{TITLE_COLOR}]")
            break

        # Minta target sesuai pilihan
        if choice in ["1","2","3","4"]:
            target = Prompt.ask(f"[{INFO_COLOR}]Target URL (e.g. http://site.com/page.php?id=1)[/{INFO_COLOR}]")
            if not target:
                console.print(f"[{ERROR_COLOR}]URL cannot be empty.[/{ERROR_COLOR}]")
                continue
        elif choice == "5":
            domain = Prompt.ask(f"[{INFO_COLOR}]Domain (e.g. target.com)[/{INFO_COLOR}]")
            if not domain:
                console.print(f"[{ERROR_COLOR}]Domain cannot be empty.[/{ERROR_COLOR}]")
                continue
        elif choice == "6":
            base_url = Prompt.ask(f"[{INFO_COLOR}]Base URL (e.g. https://target.com)[/{INFO_COLOR}]")
            if not base_url:
                console.print(f"[{ERROR_COLOR}]URL cannot be empty.[/{ERROR_COLOR}]")
                continue
        elif choice == "7":
            url_to_ip_menu()
            input(f"\n[{DIM_COLOR}]Press Enter to return to menu...[/{DIM_COLOR}]")
            console.clear()
            show_banner()
            continue
        elif choice == "8":
            dns_lookup_menu()
            input(f"\n[{DIM_COLOR}]Press Enter to return to menu...[/{DIM_COLOR}]")
            console.clear()
            show_banner()
            continue

        # Eksekusi modul SQLi / recon
        if choice == "1":
            scan_vulnerability(target)
        elif choice == "2":
            enumerate_databases(target)
        elif choice == "3":
            search_parameters(target)
        elif choice == "4":
            dump_database(target)
        elif choice == "5":
            search_subdomain(domain)
        elif choice == "6":
            search_path(base_url)
        else:
            continue

        input(f"\n[{DIM_COLOR}]Press Enter to return to menu...[/{DIM_COLOR}]")
        console.clear()
        show_banner()

# ===============================
#  MODE CLI
# ===============================
def cli_mode():
    parser = argparse.ArgumentParser(description="ZAMZZZ SQLi Toolkit - CLI Mode", add_help=False)
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("--dbs", action="store_true", help="Enumerate databases")
    parser.add_argument("--scan", action="store_true", help="Scan vulnerability")
    parser.add_argument("--params", action="store_true", help="Search parameters")
    parser.add_argument("--dump", nargs=2, metavar=('DB','TABLE'), help="Dump database")
    parser.add_argument("--subdomain", help="Subdomain discovery")
    parser.add_argument("--path", help="Directory/path discovery")
    parser.add_argument("--url2ip", help="Resolve URL/domain to IP")
    parser.add_argument("--dns", help="DNS lookup for domain (records: A, MX, TXT, NS, CNAME, SOA, ALL)")
    parser.add_argument("--risk", type=int, choices=[1,2,3], default=1, help="Risk level for SQLi scan (1=low,2=medium,3=high)")
    parser.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="Show help")

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

    if args.scan and args.url:
        core_scan_vuln(args.url, args.risk)
    elif args.dbs and args.url:
        results = core_scan_vuln(args.url, 1)
        for res in results:
            if res['vulnerable']:
                enumerator = Enumerator(args.url, res['parameter'], res['technique'], res['dbms'])
                dbs = enumerator.list_databases()
                if dbs:
                    print("[+] Databases:")
                    for db in dbs:
                        print(f"  - {db}")
                else:
                    print("[-] No databases found")
                break
        else:
            print("[-] No vulnerable parameter found")
    elif args.params and args.url:
        active = scan_parameters(args.url)
        print("[+] Active parameters:", ', '.join(active) if active else "None")
    elif args.dump and args.url:
        console.print("CLI dump not fully implemented. Use interactive mode.")
    elif args.subdomain:
        results = scan_subdomains(args.subdomain)
        for r in results:
            print(f"{r['subdomain']} -> {r['status']} ({r.get('ip', 'unknown')})")
    elif args.path:
        results = scan_paths(args.path)
        for r in results:
            print(f"{r['path']} [{r['status']}]")
    elif args.url2ip:
        ip, host = url_to_ip(args.url2ip)
        if ip:
            print(f"{host} -> {ip}")
        else:
            print(f"Error: {host}")
    elif args.dns:
        if args.dns.upper() == 'ALL':
            results = comprehensive_dns(args.dns)
        else:
            results = dns_lookup(args.dns, args.dns.upper())
        for rec, values in results.items():
            print(f"{rec}:")
            for v in values:
                print(f"  {v}")
    else:
        console.print(f"[{ERROR_COLOR}]Incomplete arguments. Use --help[/{ERROR_COLOR}]")

# ===============================
#  ENTRY POINT
# ===============================
def main():
    ensure_dir('output')
    if not load_wordlist('wordlist/common_sqli.txt'):
        console.print(f"[{ERROR_COLOR}]Warning: wordlist/common_sqli.txt not found. Some features may not work.[/{ERROR_COLOR}]")
    if len(sys.argv) > 1:
        cli_mode()
    else:
        interactive_mode()

if __name__ == "__main__":
    main()