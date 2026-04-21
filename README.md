# 🛡️ CyberGuard Pro — Unified Cybersecurity Suite

> **CodTech IT Solutions Internship** | Cybersecurity Domain | Tasks 1–4 Combined

A full-stack cybersecurity web application that integrates all four internship tasks
into a single professional dashboard with a Python Flask REST API backend, modular
architecture, and PDF report generation.

---

> **⚠️ Legal & Ethical Disclaimer**
> 
> **CyberGuard Pro is developed strictly for educational purposes, authorized security auditing, and ethical hacking.**
> 
> **No Unauthorized Scanning:** You must not use this tool to scan, probe, or test networks, web applications, or infrastructure that you do not actively own or have explicit, written permission to audit.
> 
> **Zero Liability:** The creator(s) and contributors of this repository assume absolutely no liability and are not responsible for any misuse, damage, or illegal activity caused by this software.
> 
> **Compliance:** It is the end user's responsibility to obey all applicable local, state, and federal laws.
> 
> **By downloading, cloning, or using this software, you acknowledge and agree to these terms.**

---

## 📋 Project Overview

| Task | Module | Technology |
|------|--------|------------|
| Task 1 | File Integrity Checker | `hashlib` (MD5, SHA-1, SHA-256, SHA-512) |
| Task 2 | Web Vulnerability Scanner | `requests`, `BeautifulSoup4` |
| Task 3 | Network Recon Toolkit | `socket`, `concurrent.futures` |
| Task 4 | Advanced Encryption Tool | `cryptography` (AES-256-CBC, PBKDF2) |
| **NEW** | PDF Report Generator | `reportlab` (branded PDF reports) |

---

## 🏗️ Architecture

```
cyberguard-pro/
├── app.py                      # Flask entry point — registers blueprints & PDF endpoints
├── config.py                   # Centralized configuration & constants
├── requirements.txt            # Python dependencies
├── baselines.json              # Auto-created: stores file hash baselines
│
├── modules/                    # Flask Blueprint modules
│   ├── __init__.py
│   ├── utils.py                # Shared helpers (SSRF protection, etc.)
│   ├── integrity.py            # Task 1 — File Integrity Checker
│   ├── scanner.py              # Task 2 — Web Vulnerability Scanner
│   ├── recon.py                # Task 3 — Network Recon Toolkit
│   └── encryption.py           # Task 4 — AES-256 Encryption Tool
│
├── reports/                    # PDF report generation
│   ├── __init__.py
│   └── pdf_generator.py        # ReportLab branded PDF builder
│
├── static/                     # Frontend assets
│   ├── css/
│   │   └── style.css           # Dark cyberpunk theme styles
│   └── js/
│       └── app.js              # Navigation, API calls, PDF downloads
│
└── templates/
    └── index.html              # Single-page dashboard frontend
```

**Backend:** Python Flask · Blueprints · RESTful API · JSON responses
**Frontend:** Vanilla HTML/CSS/JS · Dark cyberpunk theme · No framework required
**Reports:** ReportLab PDF generation with branded CyberGuard Pro templates
**Security:** CORS-safe · Input validation · SSRF protection · Authorized-use disclaimers

---

## 🔒 Security Hardening (v1.1)

This project has been heavily secured for safe local usage:
- **SSRF Protection:** Network recon & web scanner explicitly deny queries to private/local/reserved IP addresses (e.g. `127.0.0.1`, `192.168.x.x`), protecting your home network from external proxy attacks.
- **Path Traversal Protection:** All file uploads use `werkzeug.utils.secure_filename` to prevent arbitrary file overwrites via malicious filenames.
- **Denial of Service (DoS):** Maximum upload limits (`MAX_CONTENT_LENGTH = 16MB`) restrict memory exhaustion.
- **Disabled Debugger:** `app.run(debug=False)` eliminates local Remote Code Execution vulnerabilities.

---

## 📄 PDF Report Feature (v2.0)

Every security tool can generate a **branded PDF report** with:
- **CyberGuard Pro header** with branding and timestamp
- **Structured tables** with alternating row colors
- **Color-coded severity** indicators (HIGH=red, MEDIUM=orange, LOW=green)
- **Professional footer** with disclaimer and generation timestamp

| Tool | Report Contents |
|------|----------------|
| File Integrity (T1) | Hash values, integrity status, baseline comparison |
| Vuln Scanner (T2) | Risk level, vulnerabilities, headers, SSL info |
| Network Recon (T3) | Port scan, DNS, ping, subdomains, GeoIP — combined report |
| Encryption (T4) | Operation log, algorithm details, file metadata |

---

## 🚀 Setup & Run

### Prerequisites
- Python 3.8 or higher
- pip

### Installation

```bash
# 1. Clone / extract the project
cd cyberguard-pro

# 2. (Optional) Create virtual environment
python -m venv venv
source venv/bin/activate       # Linux/Mac
venv\Scripts\activate          # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

### Open in Browser
```
http://localhost:5000
```

---

## 🔧 API Endpoints

### Task 1 — File Integrity

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/hash` | Compute MD5/SHA1/SHA256/SHA512 for uploaded file |
| POST | `/api/integrity/save` | Save file hash as trusted baseline |
| POST | `/api/integrity/check` | Compare file against saved baseline |
| GET | `/api/integrity/baselines` | List all saved baselines |

### Task 2 — Vulnerability Scanner

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Full web vulnerability scan (SQLi, XSS, headers, SSL) |

### Task 3 — Network Recon

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/portscan` | Threaded port scanner (common/top200 modes) |
| POST | `/api/dns` | DNS resolution and PTR lookup |
| POST | `/api/ping` | Host reachability check with latency |
| POST | `/api/subdomains` | Concurrent Subdomain Brute-force Enumerator |
| POST | `/api/geoip` | IP & Domain Geographical Location Tracker |

### Task 4 — Encryption

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/encrypt` | AES-256-CBC encrypt file → download .enc |
| POST | `/api/decrypt` | AES-256-CBC decrypt .enc file → download original |

### PDF Reports (NEW)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/report/integrity` | Generate file integrity PDF report |
| POST | `/api/report/scan` | Generate vulnerability scan PDF report |
| POST | `/api/report/recon` | Generate network recon PDF report |
| POST | `/api/report/encryption` | Generate encryption operation PDF report |

---

## 🔐 Encryption Details (Task 4)

```
Algorithm : AES-256-CBC
Key size  : 256 bits (32 bytes)
KDF       : PBKDF2-HMAC-SHA256
Iterations: 120,000 (OWASP 2023 recommendation)
Salt      : 16 bytes (random, per file)
IV        : 16 bytes (random, per encryption)
Padding   : PKCS7

File Format: MAGIC(9) | SALT(16) | IV(16) | CIPHERTEXT(n)
```



---

## 🛠️ Technologies Used

- **Python 3.8+** — Backend language
- **Flask** — Web framework / REST API with Blueprints
- **hashlib** — Cryptographic hash functions (Task 1)
- **requests** — HTTP client for web scanning (Task 2)
- **BeautifulSoup4** — HTML parsing for form analysis (Task 2)
- **socket / concurrent.futures** — Network scanning with threading and subdomain brute-forcing (Task 3)
- **cryptography** — AES-256 encryption with PBKDF2 (Task 4)
- **ReportLab** — PDF report generation with branded templates (NEW)
- **ipaddress / werkzeug** — Internal SSRF and path-traversal security mitigations

---

## 👨‍💻 Author

**Internship:** CodTech IT Solutions
**Domain:** Cybersecurity

---

## 📜 License

This project is licensed under the **MIT License**.

Copyright (c) 2026 Harsh Makwana

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
