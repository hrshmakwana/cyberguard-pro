# 🛡️ CyberGuard Pro — Unified Cybersecurity Suite

> **CodTech IT Solutions Internship** | Cybersecurity Domain | Tasks 1–4 Combined

A full-stack cybersecurity web application that integrates all four internship tasks
into a single professional dashboard with a Python Flask REST API backend and a
modern dark-themed frontend.

---

## 📋 Project Overview

| Task | Module | Technology |
|------|--------|------------|
| Task 1 | File Integrity Checker | `hashlib` (MD5, SHA-1, SHA-256, SHA-512) |
| Task 2 | Web Vulnerability Scanner | `requests`, `BeautifulSoup4` |
| Task 3 | Network Recon Toolkit | `socket`, `concurrent.futures` |
| Task 4 | Advanced Encryption Tool | `cryptography` (AES-256-CBC, PBKDF2) |

---

## 🏗️ Architecture

```
cyberguard/
├── app.py              # Flask REST API backend (all 4 modules)
├── requirements.txt    # Python dependencies
├── baselines.json      # Auto-created: stores file hash baselines
└── templates/
    └── index.html      # Single-page dashboard frontend
```

**Backend:** Python Flask · RESTful API · JSON responses  
**Frontend:** Vanilla HTML/CSS/JS · Dark cyberpunk theme · No framework required  
**Security:** CORS-safe · Input validation · Authorized-use disclaimers

---

## 🔒 Security Hardening (v1.1)

This project has been heavily secured for safe local usage:
- **SSRF Protection:** Network recon & web scanner explicitly deny queries to private/local/reserved IP addresses (e.g. `127.0.0.1`, `192.168.x.x`), protecting your home network from external proxy attacks.
- **Path Traversal Protection:** All file uploads use `werkzeug.utils.secure_filename` to prevent arbitrary file overwrites via malicious filenames.
- **Denial of Service (DoS):** Maximum upload limits (`MAX_CONTENT_LENGTH = 16MB`) restrict memory exhaustion.
- **Disabled Debugger:** `app.run(debug=False)` eliminates local Remote Code Execution vulnerabilities.

---

## 🚀 Setup & Run

### Prerequisites
- Python 3.8 or higher
- pip

### Installation

```bash
# 1. Clone / extract the project
cd cyberguard

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
| POST | `/api/subdomains` | **[NEW]** Concurrent Subdomain Brute-force Enumerator |
| POST | `/api/geoip` | **[NEW]** IP & Domain Geographical Location Tracker |

### Task 4 — Encryption

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/encrypt` | AES-256-CBC encrypt file → download .enc |
| POST | `/api/decrypt` | AES-256-CBC decrypt .enc file → download original |

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

## ⚠️ Legal Disclaimer

This tool is built for **educational and authorized security testing only**.

- Only scan or test systems you **own** or have **explicit written permission** to test.
- Unauthorized port scanning, vulnerability scanning, or network probing may be illegal.
- The authors accept no liability for misuse of this software.

---

## 🛠️ Technologies Used

- **Python 3.8+** — Backend language
- **Flask** — Web framework / REST API
- **hashlib** — Cryptographic hash functions (Task 1)
- **requests** — HTTP client for web scanning (Task 2)
- **BeautifulSoup4** — HTML parsing for form analysis (Task 2)
- **socket / concurrent.futures** — Network scanning with threading and subdomain brute-forcing (Task 3)
- **cryptography** — AES-256 encryption with PBKDF2 (Task 4)
- **ipaddress / werkzeug** — Internal SSRF and path-traversal security mitigations

---

## 👨‍💻 Author

**Internship:** CodTech IT Solutions  
**Domain:** Cybersecurity
