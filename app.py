#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║          CyberGuard Pro - Unified Cybersecurity Suite         ║
║          CodTech Internship - Combined Tasks 1, 2, 3, 4       ║
║          Author: Intern @ CodTech IT Solutions                ║
╚═══════════════════════════════════════════════════════════════╝

Modules:
  Task 1 → File Integrity Checker (hashlib: MD5, SHA-1, SHA-256, SHA-512)
  Task 2 → Web Vulnerability Scanner (SQLi, XSS, Security Headers)
  Task 3 → Network Recon Toolkit (Port Scanner, DNS Lookup, Ping)
  Task 4 → Advanced Encryption Tool (AES-256-CBC + PBKDF2)
"""

import os
import io
import re
import ssl
import json
import time
import socket
import hashlib
import ipaddress
import concurrent.futures
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests as http_requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# ──────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates")
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size
BASELINE_FILE = "baselines.json"

@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

def is_safe_target(host: str) -> bool:
    """Check if the given host resolves to a public, non-reserved IP address."""
    try:
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved:
            return False
        return True
    except socket.gaierror:
        # If it can't resolve, conservatively treat it as unsafe to avoid DNS rebinding or other issues
        return False

# ══════════════════════════════════════════════════════════════
# TASK 1 ── FILE INTEGRITY CHECKER
# ══════════════════════════════════════════════════════════════

def compute_hashes(file_data: bytes) -> dict:
    """Compute MD5, SHA-1, SHA-256, and SHA-512 hashes of raw bytes."""
    return {
        "md5":    hashlib.md5(file_data).hexdigest(),
        "sha1":   hashlib.sha1(file_data).hexdigest(),
        "sha256": hashlib.sha256(file_data).hexdigest(),
        "sha512": hashlib.sha512(file_data).hexdigest(),
    }


@app.route("/api/hash", methods=["POST"])
def hash_file():
    """Endpoint: Compute all hashes for an uploaded file."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    data = f.read()
    result = compute_hashes(data)
    secure_name = secure_filename(f.filename)
    result.update({
        "filename":  secure_name,
        "size_bytes": len(data),
        "timestamp": datetime.now().isoformat(),
    })
    return jsonify(result)


@app.route("/api/integrity/save", methods=["POST"])
def save_baseline():
    """Endpoint: Save current file hash as the trusted baseline."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    data = f.read()
    secure_name = secure_filename(f.filename)
    hashes = compute_hashes(data)

    # Load existing baselines from disk
    baselines = {}
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE) as fh:
            baselines = json.load(fh)

    baselines[secure_name] = {
        **hashes,
        "size_bytes": len(data),
        "saved_at":   datetime.now().isoformat(),
    }

    with open(BASELINE_FILE, "w") as fh:
        json.dump(baselines, fh, indent=2)

    return jsonify({"message": f"Baseline saved for '{secure_name}'", "hashes": hashes})


@app.route("/api/integrity/check", methods=["POST"])
def check_integrity():
    """Endpoint: Compare uploaded file against its saved baseline."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    data = f.read()
    secure_name = secure_filename(f.filename)
    current = compute_hashes(data)

    if not os.path.exists(BASELINE_FILE):
        return jsonify({"error": "No baselines saved yet. Save a baseline first."}), 404

    with open(BASELINE_FILE) as fh:
        baselines = json.load(fh)

    if secure_name not in baselines:
        return jsonify({"error": f"No baseline found for '{secure_name}'"}), 404

    baseline = baselines[secure_name]
    changed = [
        {"algo": algo, "baseline": baseline[algo], "current": current[algo]}
        for algo in ("md5", "sha1", "sha256", "sha512")
        if current[algo] != baseline[algo]
    ]

    ok = len(changed) == 0
    return jsonify({
        "filename":         secure_name,
        "intact":           ok,
        "status":           "INTACT" if ok else "MODIFIED",
        "changes":          changed,
        "current_hashes":   current,
        "baseline_hashes":  {k: baseline[k] for k in ("md5", "sha1", "sha256", "sha512")},
        "baseline_saved_at": baseline.get("saved_at"),
        "checked_at":       datetime.now().isoformat(),
    })


@app.route("/api/integrity/baselines", methods=["GET"])
def list_baselines():
    """Endpoint: Return all saved baselines."""
    if not os.path.exists(BASELINE_FILE):
        return jsonify({"baselines": {}})
    with open(BASELINE_FILE) as fh:
        return jsonify({"baselines": json.load(fh)})


# ══════════════════════════════════════════════════════════════
# TASK 2 ── WEB VULNERABILITY SCANNER
# ══════════════════════════════════════════════════════════════

# Common SQL injection test payloads
SQL_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "\" OR \"\"=\"", "1; DROP TABLE users--",
]
# SQL error signatures that indicate a vulnerable response
SQL_ERRORS = [
    "mysql_fetch", "ORA-", "SQL syntax", "Warning: mysql",
    "PostgreSQL", "SQLite", "ODBC SQL", "Unclosed quotation",
]
# XSS injection payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]
# Important HTTP security headers
SEC_HEADERS = [
    "X-Frame-Options", "X-XSS-Protection",
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "Referrer-Policy",
    "Permissions-Policy",
]


def _test_forms(url, forms, payloads, check_fn, session):
    """Generic helper: inject payloads into every form field."""
    findings = []
    for form in forms[:4]:
        action = urljoin(url, form.get("action") or url)
        method = form.get("method", "get").lower()
        inputs = form.find_all(["input", "textarea"])
        data = {
            inp.get("name", f"field{i}"): inp.get("value", "test")
            for i, inp in enumerate(inputs)
            if inp.get("name")
        }
        for payload in payloads[:3]:
            payload_data = {k: payload for k in data}
            try:
                fn = session.post if method == "post" else session.get
                resp = fn(action, **({"data": payload_data} if method == "post"
                                     else {"params": payload_data}), timeout=6)
                result = check_fn(resp, payload, action)
                if result:
                    findings.append(result)
                    break
            except Exception:
                pass
    return findings


def _check_sqli(resp, payload, action):
    for err in SQL_ERRORS:
        if err.lower() in resp.text.lower():
            return {"type": "SQL Injection", "severity": "HIGH",
                    "form": action, "payload": payload, "evidence": err}
    return None


def _check_xss(resp, payload, action):
    if payload in resp.text:
        return {"type": "Cross-Site Scripting (XSS)", "severity": "HIGH",
                "form": action, "payload": payload}
    return None


def check_headers(resp):
    missing, present = [], []
    for h in SEC_HEADERS:
        val = resp.headers.get(h)
        (present if val else missing).append({"header": h, "value": val or ""})
    return missing, present


def check_ssl(url):
    parsed = urlparse(url)
    info = {"has_ssl": parsed.scheme == "https", "issues": [], "version": None}
    if parsed.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as ss:
                    info["version"] = ss.version()
                    info["cipher"]  = ss.cipher()[0]
        except Exception as e:
            info["issues"].append(str(e))
    else:
        info["issues"].append("No HTTPS — data sent in plaintext")
    return info


@app.route("/api/scan", methods=["POST"])
def vuln_scan():
    """Endpoint: Scan a URL for common web vulnerabilities."""
    body = request.get_json(force=True)
    url  = body.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed_url = urlparse(url)
    if not is_safe_target(parsed_url.hostname):
        return jsonify({"error": "Scanning internal or reserved IP addresses is not permitted for security reasons."}), 403

    result = {
        "url": url, "scan_time": datetime.now().isoformat(),
        "vulnerabilities": [], "headers": {}, "ssl": {}, "info": [],
    }

    try:
        sess = http_requests.Session()
        sess.headers["User-Agent"] = "CyberGuard-Pro/1.0 (Authorized Security Scanner)"
        resp = sess.get(url, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        result["info"] = [
            f"Status: {resp.status_code}",
            f"Server: {resp.headers.get('Server', 'Unknown')}",
            f"Content-Type: {resp.headers.get('Content-Type', 'Unknown')}",
            f"Forms found: {len(forms)}",
            f"Links found: {len(soup.find_all('a'))}",
        ]

        missing, present = check_headers(resp)
        result["headers"] = {"missing": missing, "present": present}
        result["ssl"]     = check_ssl(url)

        if forms:
            result["vulnerabilities"] += _test_forms(url, forms, SQL_PAYLOADS, _check_sqli, sess)
            result["vulnerabilities"] += _test_forms(url, forms, XSS_PAYLOADS, _check_xss, sess)

        # Probe for common exposed paths
        for path in ["/admin", "/.env", "/config", "/backup", "/phpinfo.php", "/wp-admin"]:
            try:
                r = sess.get(urljoin(url, path), timeout=3)
                if r.status_code == 200:
                    result["vulnerabilities"].append({
                        "type": "Exposed Sensitive Path",
                        "severity": "MEDIUM",
                        "path": path,
                        "status_code": r.status_code,
                    })
            except Exception:
                pass

        high = sum(1 for v in result["vulnerabilities"] if v.get("severity") == "HIGH")
        med  = sum(1 for v in result["vulnerabilities"] if v.get("severity") == "MEDIUM") + len(missing)
        result["risk"]    = "HIGH" if high else ("MEDIUM" if med > 2 else "LOW")
        result["summary"] = {"total": len(result["vulnerabilities"]),
                             "high": high, "medium": med, "missing_headers": len(missing)}

    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)


# ══════════════════════════════════════════════════════════════
# TASK 3 ── PENETRATION TESTING TOOLKIT
# ══════════════════════════════════════════════════════════════

# Well-known port → service mapping
WELL_KNOWN = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def _scan_port(host, port, timeout=1.0):
    """Try to connect to host:port; return metadata if open."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            # Attempt a quick banner grab
            banner = ""
            try:
                s.settimeout(1.5)
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = s.recv(512)
                banner = raw.decode("utf-8", errors="ignore").split("\r\n")[0][:120]
            except Exception:
                pass
            return {"port": port, "state": "open",
                    "service": WELL_KNOWN.get(port, "unknown"), "banner": banner}
    except Exception:
        return None


@app.route("/api/portscan", methods=["POST"])
def port_scan():
    """Endpoint: Threaded port scanner against a target host."""
    body  = request.get_json(force=True)
    host  = body.get("host", "").strip()
    mode  = body.get("mode", "common")   # common | top200

    if not host:
        return jsonify({"error": "Host required"}), 400

    if not is_safe_target(host):
        return jsonify({"error": "Scanning internal or reserved IP addresses is not permitted for security reasons."}), 403

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return jsonify({"error": f"Cannot resolve: {host}"}), 400

    ports = list(WELL_KNOWN.keys()) if mode == "common" else list(range(1, 201))
    open_ports = []
    t0 = time.time()

    # Use up to 100 threads for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        futs = {ex.submit(_scan_port, ip, p): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r:
                open_ports.append(r)

    open_ports.sort(key=lambda x: x["port"])

    return jsonify({
        "host": host, "ip": ip,
        "ports_scanned": len(ports),
        "open_ports":    open_ports,
        "total_open":    len(open_ports),
        "duration_s":    round(time.time() - t0, 2),
        "scan_time":     datetime.now().isoformat(),
    })


@app.route("/api/dns", methods=["POST"])
def dns_lookup():
    """Endpoint: DNS resolution for a domain."""
    domain = request.get_json(force=True).get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain required"}), 400

    result = {"domain": domain, "records": {}, "all_ips": []}
    try:
        result["records"]["A"] = socket.gethostbyname(domain)
        all_info = socket.getaddrinfo(domain, None)
        result["all_ips"] = list({a[4][0] for a in all_info})
        try:
            result["records"]["PTR"] = socket.gethostbyaddr(result["records"]["A"])[0]
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)


@app.route("/api/ping", methods=["POST"])
def ping():
    """Endpoint: Reachability check with latency estimate."""
    host = request.get_json(force=True).get("host", "").strip()
    if not host:
        return jsonify({"error": "Host required"}), 400

    if not is_safe_target(host):
        return jsonify({"error": "Pinging internal or reserved IP addresses is not permitted for security reasons."}), 403

    try:
        ip = socket.gethostbyname(host)
        t0 = time.time()
        with socket.create_connection((ip, 80), timeout=3):
            pass
        return jsonify({"host": host, "ip": ip, "reachable": True,
                        "latency_ms": round((time.time() - t0) * 1000, 2)})
    except Exception as e:
        return jsonify({"host": host, "reachable": False, "error": str(e)})


# ══════════════════════════════════════════════════════════════
# TASK 4 ── ADVANCED ENCRYPTION TOOL (AES-256-CBC + PBKDF2)
# ══════════════════════════════════════════════════════════════

MAGIC = b"CYBRGUARD"   # File signature so we can detect our encrypted format


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # 256 bits
        salt=salt,
        iterations=120_000,  # OWASP recommended minimum (2023)
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def aes_encrypt(data: bytes, password: str) -> bytes:
    """
    Encrypt bytes with AES-256-CBC.
    Output layout: MAGIC(9) | SALT(16) | IV(16) | CIPHERTEXT
    """
    salt = os.urandom(16)
    iv   = os.urandom(16)
    key  = _derive_key(password, salt)

    padder    = padding.PKCS7(128).padder()
    padded    = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv),
                       backend=default_backend()).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return MAGIC + salt + iv + ciphertext


def aes_decrypt(blob: bytes, password: str) -> bytes:
    """Decrypt an AES-256-CBC blob produced by aes_encrypt()."""
    if not blob.startswith(MAGIC):
        raise ValueError("Not a CyberGuard encrypted file (bad magic bytes)")

    offset = len(MAGIC)
    salt       = blob[offset     : offset + 16]
    iv         = blob[offset + 16: offset + 32]
    ciphertext = blob[offset + 32:]
    key        = _derive_key(password, salt)

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv),
                       backend=default_backend()).decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder  = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


@app.route("/api/encrypt", methods=["POST"])
def encrypt_file():
    """Endpoint: Encrypt an uploaded file with AES-256."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    password = request.form.get("password", "")
    if not password:
        return jsonify({"error": "Password required"}), 400

    f    = request.files["file"]
    data = f.read()

    try:
        encrypted = aes_encrypt(data, password)
        secure_name = secure_filename(f.filename)
        return send_file(
            io.BytesIO(encrypted),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=secure_name + ".enc",
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/decrypt", methods=["POST"])
def decrypt_file():
    """Endpoint: Decrypt an AES-256 encrypted file."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    password = request.form.get("password", "")
    if not password:
        return jsonify({"error": "Password required"}), 400

    f    = request.files["file"]
    blob = f.read()
    secure_name = secure_filename(f.filename)
    orig_name = secure_name[:-4] if secure_name.endswith(".enc") else secure_name

    try:
        plain = aes_decrypt(blob, password)
        return send_file(
            io.BytesIO(plain),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name="decrypted_" + orig_name,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "Decryption failed — wrong password or corrupted file"}), 400


# ══════════════════════════════════════════════════════════════
# NEW FEATURES (SUBDOMAINS & GEOIP)
# ══════════════════════════════════════════════════════════════

@app.route("/api/subdomains", methods=["POST"])
def subdomains_enum():
    """Endpoint: Basic subdomain enumeration."""
    domain = request.get_json(force=True).get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    
    # Common subdomains wordlist
    wordlist = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "js", "api", "support", "billing"]
    
    found = []
    def check_sub(sub):
        target = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(target)
            return {"subdomain": target, "ip": ip}
        except Exception:
            return None

    # Use thread pool to speed up resolution
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(check_sub, sub) for sub in wordlist]
        for f in concurrent.futures.as_completed(futs):
            res = f.result()
            if res:
                found.append(res)
                
    return jsonify({"domain": domain, "found": found, "total": len(found)})


@app.route("/api/geoip", methods=["POST"])
def geo_ip():
    """Endpoint: IP Geolocation using ip-api.com"""
    target = request.get_json(force=True).get("target", "").strip()
    if not target:
        return jsonify({"error": "Target IP/Domain required"}), 400
        
    try:
        if not is_safe_target(target):
            return jsonify({"error": "Geolocation of internal addresses is not permitted."}), 403
            
        ip = socket.gethostbyname(target)
        r = http_requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        if data.get("status") == "success":
            return jsonify({
                "target": target,
                "ip": ip,
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            })
        else:
            return jsonify({"error": "Geolocation failed looking up IP."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════
# SERVE FRONTEND
# ══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    with open(os.path.join(os.path.dirname(__file__), "templates", "index.html")) as fh:
        return fh.read()


# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════╗
║       CyberGuard Pro  ·  v1.0.0         ║
║  CodTech Cybersecurity Internship Suite ║
╚══════════════════════════════════════════╝
  ➜  http://localhost:5000
""")
    app.run(debug=False, port=5000)
