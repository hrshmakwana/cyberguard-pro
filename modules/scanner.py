import ssl
import socket
from datetime import datetime
from urllib.parse import urljoin, urlparse
import requests as http_requests
from bs4 import BeautifulSoup
from flask import Blueprint, request, jsonify
from modules.utils import is_safe_target
from config import (
    SQL_PAYLOADS, SQL_ERRORS, XSS_PAYLOADS,
    SECURITY_HEADERS_CHECK, SENSITIVE_PATHS,
    USER_AGENT, SCAN_TIMEOUT, PROBE_TIMEOUT,
)
scanner_bp = Blueprint("scanner", __name__)
def _test_forms(url, forms, payloads, check_fn, session):
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
                resp = fn(action, **({
                    "data": payload_data
                } if method == "post" else {
                    "params": payload_data
                }), timeout=6)
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
            return {
                "type": "SQL Injection", "severity": "HIGH",
                "form": action, "payload": payload, "evidence": err,
            }
    return None
def _check_xss(resp, payload, action):
    if payload in resp.text:
        return {
            "type": "Cross-Site Scripting (XSS)", "severity": "HIGH",
            "form": action, "payload": payload,
        }
    return None
def check_headers(resp):
    missing, present = [], []
    for h in SECURITY_HEADERS_CHECK:
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
                    info["cipher"] = ss.cipher()[0]
        except Exception as e:
            info["issues"].append(str(e))
    else:
        info["issues"].append("No HTTPS — data sent in plaintext")
    return info
@scanner_bp.route("/api/scan", methods=["POST"])
def vuln_scan():
    body = request.get_json(force=True)
    url = body.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed_url = urlparse(url)
    if not is_safe_target(parsed_url.hostname):
        return jsonify({
            "error": "Scanning internal or reserved IP addresses is not permitted for security reasons."
        }), 403
    result = {
        "url": url, "scan_time": datetime.now().isoformat(),
        "vulnerabilities": [], "headers": {}, "ssl": {}, "info": [],
    }
    try:
        sess = http_requests.Session()
        sess.headers["User-Agent"] = USER_AGENT
        resp = sess.get(url, timeout=SCAN_TIMEOUT, allow_redirects=True)
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
        result["ssl"] = check_ssl(url)
        if forms:
            result["vulnerabilities"] += _test_forms(url, forms, SQL_PAYLOADS, _check_sqli, sess)
            result["vulnerabilities"] += _test_forms(url, forms, XSS_PAYLOADS, _check_xss, sess)
        for path in SENSITIVE_PATHS:
            try:
                r = sess.get(urljoin(url, path), timeout=PROBE_TIMEOUT)
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
        med = sum(1 for v in result["vulnerabilities"] if v.get("severity") == "MEDIUM") + len(missing)
        result["risk"] = "HIGH" if high else ("MEDIUM" if med > 2 else "LOW")
        result["summary"] = {
            "total": len(result["vulnerabilities"]),
            "high": high, "medium": med, "missing_headers": len(missing),
        }
    except Exception as e:
        result["error"] = str(e)
    return jsonify(result)
