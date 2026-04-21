import time
import socket
import concurrent.futures
from datetime import datetime
import requests as http_requests
from flask import Blueprint, request, jsonify
from modules.utils import is_safe_target
from config import (
    WELL_KNOWN_PORTS, PORT_SCAN_THREADS,
    SUBDOMAIN_THREADS, SUBDOMAIN_WORDLIST,
)
recon_bp = Blueprint("recon", __name__)
def _scan_port(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            try:
                s.settimeout(1.5)
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = s.recv(512)
                banner = raw.decode("utf-8", errors="ignore").split("\r\n")[0][:120]
            except Exception:
                pass
            return {
                "port": port, "state": "open",
                "service": WELL_KNOWN_PORTS.get(port, "unknown"),
                "banner": banner,
            }
    except Exception:
        return None
@recon_bp.route("/api/portscan", methods=["POST"])
def port_scan():
    body = request.get_json(force=True)
    host = body.get("host", "").strip()
    mode = body.get("mode", "common")   
    if not host:
        return jsonify({"error": "Host required"}), 400
    if not is_safe_target(host):
        return jsonify({
            "error": "Scanning internal or reserved IP addresses is not permitted for security reasons."
        }), 403
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return jsonify({"error": f"Cannot resolve: {host}"}), 400
    ports = list(WELL_KNOWN_PORTS.keys()) if mode == "common" else list(range(1, 201))
    open_ports = []
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_SCAN_THREADS) as ex:
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
@recon_bp.route("/api/dns", methods=["POST"])
def dns_lookup():
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
@recon_bp.route("/api/ping", methods=["POST"])
def ping():
    host = request.get_json(force=True).get("host", "").strip()
    if not host:
        return jsonify({"error": "Host required"}), 400
    if not is_safe_target(host):
        return jsonify({
            "error": "Pinging internal or reserved IP addresses is not permitted for security reasons."
        }), 403
    try:
        ip = socket.gethostbyname(host)
        t0 = time.time()
        with socket.create_connection((ip, 80), timeout=3):
            pass
        return jsonify({
            "host": host, "ip": ip, "reachable": True,
            "latency_ms": round((time.time() - t0) * 1000, 2),
        })
    except Exception as e:
        return jsonify({"host": host, "reachable": False, "error": str(e)})
@recon_bp.route("/api/subdomains", methods=["POST"])
def subdomains_enum():
    domain = request.get_json(force=True).get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    found = []
    def check_sub(sub):
        target = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(target)
            return {"subdomain": target, "ip": ip}
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=SUBDOMAIN_THREADS) as ex:
        futs = [ex.submit(check_sub, sub) for sub in SUBDOMAIN_WORDLIST]
        for f in concurrent.futures.as_completed(futs):
            res = f.result()
            if res:
                found.append(res)
    return jsonify({"domain": domain, "found": found, "total": len(found)})
@recon_bp.route("/api/geoip", methods=["POST"])
def geo_ip():
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
                "lon": data.get("lon"),
            })
        else:
            return jsonify({"error": "Geolocation failed looking up IP."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
