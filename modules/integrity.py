import os
import json
import hashlib
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from config import BASELINE_FILE
integrity_bp = Blueprint("integrity", __name__)
def compute_hashes(file_data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(file_data).hexdigest(),
        "sha1":   hashlib.sha1(file_data).hexdigest(),
        "sha256": hashlib.sha256(file_data).hexdigest(),
        "sha512": hashlib.sha512(file_data).hexdigest(),
    }
@integrity_bp.route("/api/hash", methods=["POST"])
def hash_file():
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
@integrity_bp.route("/api/integrity/save", methods=["POST"])
def save_baseline():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    data = f.read()
    secure_name = secure_filename(f.filename)
    hashes = compute_hashes(data)
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
@integrity_bp.route("/api/integrity/check", methods=["POST"])
def check_integrity():
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
@integrity_bp.route("/api/integrity/baselines", methods=["GET"])
def list_baselines():
    if not os.path.exists(BASELINE_FILE):
        return jsonify({"baselines": {}})
    with open(BASELINE_FILE) as fh:
        return jsonify({"baselines": json.load(fh)})
