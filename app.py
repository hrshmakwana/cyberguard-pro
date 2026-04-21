import os
import io
from flask import Flask, request, jsonify, send_file
from config import (
    MAX_CONTENT_LENGTH, SECURITY_HEADERS as SEC_HDRS,
    TEMPLATE_DIR, STATIC_DIR,
)
from modules.integrity import integrity_bp
from modules.scanner import scanner_bp
from modules.recon import recon_bp
from modules.encryption import encryption_bp
from reports.pdf_generator import (
    generate_integrity_report,
    generate_scan_report,
    generate_recon_report,
    generate_encryption_report,
)
app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
    static_url_path="/static",
)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
@app.after_request
def apply_caching(response):
    for header, value in SEC_HDRS.items():
        response.headers[header] = value
    return response
app.register_blueprint(integrity_bp)
app.register_blueprint(scanner_bp)
app.register_blueprint(recon_bp)
app.register_blueprint(encryption_bp)
@app.route("/api/report/integrity", methods=["POST"])
def report_integrity():
    data = request.get_json(force=True)
    try:
        pdf_bytes = generate_integrity_report(data)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"CyberGuard_Integrity_Report_{data.get('filename', 'report')}.pdf",
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route("/api/report/scan", methods=["POST"])
def report_scan():
    data = request.get_json(force=True)
    try:
        pdf_bytes = generate_scan_report(data)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name="CyberGuard_VulnScan_Report.pdf",
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route("/api/report/recon", methods=["POST"])
def report_recon():
    data = request.get_json(force=True)
    try:
        pdf_bytes = generate_recon_report(data)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name="CyberGuard_Recon_Report.pdf",
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route("/api/report/encryption", methods=["POST"])
def report_encryption():
    data = request.get_json(force=True)
    try:
        pdf_bytes = generate_encryption_report(data)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"CyberGuard_Encryption_Report.pdf",
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route("/")
def index():
    with open(os.path.join(TEMPLATE_DIR, "index.html")) as fh:
        return fh.read()
if __name__ == "__main__":
    print()
    app.run(debug=False, port=5000)
