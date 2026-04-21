import io
import os
from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from config import MAGIC_BYTES, PBKDF2_ITERATIONS, AES_KEY_LENGTH, SALT_LENGTH, IV_LENGTH
encryption_bp = Blueprint("encryption", __name__)
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))
def aes_encrypt(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    key = _derive_key(password, salt)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(key), modes.CBC(iv),
        backend=default_backend(),
    ).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return MAGIC_BYTES + salt + iv + ciphertext
def aes_decrypt(blob: bytes, password: str) -> bytes:
    if not blob.startswith(MAGIC_BYTES):
        raise ValueError("Not a CyberGuard encrypted file (bad magic bytes)")
    offset = len(MAGIC_BYTES)
    salt = blob[offset:offset + SALT_LENGTH]
    iv = blob[offset + SALT_LENGTH:offset + SALT_LENGTH + IV_LENGTH]
    ciphertext = blob[offset + SALT_LENGTH + IV_LENGTH:]
    key = _derive_key(password, salt)
    decryptor = Cipher(
        algorithms.AES(key), modes.CBC(iv),
        backend=default_backend(),
    ).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()
@encryption_bp.route("/api/encrypt", methods=["POST"])
def encrypt_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    password = request.form.get("password", "")
    if not password:
        return jsonify({"error": "Password required"}), 400
    f = request.files["file"]
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
@encryption_bp.route("/api/decrypt", methods=["POST"])
def decrypt_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    password = request.form.get("password", "")
    if not password:
        return jsonify({"error": "Password required"}), 400
    f = request.files["file"]
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
