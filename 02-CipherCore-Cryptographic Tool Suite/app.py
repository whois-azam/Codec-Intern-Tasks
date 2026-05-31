"""
CipherCore — Flask Application Server
=======================================

RESTful API server for the CipherCore Cryptographic Tool Suite.  Exposes
endpoints for AES-256-GCM encryption/decryption and SHA-256 hashing of
both text and files.

Endpoints
---------
GET  /               → Serve the dashboard UI
POST /api/encrypt    → Encrypt plaintext with AES-256-GCM
POST /api/decrypt    → Decrypt AES-256-GCM ciphertext
POST /api/hash/text  → SHA-256 hash of a text string
POST /api/hash/file  → SHA-256 hash of an uploaded file

All JSON responses follow a uniform envelope:
    { "success": true|false, "data": {...} | "error": "..." }

Author : CipherCore Team
Version: 1.0.0
"""

from __future__ import annotations

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

from crypto_engine import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    hash_text_sha256,
    hash_file_sha256,
)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = Flask(__name__)
CORS(app)  # Enable cross-origin requests for frontend consumption


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Serve the main CipherCore dashboard.

    Returns the ``dashboard.html`` template located in the default
    Flask ``templates/`` directory.
    """
    return render_template("dashboard.html")


# ---- Encryption ----------------------------------------------------------

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """Encrypt plaintext using AES-256-GCM with a password-derived key.

    **Request** (``application/json``)::

        {
            "plaintext": "secret message",
            "password":  "strong-passphrase"
        }

    **Response 200**::

        {
            "success": true,
            "data": {
                "salt": "...",
                "iv":   "...",
                "ciphertext": "...",
                "tag":  "...",
                "iterations": 480000,
                "algorithm": "AES-256-GCM",
                "key_hex": "...",
                "pipeline": [...]
            }
        }

    **Response 400** — missing or empty fields.
    **Response 500** — unexpected server error.
    """
    try:
        # ------------------------------------------------------------------
        # Parse & validate JSON body
        # ------------------------------------------------------------------
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "error": "Request body must be valid JSON."}), 400

        plaintext: str | None = data.get("plaintext")
        password: str | None = data.get("password")

        if not plaintext or not isinstance(plaintext, str) or not plaintext.strip():
            return jsonify({"success": False, "error": "Field 'plaintext' is required and must be a non-empty string."}), 400

        if not password or not isinstance(password, str) or not password.strip():
            return jsonify({"success": False, "error": "Field 'password' is required and must be a non-empty string."}), 400

        # ------------------------------------------------------------------
        # Perform encryption
        # ------------------------------------------------------------------
        result = encrypt_aes_gcm(plaintext, password)

        # If the crypto engine itself reported a failure, surface it
        if result.get("success") is False:
            return jsonify(result), 500

        return jsonify({"success": True, "data": result}), 200

    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


# ---- Decryption ----------------------------------------------------------

@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    """Decrypt an AES-256-GCM ciphertext using the original password.

    **Request** (``application/json``)::

        {
            "ciphertext":  "<base64>",
            "iv":          "<base64>",
            "salt":        "<base64>",
            "tag":         "<base64>",
            "password":    "strong-passphrase",
            "iterations":  480000
        }

    **Response 200**::

        {
            "success": true,
            "plaintext": "secret message",
            "pipeline": [...]
        }

    **Response 200 (auth failure)**::

        {
            "success": false,
            "error": "Authentication failed ...",
            "error_type": "tag_mismatch"
        }

    **Response 400** — missing fields.
    **Response 500** — unexpected server error.
    """
    try:
        # ------------------------------------------------------------------
        # Parse & validate JSON body
        # ------------------------------------------------------------------
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "error": "Request body must be valid JSON."}), 400

        required_fields = ("ciphertext", "iv", "salt", "tag", "password", "iterations")
        missing = [f for f in required_fields if f not in data or data[f] is None]
        if missing:
            return jsonify({
                "success": False,
                "error": f"Missing required field(s): {', '.join(missing)}",
            }), 400

        # ------------------------------------------------------------------
        # Build the enc_data dict expected by the crypto engine
        # ------------------------------------------------------------------
        enc_data = {
            "salt": data["salt"],
            "iv": data["iv"],
            "ciphertext": data["ciphertext"],
            "tag": data["tag"],
            "iterations": data["iterations"],
        }

        # ------------------------------------------------------------------
        # Perform decryption
        # ------------------------------------------------------------------
        result = decrypt_aes_gcm(enc_data, data["password"])

        # Return directly — the result dict already contains success/error fields.
        return jsonify(result), 200

    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


# ---- Text Hashing --------------------------------------------------------

@app.route("/api/hash/text", methods=["POST"])
def api_hash_text():
    """Compute the SHA-256 hash of a text string.

    **Request** (``application/json``)::

        { "text": "hello world" }

    **Response 200**::

        {
            "success": true,
            "data": {
                "hash": "b94d27b9934d3e08...",
                "algorithm": "SHA-256",
                "input_length": 11,
                "hash_length": 256
            }
        }

    **Response 400** — missing or empty ``text`` field.
    **Response 500** — unexpected server error.
    """
    try:
        # ------------------------------------------------------------------
        # Parse & validate
        # ------------------------------------------------------------------
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "error": "Request body must be valid JSON."}), 400

        text: str | None = data.get("text")
        if not text or not isinstance(text, str) or not text.strip():
            return jsonify({"success": False, "error": "Field 'text' is required and must be a non-empty string."}), 400

        # ------------------------------------------------------------------
        # Hash
        # ------------------------------------------------------------------
        result = hash_text_sha256(text)

        if result.get("success") is False:
            return jsonify(result), 500

        return jsonify({"success": True, "data": result}), 200

    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


# ---- File Hashing --------------------------------------------------------

@app.route("/api/hash/file", methods=["POST"])
def api_hash_file():
    """Compute the SHA-256 hash of an uploaded file.

    **Request** (``multipart/form-data``)::

        file: <binary file upload>

    **Response 200**::

        {
            "success": true,
            "data": {
                "hash": "e3b0c44298fc1c14...",
                "algorithm": "SHA-256",
                "filename": "document.pdf",
                "file_size": 204800,
                "hash_length": 256
            }
        }

    **Response 400** — no file attached.
    **Response 500** — unexpected server error.
    """
    try:
        # ------------------------------------------------------------------
        # Validate the uploaded file
        # ------------------------------------------------------------------
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file uploaded. Use form field name 'file'."}), 400

        uploaded_file = request.files["file"]

        if uploaded_file.filename == "" or uploaded_file.filename is None:
            return jsonify({"success": False, "error": "Uploaded file has no filename."}), 400

        # ------------------------------------------------------------------
        # Read bytes and compute hash
        # ------------------------------------------------------------------
        file_bytes: bytes = uploaded_file.read()
        filename: str = uploaded_file.filename

        result = hash_file_sha256(file_bytes, filename)

        if result.get("success") is False:
            return jsonify(result), 500

        return jsonify({"success": True, "data": result}), 200

    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # -- Startup banner ----------------------------------------------------
    print()
    print("╔══════════════════════════════════════════════╗")
    print("║          CipherCore v1.0 — Active           ║")
    print("║   http://127.0.0.1:5000                     ║")
    print("║   Cryptographic Tool Suite Ready            ║")
    print("╚══════════════════════════════════════════════╝")
    print()

    # -- Launch the development server -------------------------------------
    app.run(debug=True, host="127.0.0.1", port=5000)
