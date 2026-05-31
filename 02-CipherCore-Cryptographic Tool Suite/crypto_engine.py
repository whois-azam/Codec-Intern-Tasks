"""
CipherCore — Cryptographic Engine Module
==========================================

Self-contained cryptographic operations module powering the CipherCore tool suite.
All cryptographic primitives are sourced exclusively from the ``cryptography`` library
(PBKDF2, AES-256-GCM) and Python's ``hashlib`` (SHA-256).

Every public function returns a structured ``dict`` and never raises uncaught
exceptions, making it safe to call directly from Flask route handlers.

Author : CipherCore Team
Version: 1.0.0
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Any, Dict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_DEFAULT_ITERATIONS: int = 480_000
_KEY_LENGTH: int = 32          # 256 bits
_SALT_LENGTH: int = 16         # 128 bits
_IV_LENGTH: int = 12           # 96  bits  (recommended for GCM)
_TAG_LENGTH: int = 16          # 128 bits  (GCM authentication tag)
_ALGORITHM_NAME: str = "AES-256-GCM"


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _b64e(data: bytes) -> str:
    """Return the standard Base-64 encoding of *data* as a UTF-8 string."""
    return base64.b64encode(data).decode("utf-8")


def _b64d(data: str) -> bytes:
    """Decode a standard Base-64 encoded string back into raw bytes."""
    return base64.b64decode(data)


# ---------------------------------------------------------------------------
# Key Derivation
# ---------------------------------------------------------------------------

def derive_key(
    password: str,
    salt: bytes,
    iterations: int = _DEFAULT_ITERATIONS,
) -> bytes:
    """Derive a 256-bit cryptographic key from a password using PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    password : str
        The user-supplied password (will be UTF-8 encoded internally).
    salt : bytes
        A random salt (should be at least 16 bytes for security).
    iterations : int, optional
        The number of PBKDF2 iterations.  Defaults to 480 000, which aligns
        with OWASP 2023 recommendations for HMAC-SHA256.

    Returns
    -------
    bytes
        A 32-byte (256-bit) derived key suitable for AES-256.

    Notes
    -----
    The function delegates to ``cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC``
    to ensure a constant-time, side-channel-resistant implementation.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# AES-256-GCM Encryption
# ---------------------------------------------------------------------------

def encrypt_aes_gcm(plaintext: str, password: str) -> Dict[str, Any]:
    """Encrypt *plaintext* with AES-256-GCM using a password-derived key.

    Workflow
    --------
    1. Generate a 16-byte cryptographic salt via ``os.urandom``.
    2. Derive a 256-bit key with :func:`derive_key` (PBKDF2-HMAC-SHA256).
    3. Generate a 12-byte random initialisation vector (IV / nonce).
    4. Encrypt with ``AESGCM``, which returns ``ciphertext || tag`` (the
       16-byte GCM authentication tag is appended to the ciphertext).
    5. Split the combined output into separate *ciphertext* and *tag* fields.

    Parameters
    ----------
    plaintext : str
        The message to encrypt (UTF-8).
    password : str
        The user-supplied password used for key derivation.

    Returns
    -------
    dict
        On success the dict contains:

        - **salt** (str): Base-64 encoded salt.
        - **iv** (str): Base-64 encoded IV.
        - **ciphertext** (str): Base-64 encoded ciphertext (without tag).
        - **tag** (str): Base-64 encoded 16-byte GCM authentication tag.
        - **iterations** (int): PBKDF2 iteration count used.
        - **algorithm** (str): ``"AES-256-GCM"``.
        - **key_hex** (str): Hex representation of the derived key (for
          educational / visualisation purposes only — never store this).
        - **pipeline** (list[dict]): Step-by-step breakdown for the
          frontend animation.

        On failure the dict contains ``success=False`` and an ``error`` message.
    """
    try:
        # ------------------------------------------------------------------
        # Step 1 — Salt generation
        # ------------------------------------------------------------------
        salt: bytes = os.urandom(_SALT_LENGTH)
        salt_b64: str = _b64e(salt)

        # ------------------------------------------------------------------
        # Step 2 — Key derivation (PBKDF2-HMAC-SHA256)
        # ------------------------------------------------------------------
        key: bytes = derive_key(password, salt, _DEFAULT_ITERATIONS)
        key_hex: str = key.hex()

        # ------------------------------------------------------------------
        # Step 3 — IV / nonce generation
        # ------------------------------------------------------------------
        iv: bytes = os.urandom(_IV_LENGTH)
        iv_b64: str = _b64e(iv)

        # ------------------------------------------------------------------
        # Step 4 — AES-256-GCM encryption
        # ------------------------------------------------------------------
        aesgcm = AESGCM(key)
        # AESGCM.encrypt returns  ciphertext_bytes || tag_bytes  (tag is last 16 bytes)
        combined: bytes = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)

        # ------------------------------------------------------------------
        # Step 5 — Split ciphertext and authentication tag
        # ------------------------------------------------------------------
        ciphertext_raw: bytes = combined[:-_TAG_LENGTH]
        tag_raw: bytes = combined[-_TAG_LENGTH:]

        ciphertext_b64: str = _b64e(ciphertext_raw)
        tag_b64: str = _b64e(tag_raw)

        # ------------------------------------------------------------------
        # Build the step-by-step pipeline for frontend animation
        # ------------------------------------------------------------------
        pipeline = [
            {
                "step": "salt_generation",
                "label": "Salt Generation",
                "value": salt_b64,
                "description": "Generated 16-byte cryptographic salt",
            },
            {
                "step": "key_derivation",
                "label": "PBKDF2 Key Stretching",
                "value": key_hex,
                "description": f"{_DEFAULT_ITERATIONS:,} iterations of HMAC-SHA256",
                "iterations": _DEFAULT_ITERATIONS,
            },
            {
                "step": "iv_generation",
                "label": "IV Generation",
                "value": iv_b64,
                "description": "Generated 12-byte initialization vector",
            },
            {
                "step": "encryption",
                "label": "AES-256-GCM Encryption",
                "value": ciphertext_b64,
                "description": "Plaintext encrypted with derived key",
            },
            {
                "step": "tag_generation",
                "label": "Authentication Tag",
                "value": tag_b64,
                "description": "16-byte GCM authentication tag generated",
            },
        ]

        return {
            "salt": salt_b64,
            "iv": iv_b64,
            "ciphertext": ciphertext_b64,
            "tag": tag_b64,
            "iterations": _DEFAULT_ITERATIONS,
            "algorithm": _ALGORITHM_NAME,
            "key_hex": key_hex,
            "pipeline": pipeline,
        }

    except Exception as exc:  # pragma: no cover — safety net
        return {
            "success": False,
            "error": f"Encryption failed: {exc}",
            "error_type": "encryption_error",
        }


# ---------------------------------------------------------------------------
# AES-256-GCM Decryption
# ---------------------------------------------------------------------------

def decrypt_aes_gcm(enc_data: Dict[str, Any], password: str) -> Dict[str, Any]:
    """Decrypt an AES-256-GCM encrypted payload using a password.

    Parameters
    ----------
    enc_data : dict
        Must contain the following keys (all strings are Base-64 encoded):

        - **salt** (str)
        - **iv** (str)
        - **ciphertext** (str)
        - **tag** (str)
        - **iterations** (int)
    password : str
        The password used during encryption.

    Returns
    -------
    dict
        On success::

            {
                "success": True,
                "plaintext": "<decrypted text>",
                "pipeline": [...]
            }

        On authentication failure (wrong password / tampered data)::

            {
                "success": False,
                "error": "Authentication failed — the password is incorrect or "
                         "the data has been tampered with.",
                "error_type": "tag_mismatch"
            }

        On any other error::

            {
                "success": False,
                "error": "<error description>",
                "error_type": "decryption_error"
            }
    """
    try:
        # ------------------------------------------------------------------
        # Decode all Base-64 fields
        # ------------------------------------------------------------------
        salt: bytes = _b64d(enc_data["salt"])
        iv: bytes = _b64d(enc_data["iv"])
        ciphertext: bytes = _b64d(enc_data["ciphertext"])
        tag: bytes = _b64d(enc_data["tag"])
        iterations: int = int(enc_data["iterations"])

        # ------------------------------------------------------------------
        # Key derivation (must mirror the encryption parameters exactly)
        # ------------------------------------------------------------------
        key: bytes = derive_key(password, salt, iterations)
        key_hex: str = key.hex()

        # ------------------------------------------------------------------
        # Reconstruct combined bytes: ciphertext || tag
        # ------------------------------------------------------------------
        combined: bytes = ciphertext + tag

        # ------------------------------------------------------------------
        # AES-256-GCM decryption + authentication
        # ------------------------------------------------------------------
        aesgcm = AESGCM(key)
        plaintext_bytes: bytes = aesgcm.decrypt(iv, combined, None)
        plaintext: str = plaintext_bytes.decode("utf-8")

        # ------------------------------------------------------------------
        # Pipeline (successful decryption)
        # ------------------------------------------------------------------
        pipeline = [
            {
                "step": "key_derivation",
                "label": "PBKDF2 Key Derivation",
                "value": key_hex,
                "description": f"Derived key using {iterations:,} iterations of HMAC-SHA256",
                "iterations": iterations,
            },
            {
                "step": "tag_verification",
                "label": "GCM Tag Verification",
                "value": "PASS",
                "description": "Authentication tag verified — data integrity confirmed",
                "status": "pass",
            },
            {
                "step": "decryption",
                "label": "AES-256-GCM Decryption",
                "value": plaintext,
                "description": "Ciphertext successfully decrypted to plaintext",
            },
        ]

        return {
            "success": True,
            "plaintext": plaintext,
            "pipeline": pipeline,
        }

    except InvalidTag:
        # The GCM tag did not verify — wrong password or tampered data.
        return {
            "success": False,
            "error": (
                "Authentication failed — the password is incorrect or "
                "the data has been tampered with."
            ),
            "error_type": "tag_mismatch",
            "pipeline": [
                {
                    "step": "key_derivation",
                    "label": "PBKDF2 Key Derivation",
                    "value": "derived",
                    "description": "Key derived from provided password",
                },
                {
                    "step": "tag_verification",
                    "label": "GCM Tag Verification",
                    "value": "FAIL",
                    "description": "Authentication tag mismatch — wrong password or tampered data",
                    "status": "fail",
                },
            ],
        }

    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "error_type": "decryption_error",
        }


# ---------------------------------------------------------------------------
# SHA-256 Hashing — Text
# ---------------------------------------------------------------------------

def hash_text_sha256(text: str) -> Dict[str, Any]:
    """Compute the SHA-256 digest of a UTF-8 text string.

    Parameters
    ----------
    text : str
        The input text to hash.

    Returns
    -------
    dict
        Contains:

        - **hash** (str): The hexadecimal digest (64 hex characters).
        - **algorithm** (str): ``"SHA-256"``.
        - **input_length** (int): Number of characters in the input.
        - **hash_length** (int): Bit-length of the digest (always 256).
    """
    try:
        digest: str = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return {
            "hash": digest,
            "algorithm": "SHA-256",
            "input_length": len(text),
            "hash_length": 256,
        }
    except Exception as exc:  # pragma: no cover
        return {
            "success": False,
            "error": f"Hashing failed: {exc}",
            "error_type": "hash_error",
        }


# ---------------------------------------------------------------------------
# SHA-256 Hashing — File
# ---------------------------------------------------------------------------

def hash_file_sha256(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Compute the SHA-256 digest of raw file bytes.

    Parameters
    ----------
    file_bytes : bytes
        The raw binary content of the uploaded file.
    filename : str
        The original filename (included in the response for reference).

    Returns
    -------
    dict
        Contains:

        - **hash** (str): The hexadecimal digest (64 hex characters).
        - **algorithm** (str): ``"SHA-256"``.
        - **filename** (str): Original filename.
        - **file_size** (int): Size of the file in bytes.
        - **hash_length** (int): Bit-length of the digest (always 256).
    """
    try:
        digest: str = hashlib.sha256(file_bytes).hexdigest()
        return {
            "hash": digest,
            "algorithm": "SHA-256",
            "filename": filename,
            "file_size": len(file_bytes),
            "hash_length": 256,
        }
    except Exception as exc:  # pragma: no cover
        return {
            "success": False,
            "error": f"File hashing failed: {exc}",
            "error_type": "hash_error",
        }
