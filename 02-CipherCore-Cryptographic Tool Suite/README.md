<p align="center">
  <img src="https://img.shields.io/badge/CipherCore-v1.0-00e5ff?style=for-the-badge&logo=lock&logoColor=white" alt="CipherCore v1.0"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/Flask-3.0+-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask 3.0+"/>
  <img src="https://img.shields.io/badge/AES--256--GCM-Encrypted-00e676?style=for-the-badge&logo=gnuprivacyguard&logoColor=white" alt="AES-256-GCM"/>
</p>

<h1 align="center">🔐 CipherCore — Cryptographic Tool Suite</h1>

<p align="center">
  <strong>A production-grade cryptographic tool suite combining a secure Python backend with a stunning, animated web dashboard for real-time visualization of encryption, decryption, and hashing operations.</strong>
</p>

---

## 👨‍💻 Developer & Project Metadata

| Field | Details |
|-------|---------|
| **Lead Engineer** | **Mohd Taha Azam** |
| **Project Tier** | Milestone Capstone Artifact / Internship Examination Submission |
| **Domain Focus** | Cryptographic Primitives & High-Entropy Data Protection Mechanics |
| **Version** | 1.0.0 |
| **License** | Academic Use — All Rights Reserved |

---

## 🏗️ Architecture Overview

CipherCore is built on a clean client-server architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                     CipherCore Architecture                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Web Dashboard (Frontend)                │   │
│  │                                                           │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │   │
│  │  │  Encryption  │  │  Decryption   │  │  SHA-256 Hash  │  │   │
│  │  │    Panel     │  │    Panel      │  │    Portal      │  │   │
│  │  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘  │   │
│  │         │                │                   │            │   │
│  │  ┌──────┴────────────────┴───────────────────┴────────┐  │   │
│  │  │        Cryptographic Pipeline Visualizer            │  │   │
│  │  │   (Real-time step-by-step animated data flow)       │  │   │
│  │  └────────────────────────┬───────────────────────────┘  │   │
│  └───────────────────────────┼──────────────────────────────┘   │
│                              │ Async JSON API                    │
│  ┌───────────────────────────┼──────────────────────────────┐   │
│  │                Flask Server (Backend)                      │   │
│  │                                                           │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │              API Endpoints Layer                      │ │   │
│  │  │   /api/encrypt  /api/decrypt  /api/hash/*            │ │   │
│  │  └────────────────────────┬────────────────────────────┘ │   │
│  │                           │                               │   │
│  │  ┌────────────────────────┴────────────────────────────┐ │   │
│  │  │            Cryptographic Engine Module               │ │   │
│  │  │                                                      │ │   │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │ │   │
│  │  │  │ PBKDF2   │  │ AES-256  │  │  SHA-256 Digest  │  │ │   │
│  │  │  │ HMAC-256 │  │   GCM    │  │    (hashlib)     │  │ │   │
│  │  │  └──────────┘  └──────────┘  └──────────────────┘  │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔑 Cryptographic Features

### 1. Symmetric Encryption Engine — AES-256-GCM

| Parameter | Specification |
|-----------|--------------|
| **Algorithm** | AES-256 in Galois/Counter Mode (GCM) |
| **Key Derivation** | PBKDF2 with HMAC-SHA256 |
| **KDF Iterations** | 480,000 (OWASP 2024 recommended) |
| **Salt** | 16-byte cryptographically random (`os.urandom`) |
| **IV / Nonce** | 12-byte cryptographically random (NIST SP 800-38D) |
| **Auth Tag** | 16-byte GCM authentication tag |
| **Encoding** | Base64 for all binary outputs |

**Encryption Pipeline:**
```
Password + Salt ──► PBKDF2 (480K rounds) ──► 256-bit Key
                                                  │
Plaintext + Key + IV ──► AES-256-GCM ──► Ciphertext + Auth Tag
```

**Decryption Pipeline:**
```
Password + Salt ──► PBKDF2 (480K rounds) ──► 256-bit Key
                                                  │
Ciphertext + Key + IV + Tag ──► AES-256-GCM ──► Tag Verify ──► Plaintext
                                                     │
                                              (Fail: InvalidTag Error)
```

### 2. Data Integrity Engine — SHA-256

- Produces fixed 256-bit (64 hex character) cryptographic fingerprints
- Supports both text input and file binary hashing
- Drag-and-drop file interface with real-time hash computation

### 3. Defensive Architecture

- All cryptographic failures return structured error objects (never crash)
- Tag tampering / wrong password → `tag_mismatch` error type with informative message
- Input validation on all API endpoints with descriptive 400-level errors
- No raw exceptions leak to the client

---

## 📁 Project Structure

```
02-CipherCore-Cryptographic Tool Suite/
│
├── app.py                          # Flask web server & API endpoints
├── crypto_engine.py                # Core cryptographic operations module
├── requirements.txt                # Python dependencies
├── README.md                       # This file
│
├── static/
│   ├── css/
│   │   └── style.css               # Dark-mode glassmorphic stylesheet
│   └── js/
│       └── ciphercore.js           # Frontend animation engine & API layer
│
└── templates/
    └── dashboard.html              # Main dashboard HTML template (Jinja2)
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+** (tested on 3.12)
- **pip** package manager

### Installation

```bash
# 1. Navigate to the project directory
cd "02-CipherCore-Cryptographic Tool Suite"

# 2. (Recommended) Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch CipherCore
python app.py
```

### Access the Dashboard

Open your browser and navigate to:

```
http://127.0.0.1:5000
```

You will see the CipherCore dashboard with three operational tabs:
- **🔒 Encrypt** — Enter plaintext and a passphrase to encrypt
- **🔓 Decrypt** — Paste encrypted components to decrypt and verify
- **#️⃣ Hash** — Generate SHA-256 fingerprints for text or files

---

## 📡 API Reference

All endpoints accept and return JSON (except file upload).

### `POST /api/encrypt`

Encrypts plaintext using AES-256-GCM with PBKDF2-derived key.

**Request:**
```json
{
  "plaintext": "Hello, World!",
  "password": "my-secure-passphrase"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "ciphertext": "base64-encoded-ciphertext",
    "iv": "base64-encoded-iv",
    "salt": "base64-encoded-salt",
    "tag": "base64-encoded-tag",
    "iterations": 480000,
    "algorithm": "AES-256-GCM",
    "key_hex": "hex-encoded-derived-key",
    "pipeline": [
      {"step": "salt_generation", "label": "Salt Generation", "value": "...", "description": "..."},
      {"step": "key_derivation", "label": "PBKDF2 Key Stretching", "value": "...", "description": "..."},
      {"step": "iv_generation", "label": "IV Generation", "value": "...", "description": "..."},
      {"step": "encryption", "label": "AES-256-GCM Encryption", "value": "...", "description": "..."},
      {"step": "tag_generation", "label": "Authentication Tag", "value": "...", "description": "..."}
    ]
  }
}
```

### `POST /api/decrypt`

Decrypts ciphertext and verifies authentication tag integrity.

**Request:**
```json
{
  "ciphertext": "base64-encoded",
  "iv": "base64-encoded",
  "salt": "base64-encoded",
  "tag": "base64-encoded",
  "password": "my-secure-passphrase",
  "iterations": 480000
}
```

**Success Response (200):**
```json
{
  "success": true,
  "plaintext": "Hello, World!",
  "pipeline": [...]
}
```

**Failure Response (200 — authentication failed):**
```json
{
  "success": false,
  "error": "Authentication failed: The passphrase is incorrect or the data has been tampered with.",
  "error_type": "tag_mismatch"
}
```

### `POST /api/hash/text`

Computes SHA-256 hash of text input.

**Request:**
```json
{
  "text": "Hello, World!"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "hash": "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
    "algorithm": "SHA-256",
    "input_length": 13,
    "hash_length": 256
  }
}
```

### `POST /api/hash/file`

Computes SHA-256 hash of an uploaded file.

**Request:** `multipart/form-data` with `file` field

**Response (200):**
```json
{
  "success": true,
  "data": {
    "hash": "e3b0c44298fc1c149afbf4c8996fb924...",
    "algorithm": "SHA-256",
    "filename": "document.pdf",
    "file_size": 102400,
    "hash_length": 256
  }
}
```

---

## 🔒 Security Considerations

| Aspect | Implementation |
|--------|----------------|
| **Key Derivation** | PBKDF2 with 480,000 iterations — exceeds OWASP minimum recommendations |
| **Random Number Generation** | `os.urandom()` — cryptographically secure PRNG |
| **Authenticated Encryption** | AES-GCM provides both confidentiality and integrity verification |
| **No Key Storage** | Keys are derived on-the-fly and never persisted to disk |
| **Tag Verification** | GCM authentication tag detects any ciphertext or key tampering |
| **Error Isolation** | Cryptographic exceptions are caught and sanitized before reaching the client |
| **Local Only** | Server binds to `127.0.0.1` — not exposed to network by default |

> ⚠️ **Note:** This is an educational and demonstration tool. For production deployment, additional hardening (HTTPS, rate limiting, input sanitization, CSP headers, etc.) would be required.

---

## 🎨 Frontend Features

- **Dark-Mode Glassmorphic Design** — Premium cybersecurity aesthetic with backdrop blur, glow effects, and gradient accents
- **Real-Time Pipeline Visualizer** — Animated step-by-step flowchart showing data transformation through the cryptographic pipeline
- **Seal Verification Animation** — Visual tag verification with green "Seal Intact" (success) and red "Seal Broken" crack effect (failure)
- **Character-by-Character Hash Reveal** — Hex characters appear one at a time with glow effects
- **Drag-and-Drop File Hashing** — Drop files directly onto the hash portal
- **Copy-to-Clipboard** — One-click copy for all cryptographic output values
- **Responsive Layout** — Adapts seamlessly from mobile to desktop viewports
- **Zero External Dependencies** — Pure CSS animations and vanilla JavaScript

---

## 🛠️ Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend Runtime** | Python 3.10+ |
| **Web Framework** | Flask 3.0+ |
| **Cryptography** | `cryptography` library (pyca) |
| **Hashing** | `hashlib` (Python standard library) |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **Typography** | Google Fonts (Inter, JetBrains Mono) |
| **Design System** | Custom glassmorphic dark-mode CSS |

---

## 📜 License

This project is developed as an academic capstone artifact and internship examination submission. All rights reserved by Mohd Taha Azam.

---

<p align="center">
  <strong>🔐 CipherCore v1.0</strong><br>
  <em>Engineered with precision by Mohd Taha Azam</em><br>
  <sub>Cryptographic Primitives & High-Entropy Data Protection Mechanics</sub>
</p>
