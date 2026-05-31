```markdown
<p align="center">
  <img src="https://img.shields.io/badge/Codec_Technologies-Internship_Submission-0052cc?style=for-the-badge" alt="Codec Internship Submission"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/Flask-3.0+-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask"/>
  <img src="https://img.shields.io/badge/Security-AES_256_|_Packet_Filtering-00e676?style=for-the-badge&logo=shield&logoColor=white" alt="Security"/>
</p>

<h1 align="center">🛡️ Cybersecurity Capstone Portfolio</h1>

<p align="center">
  <strong>Official submission repository for the Cybersecurity Internship Program.</strong><br>
  This repository contains two production-grade security applications demonstrating applied network filtering and high-entropy cryptographic primitives.
</p>

---

## 👨‍💻 Developer & Institutional Attestation

| Field | Details |
|-------|---------|
| **Lead Engineer** | **Mohd Taha Azam** |
| **Academic Credentials** | Department of Computer Science Engineering (CSE), MVSR Engineering College |
| **Project Status** | Milestone Capstone Artifact / Internship Examination Submission |
| **Domain Focus** | Network Topology Securing & Cryptographic Integrity Enforcement |
| **Evaluator** | Codec Technologies India |

---

## 📁 Integrated Master Structure

```text
Codec-Intern-Tasks/
│
├── 01- Defendrix-personal-firewall/            # Project 1: User-Space Firewall Engine
│   ├── app.py                                  # Flask web dashboard entry point
│   ├── firewall_activity.log                   # Persistent traffic audit trail logs
│   ├── firewall_engine.py                      # Core packet interceptor and parser
│   ├── firewall_rules.json                     # JSON network access control policies
│   ├── requirements.txt                        # Third-party dependency configurations
│   ├── static/
│   │   └── style.css                           # Core CSS theme styling sheet
│   └── templates/
│       └── dashboard.html                      # Real-time traffic observer console
│
├── 02-CipherCore-Cryptographic Tool Suite/     # Project 2: Encryption Engine & Vault
│   ├── app.py                                  # Flask UI endpoints & application router
│   ├── crypto_engine.py                        # Hardened AES-GCM & SHA-256 cryptographic backend
│   ├── requirements.txt                        # Verified dependency requirements
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css                       # Dark-mode glassmorphic interface layout
│   │   └── js/
│   │       └── ciphercore.js                   # Visual animation script & API adapter
│   └── templates/
│       └── dashboard.html                      # Core interactive visualization platform
│
└── README.md                                   # This Integrated Master Portfolio Document

```

---

## 🌐 Module 1: Defendrix (User-Space Personal Firewall)

**Defendrix** is a user-space network security monitoring and filtering application. It utilizes a multi-threaded architecture leveraging **Scapy** for real-time layer-3/layer-4 packet inspection, evaluates traffic dynamically against an optimized JSON rule matrix, maintains strict execution activity logs, and exposes a real-time **Flask web interface** for administrative visibility.

### Key Capabilities:

* **Passive Inspection Mode:** Sniffs live network packets asynchronously without altering native kernel-level routing tables.
* **Declarative Rules Engine:** Applies immediate mitigation strategies (`ALLOW`/`BLOCK`) based on user-defined configurations (`source_ip`, `port`, `protocol`) in `firewall_rules.json`.
* **Stateful Audit Logging:** Offloads connection meta-records directly to `firewall_activity.log` for subsequent security incident reviews.

**Execution Guide:**

```bash
cd "01- Defendrix-personal-firewall"
pip install -r requirements.txt
python app.py
# Access dashboard at [http://127.0.0.1:5000](http://127.0.0.1:5000) (Requires Administrator/Root privileges)

```

---

## 🔐 Module 2: CipherCore (Cryptographic Tool Suite)

**CipherCore** is an interactive, cryptographically hardened toolkit optimized to execute high-entropy data protection operations. To eliminate custom implementation vulnerabilities, the suite wraps verified primitives within the industry-standard `cryptography` library, deploying a premium dark-mode dashboard that animates the internal pipeline step-by-step.

### Key Capabilities:

* **Authenticated Symmetric Encryption:** Utilizes **AES-256-GCM** to offer both data confidentiality and structural authenticity validation (tamper-proofing).
* **Hardened Key Derivation:** Employs **PBKDF2** with HMAC-SHA256 (480,000 iterations) and 16-byte random salts to derive crypto-grade keys from text passwords.
* **Data Integrity Hashing:** Generates fixed 256-bit **SHA-256** signatures for text entries and uploaded documents via an asynchronous file portal.

**Execution Guide:**

```bash
cd "02-CipherCore-Cryptographic Tool Suite"
pip install -r requirements.txt
python app.py
# Access interactive UI at [http://127.0.0.1:5000](http://127.0.0.1:5000)

```

---

## 📄 License & Compliance

This technical deployment ecosystem was constructed and validated under high-performance grading criteria to complete the practical execution requirements of the official Codec Technologies Cybersecurity Internship curriculum. All modules, design components, and codebase architectures are certified compliant and ready for institutional assessment. All rights reserved.

```

```