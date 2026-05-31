# 🛡️ Cybersecurity Capstone Portfolio

## Official Internship Submission Repository

This repository contains two production-grade cybersecurity applications developed as part of the official internship evaluation program. The projects demonstrate practical implementation of network security monitoring, traffic inspection, encryption systems, authenticated cryptographic operations, and secure application engineering using Python and Flask.

---

# 👨‍💻 Developer & Institutional Information

| Field                  | Details                                                     |
| ---------------------- | ----------------------------------------------------------- |
| **Lead Developer**     | **Mohd Taha Azam**                                          |
| **Project Type**       | Cybersecurity Internship Capstone Portfolio                 |
| **Focus Domains**      | Network Security, Traffic Filtering, Cryptographic Systems  |
| **Organization**       | Codec Technologies India                                    |
| **Submission Purpose** | Internship Practical Examination & Institutional Assessment |

---

# 📁 Repository Structure

```text
Codec-Intern-Tasks/
│
├── 01-Defendrix-Personal-Firewall/
│   ├── app.py
│   ├── firewall_engine.py
│   ├── firewall_rules.json
│   ├── firewall_activity.log
│   ├── requirements.txt
│   ├── static/
│   │   └── style.css
│   └── templates/
│       └── dashboard.html
│
├── 02-CipherCore-Cryptographic-Tool-Suite/
│   ├── app.py
│   ├── crypto_engine.py
│   ├── requirements.txt
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   └── js/
│   │       └── ciphercore.js
│   └── templates/
│       └── dashboard.html
│
└── README.md
```

---

# 🌐 Project 1 — Defendrix Personal Firewall

## Overview

**Defendrix** is a user-space firewall and network monitoring application designed for real-time packet inspection and traffic analysis. The project leverages Python networking libraries to monitor live packets, evaluate traffic against configurable rule sets, and provide a centralized monitoring dashboard through Flask.

The application demonstrates foundational concepts in:

* Packet inspection
* Network traffic filtering
* Rule-based access control
* Security event logging
* Real-time monitoring systems

---

## 🔍 Core Features

### ✅ Real-Time Packet Monitoring

Captures and analyzes live network packets asynchronously using Scapy without modifying native kernel routing behavior.

### ✅ JSON-Based Rule Engine

Applies filtering logic using configurable rule definitions such as:

* Source IP filtering
* Destination port filtering
* Protocol inspection
* Allow/Block decisions

### ✅ Persistent Activity Logging

Maintains structured audit logs inside:

```text
firewall_activity.log
```

for security monitoring and forensic review.

### ✅ Web-Based Dashboard

Provides a Flask-powered administrative dashboard for observing network activity and firewall decisions in real time.

---

## ⚙️ Technologies Used

* Python
* Flask
* Scapy
* HTML/CSS
* JSON Configuration System

---

## 🚀 Execution Instructions

```bash
cd "01-Defendrix-Personal-Firewall"

pip install -r requirements.txt

python app.py
```

Access the dashboard at:

```text
http://127.0.0.1:5000
```

> Note: Administrator/Root privileges may be required for packet sniffing operations.

---

# 🔐 Project 2 — CipherCore Cryptographic Tool Suite

## Overview

**CipherCore** is a cryptographically hardened toolkit designed for secure encryption, hashing, and authenticated data protection operations. The project utilizes industry-standard cryptographic primitives from the Python `cryptography` library to ensure implementation reliability and security integrity.

The platform features an interactive dark-mode dashboard and demonstrates secure software engineering practices in modern cryptography.

---

## 🔒 Core Features

### ✅ AES-256-GCM Encryption

Implements authenticated symmetric encryption using AES-256-GCM to provide:

* Confidentiality
* Integrity validation
* Tamper detection

### ✅ Secure Key Derivation

Uses PBKDF2-HMAC-SHA256 with:

* 480,000 iterations
* Random 16-byte salts

to derive secure encryption keys from passwords.

### ✅ SHA-256 Hash Generation

Supports secure hashing for:

* Text input
* Uploaded files
* Integrity verification workflows

### ✅ Interactive Dashboard

Provides a visually enhanced Flask interface with animated cryptographic workflow visualization.

---

## ⚙️ Technologies Used

* Python
* Flask
* Cryptography Library
* JavaScript
* HTML/CSS

---

## 🚀 Execution Instructions

```bash
cd "02-CipherCore-Cryptographic-Tool-Suite"

pip install -r requirements.txt

python app.py
```

Access the application at:

```text
http://127.0.0.1:5000
```

---

# 🧠 Security Concepts Demonstrated

This repository demonstrates applied understanding of:

* Network packet analysis
* Firewall rule evaluation
* Traffic inspection workflows
* Cryptographic authentication
* Secure key derivation
* AES-GCM encryption
* SHA-256 hashing
* Secure Flask application architecture
* Security logging and monitoring

---

# 📚 Educational & Institutional Purpose

This repository was developed as part of the official cybersecurity internship curriculum under Codec Technologies India. The projects were designed to satisfy practical implementation requirements for institutional evaluation and demonstrate applied cybersecurity engineering skills.

---

# 📄 License

This repository is submitted strictly for academic, educational, and internship evaluation purposes.

All project source code, UI assets, documentation, and architectural designs are reserved under the author's ownership unless otherwise specified.

© Mohd Taha Azam — All Rights Reserved.
