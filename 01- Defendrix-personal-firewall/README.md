## 🛡️ Defendrix: User-Space Packet Filtering & Network Shield
 A professional-grade, user-space **Personal Firewall** application built in Python.  
It uses **Scapy** to sniff live network traffic, evaluates packets against a custom JSON rule set, logs every decision, and exposes a real-time **Flask web dashboard** for monitoring.

## 👨‍💻 Developer & Institutional Attestation

* **Lead Engineer:** Mohd Taha Azam
* **Project Status:** Milestone Capstone Artifact / Internship Examination Submission
* **Target Focus:** Network Topology Securing & Cryptographic Integrity Enforcement



---

## 📁 Project Structure

```
01-personal-firewall/
├── app.py                  # Flask web dashboard entry point
├── firewall_engine.py      # Core Scapy sniffer, rules engine, logger
├── firewall_rules.json     # JSON configuration for firewall rules
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── templates/
│   └── dashboard.html      # Real-time dashboard HTML
└── static/
    └── style.css           # Dashboard stylesheet (dark theme)
```

---

## ⚙️ Requirements

| Dependency | Purpose |
|------------|---------|
| **Python 3.10+** | Runtime |
| **Scapy ≥ 2.5** | Live packet capture & protocol parsing |
| **Flask ≥ 3.0** | Localhost web dashboard |
| **Npcap** (Windows) or **libpcap** (Linux/macOS) | Low-level packet capture driver |

### Windows Users
Install **Npcap** from [npcap.com](https://npcap.com/) with the **"WinPcap API-compatible Mode"** checkbox enabled.

---

## 🚀 Installation

```bash
# Clone or download the project
cd 01-personal-firewall

# Install Python dependencies
pip install -r requirements.txt
```

---

## 🔥 Usage

### Mode 1: Standalone Terminal Mode

Runs the firewall engine in the terminal with colored output. Press `Ctrl+C` to stop and see the session report.

```bash
# Windows (run as Administrator)
python firewall_engine.py

# Linux / macOS
sudo python3 firewall_engine.py
```

### Mode 2: Web Dashboard Mode (Recommended)

Launches the Flask web server on `http://127.0.0.1:5000` and runs the Scapy sniffer in a background thread.

```bash
# Windows (run as Administrator)
python app.py

# Linux / macOS
sudo python3 app.py
```

Then open your browser to **http://127.0.0.1:5000** to see the live dashboard.

> ⚠️ **Administrator / root privileges** are required for packet capture.

---

## 📋 Configuring Rules

Edit `firewall_rules.json` to customize the firewall behavior:

```json
{
    "firewall_rules": {
        "default_policy": "ALLOW",
        "blocked_source_ips": ["10.0.0.100"],
        "blocked_destination_ports": [23, 8080, 31337],
        "blocked_protocols": ["ICMP"],
        "rules": [
            {
                "id": 1,
                "name": "Block Telnet",
                "type": "port",
                "value": 23,
                "action": "BLOCK",
                "enabled": true
            }
        ]
    }
}
```

### Rule Types

| Type | Description | Example Value |
|------|-------------|---------------|
| `source_ip` | Block traffic from a specific source IP | `"10.0.0.100"` |
| `port` | Block traffic to a specific destination port | `23` |
| `protocol` | Block all traffic of a specific protocol | `"ICMP"` |

---

## 📊 Dashboard Features

- **Real-time Metrics** — Packets Scanned, Allowed, Blocked, Packets/sec
- **Live Activity Log** — Auto-refreshing table with color-coded ALLOW/BLOCK rows
- **Active Rules Panel** — Displays all loaded rules from the JSON config
- **Status Indicator** — Online/Offline dot with uptime counter
- **Responsive Design** — Works on desktop, tablet, and mobile

---

## 📝 Log File Format

All activity is also logged to `firewall_activity.log`:

```
==========================================================================================
  FIREWALL SESSION STARTED — 2026-05-31 04:00:00 UTC
==========================================================================================
[2026-05-31 04:00:01] [ACTION: ALLOW] PROTO: TCP | SRC: 192.168.1.5:49231 -> DST: 142.250.80.46:443
[2026-05-31 04:00:02] [ACTION: BLOCK] PROTO: ICMP | SRC: 10.0.0.100 -> DST: 192.168.1.5 | REASON: Protocol ICMP is blocked
```

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Flask Web Server                    │
│           (localhost:5000, main thread)               │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ /         │  │ /api/    │  │ /api/logs        │   │
│  │ Dashboard │  │ metrics  │  │ /api/rules       │   │
│  └──────────┘  └──────────┘  └──────────────────┘   │
└──────────────────────┬───────────────────────────────┘
                       │ reads from
        ┌──────────────▼──────────────────┐
        │      FirewallEngine (shared)     │
        │  ┌────────────────────────────┐ │
        │  │ Metrics   │  Log Buffer    │ │
        │  │ total     │  [entry, ...]  │ │
        │  │ allowed   │                │ │
        │  │ blocked   │                │ │
        │  └────────────────────────────┘ │
        └──────────────┬──────────────────┘
                       │ callback
        ┌──────────────▼──────────────────┐
        │    Scapy Sniffer (daemon thread) │
        │    sniff(prn=..., filter="ip")   │
        │    ┌──────────────────────────┐  │
        │    │ parse_packet()           │  │
        │    │ FirewallRules.evaluate() │  │
        │    │ FirewallLogger.log()     │  │
        │    └──────────────────────────┘  │
        └─────────────────────────────────┘
```

---
> **Note:** This is a *user-space simulator* — it sniffs and analyzes live packets but does not modify kernel-level firewall tables (which would require kernel drivers). The "BLOCK" action represents what a full kernel firewall would do; the packet is logged and classified accordingly. 

## 📄 License
This project has been developed and submitted by Mohd Taha Azam to satisfy the capstone technical execution parameters required for the official Cybersecurity Internship Program curriculum evaluation. All source assets, technical logic configurations, and implementations are verified compliant with program standards.
This project is submitted as part of an internship program. All rights reserved.
