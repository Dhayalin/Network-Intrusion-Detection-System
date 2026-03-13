# 🛡️ Network Intrusion Detection System (NIDS)

A real-time Network Intrusion Detection System built with Python and Flask. Captures and inspects network packets, applies rule-based threat detection, and visualises live traffic through an interactive web dashboard.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📸 Dashboard Preview

The dashboard updates every 2 seconds with live packet data, alert feeds, and traffic charts — no page refresh needed.

---

## ✨ Features

| Feature | Details |
|---|---|
| **Packet Capture** | Raw socket capture via AF_PACKET; parses Ethernet → IP → TCP/UDP/ICMP |
| **Rule-Based Detection** | Port Scan, SYN Flood, ICMP Sweep, UDP Flood, Brute Force |
| **Sliding Window Analysis** | Configurable time-window thresholds per rule with alert suppression |
| **Real-Time Dashboard** | Live packet feed, traffic timeline, protocol distribution, top talkers |
| **Alert Severity** | CRITICAL / HIGH / MEDIUM / LOW with colour-coded feed |
| **Alert Logging** | JSON Lines log at `logs/alerts.jsonl` for offline analysis |
| **Simulation Mode** | Auto-engages when run without root — generates realistic synthetic traffic |

---

## 🏗️ Project Structure

```
nids/
├── app.py                  # Flask entry point & API routes
├── nids_manager.py         # Orchestrator: capture ↔ detection ↔ logging
├── requirements.txt
│
├── core/
│   └── packet_capture.py   # Raw socket capture + packet parser
│
├── rules/
│   └── detection.py        # Rule engine, Alert dataclass, thresholds
│
├── web/
│   ├── templates/
│   │   └── index.html      # Dashboard template
│   └── static/
│       ├── css/style.css
│       └── js/dashboard.js # Chart.js, live polling, table renders
│
└── logs/
    ├── nids.log            # Application log
    └── alerts.jsonl        # Machine-readable alert log
```

---

## 🚀 Getting Started

### 1. Clone & install

```bash
git clone https://github.com/<your-username>/nids.git
cd nids
pip install -r requirements.txt
```

### 2. Run (simulation mode — no root needed)

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

### 3. Run with live capture (Linux, requires root)

```bash
sudo python app.py
```

The app auto-detects whether it has the privileges needed for raw socket capture and falls back to simulation mode if not.

---

## 🔍 Detection Rules

### Port Scan
Fires when a single source IP probes **≥ 10 unique ports** within a 10-second window.  
**Severity: HIGH**

### SYN Flood
Fires when **≥ 50 SYN-only packets** (no ACK) arrive at one destination within 10 seconds.  
**Severity: CRITICAL**

### ICMP Host Sweep
Fires when a source IP sends ICMP echo requests to **≥ 8 distinct hosts** within 10 seconds.  
**Severity: MEDIUM**

### UDP Flood
Fires when **≥ 100 UDP packets** hit one destination within 10 seconds.  
**Severity: HIGH**

### Brute Force (SSH/RDP)
Fires when **≥ 8 connection attempts** reach port 22 or 3389 from the same source within 10 seconds.  
**Severity: HIGH**

All thresholds are easily tunable in `rules/detection.py`.

---

## 🛠️ Tech Stack

- **Python 3.11+** — packet capture, detection engine, REST API
- **Flask 3** — lightweight web server
- **Raw Sockets (AF_PACKET)** — low-level packet capture on Linux
- **Chart.js 4** — traffic timeline & protocol distribution charts
- **HTML/CSS/JS** — single-page dashboard with 2-second polling

---

## 📡 REST API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/dashboard` | Full dashboard snapshot (packets, alerts, stats, charts) |
| `GET /api/alerts` | Last 100 alerts |
| `GET /api/packets` | Last 100 captured packets |
| `GET /api/stats` | Capture & alert counters |

---

## 📌 Notes

- **Root / sudo** is required on Linux for live AF_PACKET capture.  
- On macOS/Windows or without root, **simulation mode** automatically generates realistic traffic including attack scenarios — ideal for demos.
- Alert suppression prevents the same rule/source firing repeatedly within a cooldown window.

---

## 📄 License

MIT License — free to use, modify, and distribute.
