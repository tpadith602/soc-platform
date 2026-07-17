# 🛡️ SOC Platform - AI-Powered Security Operations Center

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Cynuxera/soc-platform/releases)
[![Python](https://img.shields.io/badge/python-3.14-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/Cynuxera/soc-platform/actions)

**A Production-Ready Security Operations Center Platform Built from Scratch**

> *"Rule-Based Detection + Machine Learning (98.48% Accuracy) + Honeypot Services"*

---

## 👥 Team Cynuxera

| Role | Name | Responsibilities | GitHub |
|------|------|------------------|--------|
| **Lead Developer & Architect** | Adith TP | System Architecture, NIDS, ML Pipeline, Dashboard, Cloud Filtering, Deployment | [@adithtp](https://github.com/tpadith602) |
| **Security Data Engineer** | Hebsheeba Beula P | Data Preprocessing, Feature Engineering, Dataset Preparation, Data Pipeline | [@hebsheeba](https://github.com/hebsheeba2003-boop) |
| **Threat Intelligence Engineer** | Tsukholu Ringa | GeoIP Integration, IP Enrichment, Geolocation Mapping, Threat Intel Feeds | [@tsukholu](https://github.com/tsukholuringa-oss) |

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Detection Layers](#detection-layers)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Dashboard](#dashboard)
- [API Reference](#api-reference)
- [Database Schema](#database-schema)
- [Project Structure](#project-structure)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## 🎯 Overview

**SOC Platform** is an enterprise-grade security monitoring solution that combines:

- **Rule-Based NIDS** for real-time packet analysis
- **Machine Learning** (98.48% accuracy) for anomaly detection
- **Honeypot Services** for 100% confidence attacker capture
- **Live Dashboard** with world map visualization
- **Telegram Alerts** for instant notifications

Built to run on standard Ubuntu hardware with **zero licensing cost**, this platform delivers enterprise detection capabilities without the $50,000+/year price tag of traditional SOC solutions.

| Traditional SOC Tool | Estimated Cost | Why It's Limiting |
|----------------------|----------------|-------------------|
| Splunk Enterprise | $150,000+/year | Expensive licensing, complex setup |
| IBM QRadar | $100,000+/year | Requires dedicated hardware + training |
| ArcSight (HP) | $80,000+/year | Complex integration, slow deployment |
| **THIS PLATFORM** | **$0** | **Runs on a standard Ubuntu VM** |

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **🛡️ NIDS Engine** | Real-time packet capture & analysis using Scapy |
| **🧠 ML Detection** | Random Forest classifier with 98.48% accuracy |
| **🍯 Honeypot Services** | SSH (2222), HTTP (8080), FTP (2121) decoys |
| **📊 Live Dashboard** | Flask + SocketIO with auto-refresh (60s) |
| **🗺️ World Map** | Attack origin visualization with Leaflet.js |
| **📱 Telegram Alerts** | Instant CRITICAL/HIGH severity notifications |
| **🌍 GeoIP Enrichment** | MaxMind GeoLite2-City integration |
| **☁️ Cloud Filter** | 95+ CIDRs, 9 providers (Google, AWS, Azure, etc.) |
| **💾 SQLite Database** | WAL mode, thread-local connections |
| **🔄 Systemd Service** | Auto-start & auto-restart on crash |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SOC PLATFORM ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                     INGESTION LAYER                                   │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│  │  │   NIDS       │  │  SSH Monitor │  │   Honeypot   │              │   │
│  │  │   (Scapy)    │  │  (auth.log)  │  │  (3 Services)│              │   │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │   │
│  │         │                 │                 │                        │   │
│  │         └─────────────────┼─────────────────┘                        │   │
│  │                           ▼                                          │   │
│  │              ┌─────────────────────────────┐                        │   │
│  │              │   IP Attribution & Filter   │                        │   │
│  │              └──────────────┬──────────────┘                        │   │
│  └─────────────────────────────┼────────────────────────────────────────┘   │
│                                │                                            │
│  ┌─────────────────────────────▼────────────────────────────────────────┐   │
│  │                      ML PIPELINE                                     │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │  Random Forest Classifier (98.48% Accuracy)                │  │   │
│  │  │  - 4 Classes: BENIGN, PortScan, FTP-Patator, SSH-Patator  │  │   │
│  │  │  - 5 Features: dst_port, duration, packets, bytes, rate   │  │   │
│  │  │  - 100 Decision Trees, Max Depth 15                       │  │   │
│  │  │  - Balanced Class Weights                                 │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────┬──────────────────────────────────────┘   │
│                                │                                            │
│  ┌─────────────────────────────▼──────────────────────────────────────┐   │
│  │                      STORAGE LAYER                                  │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │  SQLite Database (WAL Mode) - 23 Column Alerts Table       │  │   │
│  │  │  - Thread-local connections                                │  │   │
│  │  │  - Indexes: timestamp, source_ip, severity                │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────┬──────────────────────────────────────┘   │
│                                │                                            │
│  ┌─────────────────────────────▼──────────────────────────────────────┐   │
│  │                      PRESENTATION LAYER                             │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │  Flask Dashboard (Port 5001) + REST API                    │  │   │
│  │  │  - SocketIO real-time push                                 │  │   │
│  │  │  - Leaflet.js world map                                   │  │   │
│  │  │  - Auto-refresh (60s)                                     │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      DAEMON MANAGEMENT (Systemd)                     │   │
│  │  - Unified Launcher with RLock Watchdog                             │   │
│  │  - 4 Independent Processes (Isolated Failures)                     │   │
│  │  - Auto-restart on crash (≤3 seconds)                             │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔍 Detection Layers

### Layer 1: Rule-Based NIDS

| Attack Type | Detection Method | Threshold | Severity | Confidence |
|-------------|------------------|-----------|----------|------------|
| **Port Scan** | Distinct ports per IP | ≥10 ports / 60s | MEDIUM | 88% |
| **DDoS/Flood** | TCP connections per IP | ≥80 connections / 60s | HIGH | 92% |

### Layer 2: Machine Learning (98.48% Accuracy)

| Property | Value |
|----------|-------|
| **Algorithm** | Random Forest Classifier |
| **Training Data** | CICIDS2017 (15,171 samples, 4 classes) |
| **Features** | destination_port, duration (μs), packet_count, byte_count, connection_rate |
| **Estimators** | 100 decision trees |
| **Max Depth** | 15 levels |
| **Min Confidence** | 60% |
| **Inference Rate** | Every 15 packets per IP (after first 10) |

### Layer 3: Honeypot Services (100% Confidence)

| Service | Port | Severity | Why 100%? |
|---------|------|----------|-----------|
| **SSH** | 2222 | HIGH | No legitimate reason to connect |
| **HTTP** | 8080 | HIGH | Decoy service |
| **HTTP (/admin, /.env)** | 8080 | CRITICAL | Targeted exploitation attempt |
| **FTP** | 2121 | CRITICAL | Credential capture |

---

## 🛠️ Technology Stack

| Category | Technology | Version | Purpose |
|----------|------------|---------|---------|
| **Language** | Python | 3.14 | All components |
| **Packet Capture** | Scapy | ≥2.5.0 | Raw packet sniffing |
| **Machine Learning** | scikit-learn | ≥1.3.0 | Random Forest training |
| **ML Data** | pandas + numpy | ≥2.0 / ≥1.24 | Dataset processing |
| **Model Persistence** | joblib | ≥1.3.0 | Save/load .pkl files |
| **Web Framework** | Flask | ≥3.0.0 | REST API & HTML |
| **WebSocket** | Flask-SocketIO | ≥5.3.4 | Real-time dashboard push |
| **CORS** | Flask-CORS | ≥4.0.0 | Cross-origin policy |
| **Database** | SQLite | Built-in | WAL mode, thread-local |
| **Map Rendering** | Leaflet.js | 1.9.4 | Dark CartoDB attack map |
| **GeoIP** | geoip2 + MaxMind | ≥4.8.0 | Country/city/lat/lon lookup |
| **Notifications** | Telegram Bot API | REST | Push alerts |
| **Process Manager** | systemd | - | Service lifecycle |
| **Capabilities** | setcap | - | Raw socket access without root |
| **OS** | Ubuntu | 22/24 LTS | Tested on VMware |

---

## 📥 Installation

### Prerequisites

- Ubuntu 22.04 LTS or 24.04 LTS
- Python 3.14+
- 2 vCPUs, 4GB RAM (minimum)
- 10GB+ disk space

### Step-by-Step Setup

```bash
# 1. Clone the repository
git clone https://github.com/Cynuxera/soc-platform.git
cd soc-platform

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Setup NIDS permissions
sudo setcap cap_net_raw,cap_net_admin=eip venv/bin/python

# 5. Train ML model
python3 scripts/train_model.py

# 6. Install systemd service
sudo cp systemd/soc-platform.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable soc-platform
sudo systemctl start soc-platform

# 7. Get API key
sudo cat storage/api_key

# 8. Access dashboard
# Open: http://localhost:5001
```

---

## 🚀 Quick Start

```bash
# Start all services
./start.sh

# Stop all services
./stop.sh

# Check status
./status.sh

# View logs
sudo journalctl -u soc-platform -f

# Access dashboard
# http://localhost:5001
```

---

## 📊 Dashboard

The dashboard provides:

- **Stats Row:** Total alerts, Critical, High, Medium
- **World Map:** Attack origins with GeoIP data
- **Honeypot Activity:** Per-service hit counts
- **Recent Alerts:** Time, IP, Type, Severity, Status
- **Attack Timeline:** 24-hour attack patterns

### API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/` | No | Dashboard HTML |
| `GET` | `/api/alerts` | Yes | Alert list |
| `GET` | `/api/summary` | Yes | Alert summary |
| `GET` | `/api/honeypot` | Yes | Honeypot stats |
| `GET` | `/api/geo` | Yes | GeoIP data |
| `POST` | `/api/alerts/{id}/ack` | Yes | Acknowledge alert |
| `POST` | `/api/alerts/{id}/status` | Yes | Update status |

---

## 🗄️ Database Schema

### Table: `alerts` (23 Columns)

| Column | Type | Description |
|--------|------|-------------|
| `alert_id` | TEXT (PK) | Unique alert identifier |
| `timestamp` | TEXT | Alert timestamp |
| `source_ip` | TEXT | Attacker's IP |
| `destination_ip` | TEXT | Target IP / 'honeypot' |
| `destination_port` | INTEGER | Port targeted |
| `protocol` | TEXT | TCP/UDP/ICMP/OTHER |
| `severity` | TEXT | CRITICAL/HIGH/MEDIUM/LOW |
| `confidence` | REAL | 0.0-1.0 detection confidence |
| `explanation` | TEXT | Human-readable description |
| `country` | TEXT | GeoIP country |
| `city` | TEXT | GeoIP city |
| `region` | TEXT | GeoIP region |
| `isp` | TEXT | Internet Service Provider |
| `asn` | TEXT | Autonomous System Number |
| `is_anonymized` | INTEGER | VPN/Proxy flag (0/1) |
| `ip_category` | TEXT | Public/Private/Loopback |
| `status` | TEXT | new/acknowledged/investigating/closed/false_positive |
| `acknowledged_by` | TEXT | Who acknowledged |
| `comments` | TEXT | Analyst notes |
| `packet_info` | TEXT | Raw packet summary |
| `attack_type` | TEXT | PortScan/DDoS/SSH-BruteForce/Honeypot-X |
| `source_component` | TEXT | nids/ml_engine/honeypot/ssh_monitor |
| `detection_method` | TEXT | rule/ml/honeypot |

---

## 📁 Project Structure

```
soc-platform/
├── config/
│   └── settings.py          # Main configuration
├── daemon/
│   └── launcher.py          # Unified launcher (RLock watchdog)
├── ingestion/
│   ├── nids_engine.py       # NIDS engine (Scapy)
│   ├── database.py          # Thread-local SQLite
│   ├── honeypot.py          # SSH/HTTP/FTP decoys
│   ├── ml_inference.py      # ML model loader
│   └── flow_features.py     # Per-IP traffic profiles
├── pipeline/
│   ├── ip_utils.py          # Local IP detection
│   ├── cloud_filter.py      # 95+ CIDRs, 9 providers
│   ├── geoip.py             # MaxMind GeoIP lookup
│   └── telegram_notifier.py # Async Telegram alerts
├── scripts/
│   ├── train_model.py       # ML training script
│   ├── phase3_ingestion.py  # SSH auth.log monitor
│   └── clear_alerts.py      # Alert cleanup
├── web/
│   ├── app.py               # Flask dashboard
│   └── templates/
│       └── index.html       # Dashboard HTML
├── data/
│   ├── processed_dataset.csv    # CICIDS2017 dataset
│   └── GeoLite2-City.mmdb      # MaxMind GeoIP (optional)
├── storage/
│   └── soc_enriched_matrix.db   # SQLite database
├── logs/                        # Application logs
├── model/                       # ML models
├── systemd/                     # Systemd service file
├── start.sh                     # Start script
├── stop.sh                      # Stop script
├── status.sh                    # Status script
└── requirements.txt              # Python dependencies
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **CICIDS2017 Dataset** - Canadian Institute for Cybersecurity
- **MaxMind** - GeoLite2-City database
- **Scapy** - Packet manipulation library
- **scikit-learn** - Machine learning framework
- **Flask** - Web framework
- **Leaflet.js** - Interactive maps
- **Telegram Bot API** - Instant notifications

---

## 📞 Support

For issues, questions, or contributions:

- **Issues:** [GitHub Issues](https://github.com/Cynuxera/soc-platform/issues)
- **Email:** security@cynuxera.com

---

## ⭐ Star Us!

If you find this project useful, please give us a star on GitHub!

---

**Built with ❤️ by the Cynuxera Team**

*"Securing the future, one alert at a time."*
