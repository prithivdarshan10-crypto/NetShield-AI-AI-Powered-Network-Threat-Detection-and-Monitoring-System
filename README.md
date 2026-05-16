# 🛡️ NetShield AI
### AI-Powered Network Threat Detection and Monitoring System

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4+-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> A professional-grade, AI-driven network security dashboard that simulates real-time threat detection — similar in concept to Cisco's network monitoring platforms. Built as a final-year engineering project with a futuristic cybersecurity UI.

---

## 📸 Dashboard Preview

```
┌─────────────────────────────────────────────────────────────────┐
│  🛡 NETSHIELD AI    AI-Powered Network Threat Detection         │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────┤
│ PACKETS  │ THREATS  │  DDoS    │PORT SCAN │SUSPICIOUS│HIGH/CRIT│
│  1,240   │   312    │   128    │   84     │   100    │   64    │
├──────────┴──────────┴──────────┴──────────┴──────────┴─────────┤
│  [THREAT GAUGE]      [LIVE TRAFFIC TIMELINE ────────────────]  │
├─────────────────────────────┬───────────────────────────────────┤
│  PROTOCOL DISTRIBUTION 🔌   │  THREAT CLASSIFICATION ⚠️         │
│     ╭──────╮               │   DDoS       ████████████  128    │
│     │  TCP │ 60%           │   PortScan   ████████      84     │
│     │  UDP │ 30%           │   Suspicious ██████████    100    │
│     │ ICMP │ 10%           │   Normal     ████████████  928    │
├─────────────────────────────┴───────────────────────────────────┤
│  PACKET LENGTH HISTOGRAM    │  FREQ vs LENGTH SCATTER           │
├─────────────────────────────┴───────────────────────────────────┤
│  TOP ATTACKING IPs 🎯        │  🚨 SUSPICIOUS IP TABLE           │
│  10.0.0.20  ████████  128   │  IP            Type     Sev  Cnt  │
│  172.16.0.1 ██████    84    │  10.0.0.20     DDoS     High  128 │
├─────────────────────────────┴───────────────────────────────────┤
│  ALERT LOG                                                       │
│  [12:34:01] 🔴 DDoS ATTACK detected from 10.0.0.20 → 192.168.1.1│
│  [12:34:02] 🟠 PORT SCAN activity from 172.16.0.1 targeting ...  │
├─────────────────────────────────────────────────────────────────┤
│  ⬇ Download Threat Report (CSV)                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

| Feature | Details |
|---|---|
| 🤖 **AI Classification** | Random Forest model classifies traffic into Normal / DDoS / Port Scan / Suspicious |
| 📡 **Live Packet Capture** | Scapy-based capture (root required); auto-falls back to demo traffic |
| 📊 **Real-Time Dashboard** | Auto-refreshing Plotly charts with configurable interval |
| 🚨 **Alert Engine** | Severity-labelled alerts (Low / Medium / High / Critical) |
| 🎯 **Threat Intelligence** | Top attacker IPs, suspicious IP table, protocol distribution |
| 📦 **Export** | One-click downloadable CSV threat report |
| 🎨 **Futuristic UI** | Dark cyberpunk theme with Share Tech Mono / Rajdhani fonts |

---

## 🗂️ Project Structure

```
NetShieldAI/
├── app.py               ← Main Streamlit dashboard (entry point)
├── train_model.py       ← Model training & saving pipeline
├── packet_capture.py    ← Scapy capture + demo traffic generator
├── dashboard.py         ← All Plotly chart functions
├── alerts.py            ← Severity assignment & alert engine
├── sample_dataset.csv   ← Labelled training dataset (64 rows)
├── requirements.txt     ← Python dependencies
├── README.md            ← This file
└── model/               ← Auto-created on first run
    ├── netshield_model.pkl
    └── label_encoder.pkl
```

---

## 🚀 Quick Start

### 1 · Clone the repository
```bash
git clone https://github.com/yourusername/NetShieldAI.git
cd NetShieldAI
```

### 2 · Create a virtual environment (recommended)
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 3 · Install dependencies
```bash
pip install -r requirements.txt
```

### 4 · Train the model (one-time setup)
```bash
python train_model.py
```
Expected output:
```
✓ Loaded dataset: 64 rows, 4 classes
✓ Test Accuracy: 100.00%
✓ Model saved → model/netshield_model.pkl
```

### 5 · Launch the dashboard
```bash
streamlit run app.py
```
Open your browser at **http://localhost:8501**

---

## 🔴 Live Packet Capture (Optional)

By default the app runs in **demo mode** (synthetic traffic). To enable live capture:

1. Check the **"Try live capture"** box in the sidebar.
2. Run Streamlit with elevated privileges:
```bash
sudo streamlit run app.py
```
> ⚠️ Live capture requires a compatible network interface and root/admin access.
> On Windows, install [Npcap](https://npcap.com) first.

---

## 🧠 ML Model Details

| Attribute | Value |
|---|---|
| Algorithm | Random Forest Classifier |
| Estimators | 200 trees |
| Max depth | 10 |
| Features | src_ip_enc, dst_ip_enc, protocol_enc, packet_length, traffic_freq |
| Labels | Normal, DDoS, PortScan, Suspicious |
| Train/Test split | 75% / 25% |

### Feature Engineering
- IP addresses → deterministic hash modulo 10,000
- Protocol strings → integer map (TCP=0, UDP=1, ICMP=2, OTHER=3)
- Packet length & traffic frequency → used as-is (numeric)

---

## 📊 Severity Levels

| Label | Base Severity | Escalation |
|---|---|---|
| Normal | — | — |
| Suspicious | Medium | — |
| PortScan | Medium | — |
| DDoS | High | Critical if freq ≥ 1000 |

---

## 🛠️ Tech Stack

- **Python 3.11+**
- **Streamlit** – web dashboard framework
- **Scikit-learn** – Random Forest classifier
- **Scapy** – packet capture
- **Plotly** – interactive charts
- **Pandas / NumPy** – data processing
- **Joblib** – model persistence

---

## 📈 Extending the Project

- Replace the demo dataset with real PCAP exports (e.g. from Wireshark).
- Add a database (SQLite / PostgreSQL) to persist packet history across sessions.
- Integrate email/Slack webhook notifications for Critical alerts.
- Add an Isolation Forest anomaly detector alongside the Random Forest.
- Deploy to a cloud VM and point Scapy at a real network interface.

---

## 👨‍💻 Author

PRIYADARSHAN S V · Third Year B.Tech. AIML
*Project submitted for SRM INSTITUTE OF SCIENCE AND TECHNOLOGY , Academic Year 2026*

---

## 📄 License

MIT © 2025 – Free to use for academic and personal projects.
