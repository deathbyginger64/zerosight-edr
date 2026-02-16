# 🛡️ ZeroSight — Behavioral EDR Platform

**ZeroSight demonstrates how behavioral monitoring can detect unknown threats
by analyzing process activity patterns instead of relying on static signatures.**

ZeroSight is a lightweight Endpoint Detection and Response (EDR) system that detects anomalous process behavior without relying on malware signatures.

---

## 🎥 Demo

Run the system locally to view the live SOC dashboard.

---

## 🚀 Key Features

* Real-time process telemetry monitoring
* Behavioral risk scoring engine
* Zero-day candidate detection
* Interactive SOC dashboard
* Manual process isolation
* Incident logging

---

## 📂 Project Structure

```
zerosight-edr/
│
├── frontend/
│   └── app.py                  # Streamlit SOC dashboard
│
├── attack_simulator.py         # Behavior simulation
├── zerosight_collector.py      # Telemetry collection
├── zerosight_risk_engine.py    # Risk scoring engine
│
├── requirements.txt
└── .gitignore

```

---

## ⚙️ How to Run

```
git clone https://github.com/deathbyginger64/zerosight-edr.git
cd zerosight-edr
pip install -r requirements.txt
python zerosight_collector.py
python zerosight_risk_engine.py
streamlit run frontend/app.py
```

---

## 🧪 Tech Stack

Python • Streamlit • SQLite • psutil • Plotly

---

## 👨‍💻 Author

Aditya Khandelwal
