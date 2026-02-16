import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import os, time
from datetime import datetime, timedelta

# --------------------------------------------------
# PATHS & DB
# --------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
DB_PATH = os.path.join(BASE_DIR, "zerosight.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn

# --------------------------------------------------
# TABLES & LOGS
# --------------------------------------------------
def init_quarantine_table():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS quarantine_log (
        timestamp TEXT,
        pid INTEGER,
        action TEXT
    )
    """)
    conn.commit()
    conn.close()

def log_quarantine(pid):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO quarantine_log VALUES (?,?,?)
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), pid, "ISOLATED"))
    conn.commit()
    conn.close()

def load_latest_risks():
    try:
        conn = get_conn()
        df = pd.read_sql_query("SELECT * FROM latest_risks", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def load_incidents():
    try:
        conn = get_conn()
        df = pd.read_sql_query("SELECT * FROM incident_logs", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def load_heartbeat():
    try:
        conn = get_conn()
        df = pd.read_sql_query("SELECT * FROM system_heartbeat", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def load_quarantine_log():
    try:
        conn = get_conn()
        df = pd.read_sql_query("SELECT * FROM quarantine_log", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def isolate_process(pid):
    try:
        os.kill(int(pid), 9)
        log_quarantine(pid)
        return True
    except:
        return False

# --------------------------------------------------
# STREAMLIT CONFIG & THEME
# --------------------------------------------------
st.set_page_config(page_title="ZeroSight SOC", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp {
    background-color: #0d1117;
    color: #c9d1d9;
}

/* ======= TOP BAR ======= */
.top-row {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr;
    gap: 12px;
    margin-bottom: 12px;
}

.panel {
    background:#161b22;
    padding:14px;
    border-radius:8px;
    border:1px solid #30363d;
}

/* Tables */
.stDataFrame {
    border: 1px solid #30363d;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)

# =============== INIT =================
init_quarantine_table()

# =============== LOAD DATA =================
df = load_latest_risks()
hb = load_heartbeat()
incidents = load_incidents()
quarantine_log = load_quarantine_log()

# ---- ZERO DAY COUNT (SAFE CHECK) ----
zero_day_count = 0
if not df.empty and "attack_label" in df.columns:
    zero_day_count = len(df[df["attack_label"] == "ZERO-DAY CANDIDATE"])

# ---- HEARTBEAT STATUS (REAL LIVE) ----
statuses = dict(zip(hb["component"], hb["status"])) if not hb.empty else {}
last_seen = dict(zip(hb["component"], hb["last_seen"])) if not hb.empty else {}

coll_status = statuses.get("collector", "STOPPED")
risk_status = statuses.get("risk_engine", "STOPPED")

coll_color = "#7ee787" if coll_status == "RUNNING" else "#f85149"
risk_color = "#7ee787" if risk_status == "RUNNING" else "#f85149"

# =============== LIVE CLOCK =================
current_time = datetime.now().strftime("%H:%M:%S")

# =============== HEADER =================
live_mode = st.toggle("🔄 Live Telemetry", value=True)

st.markdown(f"""
<div class="top-row">

<div class="panel">
<h3 style="margin:0;">🛡️ ZeroSight — Behavioral SOC</h3>
</div>

<div class="panel" style="text-align:center;">
<b>Clock</b><br>
<span style="font-size:18px;">{current_time}</span>
</div>

<div class="panel" style="text-align:center;">
<b>Mode</b><br>
<span style="color:{'#7ee787' if live_mode else '#f85149'}; font-size:16px;">
● {'LIVE' if live_mode else 'PAUSED'}
</span>
</div>

</div>
""", unsafe_allow_html=True)

# =============== COMPONENT STATUS =================
st.markdown(f"""
<div style="display:flex; gap:20px; margin-bottom:15px;">
<div>COLLECTOR: <span style="color:{coll_color}">●</span> {coll_status}</div>
<div>RISK ENGINE: <span style="color:{risk_color}">●</span> {risk_status}</div>
<div style="margin-left:auto;">LAST UPDATE: {current_time}</div>
</div>
""", unsafe_allow_html=True)

# =============== SECURITY POSTURE =================
posture_color = "#f85149" if zero_day_count > 0 else "#7ee787"

st.markdown(f"""
<div style="background:#161b22; padding:16px; border-radius:10px; border-left:6px solid {posture_color}; margin-bottom:15px;">
<b>Security Posture:</b>
<span style="color:{posture_color}; font-size:18px;">
{'🚨 ZERO-DAY CANDIDATE DETECTED' if zero_day_count>0 else '🟢 SYSTEM NOMINAL'}
</span>
&nbsp;&nbsp;|&nbsp;&nbsp;
<b>{zero_day_count}</b> zero-day candidates flagged
</div>
""", unsafe_allow_html=True)

# =============== TABS =================
tab_monitor, tab_history, tab_intel, tab_quarantine, tab_about = st.tabs(
["📡 TELEMETRY", "📜 FORENSICS", "📈 ANALYTICS", "🛑 QUARANTINE LOG", "ℹ️ ABOUT"]
)

# =====================================================
# TAB 1 — TELEMETRY
# =====================================================
with tab_monitor:
    if not df.empty:

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Active PIDs", len(df))
        m2.metric("Mean Risk", f"{df['risk_score'].mean():.1f}")
        m3.metric("CPU Load", f"{df['cpu'].mean():.1f}%")
        m4.metric("ZERO-DAY Count", zero_day_count)

        st.subheader("Live Process Risk Perimeter")

        st.dataframe(
            df.sort_values("risk_score", ascending=False),
            use_container_width=True,
            hide_index=True,
            height=550
        )

        with st.expander("⚡ COMMAND TERMINAL: PROCESS ISOLATION"):
            c1, c2 = st.columns([3,1])
            pid_input = c1.text_input("Enter Target PID", placeholder="e.g. 1184")
            if c2.button("ISOLATE PID", type="primary"):
                if pid_input:
                    if isolate_process(pid_input):
                        st.success(f"Quarantined PID {pid_input}")
                    else:
                        st.error("Isolation failed")
    else:
        st.info("Waiting for live telemetry...")

# =====================================================
# TAB 2 — FORENSICS
# =====================================================
with tab_history:
    st.subheader("Historical Incident Audit")
    if not incidents.empty:
        st.dataframe(
            incidents.sort_values("timestamp", ascending=False),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No recorded security violations.")

# =====================================================
# TAB 3 — ANALYTICS
# =====================================================
with tab_intel:
    if not df.empty:

        col1, col2, col3 = st.columns(3)
        col1.metric("Average System Risk", f"{df['risk_score'].mean():.2f}")
        col2.metric("High-Risk Processes", len(df[df['risk_score']>=70]))
        col3.metric("Total Processes Tracked", len(df))

        st.markdown("---")

        st.subheader("Top 10 Riskiest Processes")

        top10 = df.nlargest(10, "risk_score")

        fig1 = px.bar(
            top10,
            x="risk_score",
            y="name",
            orientation="h",
            template="plotly_dark"
        )
        fig1.update_layout(height=400)
        st.plotly_chart(fig1, use_container_width=True)

        st.markdown("---")

        st.subheader("Resource Anomaly Map")

        fig2 = px.scatter(
            df,
            x="cpu",
            y="memory_mb",
            size="risk_score",
            color="risk_score",
            template="plotly_dark"
        )
        fig2.update_layout(height=400)
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("Analytics will appear once data arrives.")

# =====================================================
# TAB 4 — QUARANTINE LOG
# =====================================================
with tab_quarantine:
    st.subheader("🛑 Quarantined Processes (Containment Log)")

    if quarantine_log.empty:
        st.info("No processes quarantined yet.")
    else:
        st.dataframe(
            quarantine_log.sort_values("timestamp", ascending=False),
            use_container_width=True,
            hide_index=True
        )

# =====================================================
# TAB 5 — ABOUT
# =====================================================
with tab_about:
    st.markdown("""
## 🛡️ ZeroSight — Behavioral EDR Platform  

ZeroSight is a lightweight Endpoint Detection and Response (EDR) system that detects 
anomalous process behavior **without relying on malware signatures.**

### Core Components  

**1) Collector (Sensing Layer)**  
- Samples CPU, memory, and network behavior  
- Streams telemetry into SQLite in real time  
- Sends heartbeats so the dashboard knows it is alive  

**2) Risk Engine (Analysis Layer)**  
- Scores each process using behavioral rules  
- Flags high-risk and zero-day candidates  
- Logs critical incidents for forensic review  

**3) Dashboard (Response Layer)**  
- Visualizes system risk  
- Allows manual process quarantine  
- Maintains a permanent containment log  
""")

# -------- LIVE REFRESH (2 SECONDS) --------
if live_mode:
    time.sleep(2)
    st.rerun()
