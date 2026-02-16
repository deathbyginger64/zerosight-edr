import sqlite3
import pandas as pd
import time
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "zerosight.db")


# --------- SAFE CONNECTION ---------
def get_conn():
    conn = sqlite3.connect(f"file:{DB}?mode=rwc", uri=True,
                           timeout=20, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=20000;")
    return conn

# --------- INIT TABLES ---------
def init_tables():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS latest_risks (
        timestamp TEXT,
        pid INTEGER,
        name TEXT,
        cpu REAL,
        memory_mb REAL,
        connections INTEGER,
        username TEXT,
        risk_score REAL,
        reason TEXT,
        attack_label TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS incident_logs (
        timestamp TEXT,
        pid INTEGER,
        name TEXT,
        risk_score REAL,
        reason TEXT,
        attack_label TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS system_heartbeat (
        component TEXT PRIMARY KEY,
        last_seen TEXT,
        status TEXT
    )
    """)

    conn.commit()
    conn.close()

# --------- HEARTBEAT ---------
def send_heartbeat(component):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO system_heartbeat(component, last_seen, status)
    VALUES(?,?,?)
    ON CONFLICT(component) DO UPDATE SET
        last_seen = excluded.last_seen,
        status = excluded.status
    """, (
        component,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "RUNNING"
    ))

    conn.commit()
    conn.close()

# --------- LOAD DATA ---------
def load_recent_data():
    conn = get_conn()
    query = """
    SELECT timestamp, pid, name, cpu, memory_mb, connections, username
    FROM process_telemetry
    WHERE timestamp >= datetime('now','-60 seconds','localtime')
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# --------- RISK RULES (UNCHANGED) ---------
def compute_risk(row):
    score = 0
    reasons = []

    if row["cpu"] > 50:
        score += 30
        reasons.append("High CPU")

    if row["memory_mb"] > 500:
        score += 25
        reasons.append("High Memory")

    if row["connections"] > 8:
        score += 30
        reasons.append("Network Spike")

    final_score = min(score, 100)

    if final_score < 40:
        attack_label = "NORMAL"
    elif final_score < 70:
        attack_label = "SUSPICIOUS"
    elif final_score < 90:
        attack_label = "HIGH-RISK"
    else:
        attack_label = "ZERO-DAY CANDIDATE"

    reason_text = ", ".join(reasons) if reasons else "Normal"
    return final_score, reason_text, attack_label

# --------- UPDATE TABLE ---------
def refresh_latest_risks(df):
    conn = get_conn()
    df.to_sql("latest_risks", conn, if_exists="replace", index=False)
    conn.close()

# --------- LOG INCIDENTS ---------
def log_incidents(df):
    critical = df[df["attack_label"] == "ZERO-DAY CANDIDATE"]
    if critical.empty:
        return

    conn = get_conn()
    for _, r in critical.iterrows():
        conn.execute("""
        INSERT INTO incident_logs
        VALUES (?,?,?,?,?,?)
        """, (
            r["timestamp"],
            int(r["pid"]),
            r["name"],
            float(r["risk_score"]),
            r["reason"],
            r["attack_label"]
        ))
    conn.commit()
    conn.close()

# --------- MAIN LOOP ---------
def main():
    print("[+] ZeroSight Risk Engine LIVE (PATH A)")
    init_tables()

    try:
        while True:
            df = load_recent_data()

            if df.empty:
                print("[*] Waiting for collector...")
                time.sleep(2)
                continue

            results = []
            for _, row in df.iterrows():
                score, reason, label = compute_risk(row)

                results.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "pid": int(row["pid"]),
                    "name": row["name"],
                    "cpu": float(row["cpu"]),
                    "memory_mb": float(row["memory_mb"]),
                    "connections": int(row["connections"]),
                    "username": row["username"],
                    "risk_score": float(score),
                    "reason": reason,
                    "attack_label": label
                })

            scored = pd.DataFrame(results)
            refresh_latest_risks(scored)
            log_incidents(scored)
            send_heartbeat("risk_engine")

            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Updated | Rows={len(scored)} | "
                  f"Zero-Day Candidates={len(scored[scored['attack_label']=='ZERO-DAY CANDIDATE'])}")

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[!] Risk engine stopped safely.")

if __name__ == "__main__":
    main()
