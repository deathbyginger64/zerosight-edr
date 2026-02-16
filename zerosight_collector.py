import psutil, sqlite3, time
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "zerosight.db")


# --------- SAFE DB CONNECTION ---------
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
    CREATE TABLE IF NOT EXISTS process_telemetry (
        timestamp TEXT,
        pid INTEGER,
        name TEXT,
        cpu REAL,
        memory_mb REAL,
        connections INTEGER,
        username TEXT,
        note TEXT
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

# --------- COLLECTOR CORE ---------
def collect_once():
    conn = get_conn()
    cur = conn.cursor()

    rows = []

    for proc in psutil.process_iter(attrs=['pid','name','cpu_percent','memory_info','username']):
        try:
            cpu = proc.cpu_percent(interval=None)
            mem = proc.info['memory_info'].rss / (1024 * 1024)
            conns = len(proc.net_connections(kind='inet'))
            user = proc.info.get('username', 'unknown')

            rows.append((
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                proc.pid,
                proc.info['name'],
                cpu,
                mem,
                conns,
                user,
                "live"
            ))
        except:
            continue

    if rows:
        cur.executemany("""
        INSERT INTO process_telemetry
        VALUES (?,?,?,?,?,?,?,?)
        """, rows)

    conn.commit()
    conn.close()

# --------- MAIN LOOP ---------
def main():
    print("[+] ZeroSight Collector LIVE (STABLE MODE)")
    init_tables()

    try:
        while True:
            collect_once()
            send_heartbeat("collector")
            print(f"[{datetime.now().strftime('%H:%M:%S')}] data written")
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Collector stopped safely. Goodbye.")

if __name__ == "__main__":
    main()
