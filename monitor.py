import os, time, json, shutil, hashlib, math
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR = r"D:\3RD year"
QUARANTINE = r"D:\4TH YEAR\Capstone\quarantine"
LOG_FILE = "logs.json"

os.makedirs(QUARANTINE, exist_ok=True)

def log_event(data):
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    logs.append(data)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def entropy(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
        if not data:
            return 0
        freq = [data.count(b) / len(data) for b in set(data)]
        return -sum(p * math.log2(p) for p in freq)
    except:
        return 0

class RansomHandler(FileSystemEventHandler):

    def __init__(self):
        self.write_counts = {}
        self.extensions = {}
        self.entropies = {}
        self.window = 5
        self.threshold = 50

    def on_modified(self, event):
        if not event.is_directory:
            self.analyze(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.analyze(event.src_path)

    def analyze(self, path):
        now = time.time()

        self.write_counts.setdefault(path, []).append(now)
        self.write_counts[path] = [
            t for t in self.write_counts[path] if t > now - self.window
        ]

        total_writes = sum(len(v) for v in self.write_counts.values())

        ext = os.path.splitext(path)[1]
        old_ext = self.extensions.get(path)
        self.extensions[path] = ext

        new_entropy = entropy(path)
        old_entropy = self.entropies.get(path, new_entropy)
        self.entropies[path] = new_entropy

        reasons = []

        if total_writes > self.threshold:
            reasons.append("High write rate")

        if old_ext and old_ext != ext:
            reasons.append("File extension changed")

        if new_entropy - old_entropy > 2.0:
            reasons.append("Entropy spike (possible encryption)")

        if reasons:
            self.quarantine(path, reasons)

    def severity_level(self, reasons):
        if len(reasons) >= 3:
            return "HIGH"
        elif len(reasons) == 2:
            return "MEDIUM"
        return "LOW"

    def quarantine(self, path, reasons):
        if not os.path.exists(path):
            return

        fname = os.path.basename(path)
        dest = os.path.join(QUARANTINE, f"{int(time.time())}_{fname}")
        shutil.copy2(path, dest)

        proc = self.find_process(path)
        severity = self.severity_level(reasons)

        event = {
            "time": time.ctime(),
            "file": path,
            "process": proc["name"],
            "severity": severity,
            "reasons": reasons,
            "action": "File quarantined & process terminated"
        }

        log_event(event)
        print(f"🚨 {severity} ALERT:", path)

        if proc["pid"]:
            try:
                psutil.Process(proc["pid"]).terminate()
            except:
                pass

    def find_process(self, path):
        for p in psutil.process_iter(['pid', 'name']):
            try:
                for f in p.open_files():
                    if f.path == path:
                        return {"pid": p.pid, "name": p.name()}
            except:
                continue
        return {"pid": None, "name": "Unknown"}

if __name__ == "__main__":
    print("👀 Monitoring:", WATCH_DIR)
    observer = Observer()
    observer.schedule(RansomHandler(), WATCH_DIR, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
