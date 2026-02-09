import os, time, json, shutil, hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR = r"D:\3RD year"  
QUARANTINE = r"D:\4TH YEAR\Capstone"
os.makedirs(QUARANTINE, exist_ok=True)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(8192)
            if not b: break
            h.update(b)
    return h.hexdigest()

class RansomHandler(FileSystemEventHandler):
    def __init__(self):
        self.write_counts = {}
        self.window_seconds = 5
        self.threshold_writes = 50

    def on_modified(self, event):
        if event.is_directory: return
        self._note_write(event.src_path)

    def on_created(self, event):
        if event.is_directory: return
        self._note_write(event.src_path)

    def _note_write(self, path):
        now = time.time()
        self.write_counts.setdefault(path, []).append(now)
        self.write_counts[path] = [t for t in self.write_counts[path] if t > now - self.window_seconds]
        total_writes = sum(len(v) for v in self.write_counts.values())
        if total_writes > self.threshold_writes:
            self.handle_suspicious_activity(path)

    def handle_suspicious_activity(self, path):
        try:
            if not os.path.exists(path):
                return
            fname = os.path.basename(path)
            dest = os.path.join(QUARANTINE, f"{int(time.time())}_{fname}")
            shutil.copy2(path, dest)
            meta = {
                "original_path": path,
                "quarantine_path": dest,
                "sha256": sha256(dest),
                "timestamp": time.time(),
                "reason": "high_write_rate"
            }
            with open(dest + ".meta.json", "w") as f:
                json.dump(meta, f, indent=2)
            print("🚨 QUARANTINED:", path)
        except Exception as e:
            print("Error quarantining:", e)

if __name__ == "__main__":
    event_handler = RansomHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()
    print("👀 Monitoring", WATCH_DIR)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
