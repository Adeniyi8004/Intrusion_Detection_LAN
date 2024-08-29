import json
import firebase_admin
from firebase_admin import credentials, firestore
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

# Initialize Firebase Admin SDK
cred = credentials.Certificate("path to Firebase Credentials")
firebase_admin.initialize_app(cred)
db = firestore.client()

# Mapping of VM IPs
vm_ips = {
    "192.168.0.171": "VM1",
    "192.168.0.129": "VM2",
    "192.168.0.103": "VM3"
}

# Function to upload data to Firebase
def upload_to_firebase(vm, intrusion_data):
    doc_ref = db.collection('intrusions').document(vm)
    doc_ref.set(intrusion_data)

# Process and format the log entry
def process_log_entry(log_entry):
    log_data = json.loads(log_entry)
    
    # Check if 'dst_addr' exists in log_data
    if 'dst_addr' in log_data:
        dst_ip = log_data['dst_addr']

        if dst_ip in vm_ips:
            vm = vm_ips[dst_ip]
            intrusion_data = {
                "timestamp": log_data["timestamp"],
                "msg": log_data["msg"],
                "priority": log_data["priority"],
                "src_addr": log_data["src_addr"],
                "src_port": log_data["src_port"],
                "dst_addr": log_data["dst_addr"],
                "dst_port": log_data["dst_port"],
                "proto": log_data["proto"]
            }

            # Upload data to Firebase
            upload_to_firebase(vm, intrusion_data)
            print(f"Data uploaded to Firebase for {vm}")
    else:
        print(f"'dst_addr' missing in log entry, continuing to next entry.")

# Watchdog Event Handler
class SnortLogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith("alert_json.txt"):
            with open(event.src_path, 'r') as log_file:
                for line in log_file:
                    if line.strip():  # Avoid empty lines
                        process_log_entry(line.strip())

# Monitor the log file
def monitor_log_file(log_file_path):
    event_handler = SnortLogHandler()
    observer = Observer()
    observer.schedule(event_handler, path=log_file_path, recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    monitor_log_file("/var/log/snort/alert_json.txt")

