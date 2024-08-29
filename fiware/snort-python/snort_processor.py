import requests
import json
import time
import os

# Environment Variables
IOTA_URL = os.environ.get('IOTA_URL', 'http://iot-agent:4061')
ORION_URL = os.environ.get('ORION_URL', 'http://orion:1026')
SERVICE = os.environ.get('FIWARE_SERVICE', 'snortService')
SERVICE_PATH = os.environ.get('FIWARE_SERVICEPATH', '/')
DEVICE_ID = os.environ.get('DEVICE_ID', 'snortDevice')
API_KEY = os.environ.get('API_KEY', '1234')
ALERT_FILE_PATH = os.environ.get('ALERT_FILE_PATH', '/var/log/snort/alert_json.txt')

HEADERS = {
    'fiware-service': SERVICE,
    'fiware-servicepath': SERVICE_PATH,
    'Content-Type': 'application/json'
}

def provision_service_group():
    url = f'{IOTA_URL}/iot/services'
    payload = {
        "services": [
            {
                "resource": "/iot/d",
                "apikey": API_KEY,
                "type": "SnortDevice",
                "cbhost": "orion",
                "cbstype": "orion"
            }
        ]
    }
    
    retries = 5
    for _ in range(retries):
        try:
            response = requests.post(url, headers=HEADERS, json=payload)
            if response.status_code in [201, 409]:
                print("Service group provisioned successfully or already exists.")
                return
            else:
                print(f"Failed to provision service group: {response.status_code} {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"Exception occurred: {e}")
        time.sleep(5)  # Wait before retrying

def provision_device():
    url = f'{IOTA_URL}/iot/devices'
    payload = {
        "devices": [
            {
                "device_id": DEVICE_ID,
                "entity_name": f'urn:ngsi-ld:SnortDevice:{DEVICE_ID}',
                "entity_type": "SnortDevice",
                "attributes": [
                    { "object_id": "t", "name": "timestamp", "type": "Text" },
                    { "object_id": "c", "name": "class", "type": "Text" },
                    { "object_id": "m", "name": "msg", "type": "Text" },
                    { "object_id": "p", "name": "priority", "type": "Integer" },
                    { "object_id": "sa", "name": "src_addr", "type": "Text" },
                    { "object_id": "sp", "name": "src_port", "type": "Integer" },
                    { "object_id": "da", "name": "dst_addr", "type": "Text" },
                    { "object_id": "dp", "name": "dst_port", "type": "Integer" }
                ],
                "protocol": "PDI-IoTA-UltraLight::HTTP"
            }
        ]
    }
    
    retries = 5
    for _ in range(retries):
        try:
            response = requests.post(url, headers=HEADERS, json=payload)
            if response.status_code in [201, 409]:
                print("Device provisioned successfully or already exists.")
                return
            else:
                print(f"Failed to provision device: {response.status_code} {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"Exception occurred: {e}")
        time.sleep(5)  # Wait before retrying

def send_measurement(alert):
    url = f'{IOTA_URL}/iot/d?i={DEVICE_ID}&k={API_KEY}'
    payload = {
        "t": alert.get('timestamp', ''),
        "c": alert.get('class', ''),
        "m": alert.get('msg', ''),
        "p": alert.get('priority', 0),
        "sa": alert.get('src_addr', ''),
        "sp": alert.get('src_port', 0),
        "da": alert.get('dst_addr', ''),
        "dp": alert.get('dst_port', 0)
    }
    headers = {'Content-Type': 'text/plain'}
    
    retries = 5
    for _ in range(retries):
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload))
            if response.status_code == 200:
                print(f"Measurement sent successfully: {payload}")
                return
            else:
                print(f"Failed to send measurement: {response.status_code} {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"Exception occurred: {e}")
        time.sleep(2)  # Wait before retrying

def tail_f(file):
    file.seek(0, 2)  # Move to EOF
    while True:
        line = file.readline()
        if not line:
            time.sleep(1)
            continue
        yield line

def main():
    # Provision Service Group and Device
    provision_service_group()
    provision_device()
    
    # Process Snort Alerts in Real-Time
    with open(ALERT_FILE_PATH, 'r') as f:
        for line in tail_f(f):
            line = line.strip()
            if line:
                try:
                    alert = json.loads(line)
                    send_measurement(alert)
                except json.JSONDecodeError as e:
                    print(f"JSON decode error: {e}")

if __name__ == "__main__":
    main()
