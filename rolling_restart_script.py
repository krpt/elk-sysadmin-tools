import requests
import json
import time
import subprocess
import logging
import argparse
from datetime import datetime
import urllib3
import socket

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Argument parsing
parser = argparse.ArgumentParser(description="Safe rolling restart for a single Elasticsearch node")
parser.add_argument('--password', required=True, help='Password for the "elastic" user')
parser.add_argument('--host', help='Elasticsearch host URL (e.g. https://localhost:9200)')
parser.add_argument('--export-commands', action='store_true', help='Generate a shell script with equivalent commands')
parser.add_argument('--resume-post-restart', action='store_true', help='Resume only from post-restart phase')
args = parser.parse_args()

# Runtime configuration
ELASTIC_USER = 'elastic'
ELASTIC_PASS = args.password
VERIFY_SSL = False
HEADERS = {'Content-Type': 'application/json'}
SERVICE_NAME = 'elasticsearch'

# Determine ES host
if args.host:
    ES_HOST = args.host
else:
    fqdn = socket.getfqdn()
    ES_HOST = f"https://{fqdn}:9200"
print(f"Detected Elasticsearch host: {ES_HOST}")

# Logging setup
log_file = f"rolling_restart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s %(message)s')
print(f"Log file: {log_file}")

# Export shell commands only and exit
if args.export_commands:
    with open("rolling_restart_commands.sh", "w") as f:
        def write(command, comment):
            f.write(f"# {comment}\n{command}\n\n")

        write(f"curl -k -u 'elastic:{ELASTIC_PASS}' -X PUT '{ES_HOST}/_all/_settings' -H 'Content-Type: application/json' -d '{{\"settings\": {{\"index.unassigned.node_left.delayed_timeout\": \"60m\"}}}}'", "Set delayed allocation timeout to 60m")
        write(f"curl -k -u 'elastic:{ELASTIC_PASS}' -X PUT '{ES_HOST}/_cluster/settings' -H 'Content-Type: application/json' -d '{{\"persistent\": {{\"cluster.routing.allocation.enable\": \"primaries\"}}}}'", "Disable shard allocation except primaries")
        write(f"curl -k -u 'elastic:{ELASTIC_PASS}' -X POST '{ES_HOST}/_flush?ignore_unavailable=true'", "Flush all indices")
        write(f"sudo systemctl stop elasticsearch", "Stop Elasticsearch service")
        write(f"# Perform any manual node changes here", "Manual maintenance point")
        write(f"sudo systemctl start elasticsearch", "Start Elasticsearch service")
        write(f"curl -k -u 'elastic:{ELASTIC_PASS}' '{ES_HOST}/_cat/nodes?v=true'", "Check node joined the cluster")
        write(f"curl -k -u 'elastic:{ELASTIC_PASS}' '{ES_HOST}/_cluster/health?pretty'", "Wait until cluster health is green")
        write(f"curl -k -u 'elastic:{ELASTIC_PASS}' -X PUT '{ES_HOST}/_cluster/settings' -H 'Content-Type: application/json' -d '{{\"persistent\": {{\"cluster.routing.allocation.enable\": \"all\"}}}}'", "Re-enable full shard allocation")
        write(f"curl -k -u 'elastic:{ELASTIC_PASS}' -X PUT '{ES_HOST}/_all/_settings' -H 'Content-Type: application/json' -d '{{\"settings\": {{\"index.unassigned.node_left.delayed_timeout\": \"5m\"}}}}'", "Reset delayed allocation timeout to 5m")
    print("✅ Shell command file 'rolling_restart_commands.sh' generated.")
    exit(0)

# Utility functions
def prompt_continue(message="Press Enter to continue..."):
    input(f"\n[PAUSE] {message}")

def confirm_action(label):
    input(f"\n[ACTION REQUIRED] {label} - Press Enter to proceed.")

def log_request(name, method, url, payload, response):
    logging.info(f"[REQUEST] {name}")
    logging.info(f"Method: {method} URL: {url}")
    if payload:
        logging.info("Payload:\n" + json.dumps(payload, indent=2))
    try:
        logging.info("Response:\n" + json.dumps(response, indent=2))
    except:
        logging.info(f"Raw response: {response}")

def send_request(method, endpoint, data=None, name=""):
    url = f"{ES_HOST}{endpoint}"
    print("\n" + "-" * 80)
    print(f"Request: {method} {url}")
    if data:
        print("Payload:")
        print(json.dumps(data, indent=2))
    else:
        print("No payload.")
    print("-" * 80)
    confirm_action(f"Execute: {method} {endpoint}")
    try:
        resp = requests.request(method, url, headers=HEADERS, auth=(ELASTIC_USER, ELASTIC_PASS), data=json.dumps(data) if data else None, verify=VERIFY_SSL)
        resp.raise_for_status()
        parsed = resp.json()
        print("Response:")
        print(json.dumps(parsed, indent=2))
        log_request(name, method, url, data, parsed)
        return parsed
    except Exception as e:
        print(f"[ERROR] HTTP Exception: {e}")
        logging.error(f"[ERROR] HTTP Exception: {e}")
        if input("Ignore and continue? (y/N): ").strip().lower() == "y":
            return {}
        exit(1)

def check_ack(response, label):
    if not response.get("acknowledged"):
        print(f"[ERROR] {label} not acknowledged")
        if input("Ignore and continue? (y/N): ").strip().lower() != "y":
            exit(1)
    else:
        print(f"[OK] {label}")

def check_flush(response):
    failed = response.get("_shards", {}).get("failed", 1)
    if failed != 0:
        print(f"[ERROR] Flush failed: {failed} shard failures")
        if input("Ignore and continue? (y/N): ").strip().lower() != "y":
            exit(1)
    else:
        print("[OK] Flush successful")

def systemctl(command):
    confirm_action(f"sudo systemctl {command} {SERVICE_NAME}")
    try:
        subprocess.run(["sudo", "systemctl", command, SERVICE_NAME], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] systemctl {command} failed: {e}")
        if input("Ignore and continue? (y/N): ").strip().lower() != "y":
            exit(1)
    prompt_continue("System command complete.")

def wait_for_node(name):
    print("Waiting for node to rejoin the cluster...")
    while True:
        try:
            r = requests.get(f"{ES_HOST}/_cat/nodes?h=name", auth=(ELASTIC_USER, ELASTIC_PASS), verify=VERIFY_SSL)
            if name in r.text:
                print(f"[OK] Node {name} found in cluster")
                break
        except:
            pass
        time.sleep(10)

def wait_for_cluster_green():
    print("Waiting for cluster status to become GREEN...")
    while True:
        try:
            r = requests.get(f"{ES_HOST}/_cluster/health", auth=(ELASTIC_USER, ELASTIC_PASS), verify=VERIFY_SSL)
            status = r.json().get("status")
            print(f"Current status: {status}")
            if status == "green":
                print("[OK] Cluster is GREEN")
                break
        except:
            pass
        time.sleep(10)

def get_node_name():
    try:
        r = requests.get(f"{ES_HOST}/_nodes/_local", auth=(ELASTIC_USER, ELASTIC_PASS), verify=VERIFY_SSL)
        r.raise_for_status()
        data = r.json()
        return next(iter(data['nodes'].values()))['name']
    except Exception as e:
        print(f"[ERROR] Could not retrieve node name: {e}")
        exit(1)

# === Execution ===

node_name = get_node_name()

if not args.resume_post_restart:
    resp = send_request("PUT", "/_all/_settings", {"settings": {"index.unassigned.node_left.delayed_timeout": "60m"}}, "Set delayed_timeout")
    check_ack(resp, "Set delayed_timeout")
    prompt_continue()

    resp = send_request("PUT", "/_cluster/settings", {"persistent": {"cluster.routing.allocation.enable": "primaries"}}, "Disable shard allocation")
    check_ack(resp, "Disable shard allocation")
    prompt_continue()

    resp = send_request("POST", "/_flush?ignore_unavailable=true", None, "Flush indices")
    check_flush(resp)
    prompt_continue()

    systemctl("stop")
    print("Perform necessary node changes now.")
    prompt_continue()
    systemctl("start")

wait_for_node(node_name)
prompt_continue()
wait_for_cluster_green()
prompt_continue()

resp = send_request("PUT", "/_cluster/settings", {"persistent": {"cluster.routing.allocation.enable": "all"}}, "Re-enable shard allocation")
check_ack(resp, "Re-enable shard allocation")
prompt_continue()

resp = send_request("PUT", "/_all/_settings", {"settings": {"index.unassigned.node_left.delayed_timeout": "5m"}}, "Reset delayed_timeout")
check_ack(resp, "Reset delayed_timeout")
prompt_continue()

print("\n[FINISHED] Rolling restart process completed successfully.")
logging.info("Rolling restart completed successfully.")
