import urllib.request
import json
import time
import subprocess
import sys
import os

SERVER_URL = "http://localhost:5000/check"
TRUST_URL = "http://localhost:5000/trust"

def check_policy(url):
    data = {
        "agent_id": "test-browser-agent",
        "tool_name": "navigate", # Maps to Action: navigate, Asset: browser
        "parameters": {"url": url}
    }
    json_data = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(SERVER_URL, data=json_data, headers={'Content-Type': 'application/json'})
    
    with urllib.request.urlopen(req) as response:
        resp_body = response.read().decode('utf-8')
        return json.loads(resp_body)

def trust_host(host):
    data = {
        "category": "host",
        "value": host
    }
    json_data = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(TRUST_URL, data=json_data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as response:
        return response.read()

def main():
    # Remove user_config.json to start fresh
    if os.path.exists("config/user_config.json"):
        os.remove("config/user_config.json")

    print("Starting Policy Server...")
    server_process = subprocess.Popen([sys.executable, "src/server.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(5) 

    try:
        # 1. Allowed Site
        print("Testing Google (Allowed)...")
        resp = check_policy("https://google.com")
        if resp['status'] == "ALLOW": print("PASS")
        else: print(f"FAIL: {resp}")

        # 2. Blocked Site
        print("Testing Malicious (Blocked)...")
        resp = check_policy("https://malicious.com")
        if resp['status'] == "DENY": print("PASS") # Prohibited
        else: print(f"FAIL: {resp}")

        # 3. Unknown Site (Catch-All -> HITL)
        print("Testing Unknown Site (Expect HITL)...")
        resp = check_policy("https://new-site.com")
        if resp['status'] == "HITL": print("PASS")
        else: print(f"FAIL: {resp}")

        # 4. Simulate User Clicking "Allow Always"
        print("Simulating Allow Always for new-site.com...")
        trust_host("new-site.com")
        
        # 5. Re-test Unknown Site (Expect ALLOW)
        print("Re-testing new-site.com (Expect ALLOW via Trust)...")
        resp = check_policy("https://new-site.com")
        if resp['status'] == "ALLOW": print("PASS")
        else: print(f"FAIL: {resp}")

    finally:
        print("Stopping Policy Server...")
        server_process.terminate()
        stdout, stderr = server_process.communicate()
        # if stdout: print(f"Server Stdout: {stdout.decode()}")
        # if stderr: print(f"Server Stderr: {stderr.decode()}")

if __name__ == "__main__":
    main()
