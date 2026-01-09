import requests
import os
import time

def test_egress(url):
    print(f"--- Attempting to access {url} ---")
    try:
        # We rely on the HTTP_PROXY env var set in docker-compose
        response = requests.get(url, timeout=5)
        print(f"Status: {response.status_code}")
        print("Success!")
    except Exception as e:
        print(f"Blocked/Failed: {e}")

def main():
    print("Waiting for proxy to start...")
    time.sleep(5) 

    print("Running CLI Agent Egress Tests...")
    
    # 1. Allowed URL
    test_egress("http://api.github.com/zen")
    
    # 2. Blocked URL
    test_egress("http://malicious.com")

    # 3. Another Allowed URL
    test_egress("http://pypi.org")

if __name__ == "__main__":
    main()
