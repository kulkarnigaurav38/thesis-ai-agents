import requests
import json

url = "http://localhost:5000/check"
payload = {
    "agent_id": "agent-007",
    "tool_name": "delete",
    "parameters": {
        "url": "http://localhost:8000/api/delete",
        "asset_type": "calendar_event"
    }
}

try:
    response = requests.post(url, json=payload)
    data = response.json()
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(data, indent=2)}")
    
    if data.get("status") == "HITL":
        print("\nSUCCESS: Server returns HITL for agent-007.")
    else:
        print("\nFAILURE: Server returned unexpected status.")
except Exception as e:
    print(f"Error: {e}")
