from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Robust path handling
# BASE_DIR is the project root (one directory up from this script in src/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add project root to path for imports
sys.path.append(BASE_DIR)

from src.policy_engine import ODRLEvaluator, AuthorizationRequest, Verdict
from src.audit_log import AuditLogger, AuditEvent

app = Flask(__name__)
CORS(app)  # Enable CORS for extension requests

# Initialize components with absolute paths
POLICY_PATH = os.path.join(BASE_DIR, "config", "policy.yaml")
USER_CONFIG_PATH = os.path.join(BASE_DIR, "config", "user_config.json")
AUDIT_DB_PATH = os.path.join(BASE_DIR, "audit.db")

evaluator = ODRLEvaluator(POLICY_PATH, USER_CONFIG_PATH)
audit_logger = AuditLogger(AUDIT_DB_PATH)

@app.route('/check', methods=['POST'])
def check_policy():
    data = request.json
    agent_id = data.get('agent_id', 'unknown')
    tool_name = data.get('tool_name') # Legacy field from extension
    parameters = data.get('parameters', {})

    print(f"[Server] Received request: {tool_name} with {parameters}")

    # Map Legacy Tool Name to ODRL Action/Target
    action = "unknown"
    target = "unknown"
    
    if tool_name == "navigate":
        action = "navigate"
        target = "http://example.com/asset:browser"
    elif tool_name == "delete": # Calendar Use Case
        action = "delete"
        target = "http://example.com/asset:calendar_event"
    elif tool_name == "pay": # Payment Use Case
        action = "pay"
        target = "http://example.com/asset:payment_gateway"
    elif tool_name == "read_file":
        action = "read"
        target = "http://example.com/asset:filesystem"
    else:
        # Fallback for generic tools
        action = "use"
        target = f"http://example.com/asset:{tool_name}"

    # Create Authorization Request
    auth_req = AuthorizationRequest(
        assignee=f"user:{agent_id}",
        action=action,
        target=target,
        context=parameters
    )

    # Check Policy
    verdict = evaluator.evaluate(auth_req)

    # Log Event
    audit_logger.log_event(AuditEvent(
        agent_id=agent_id,
        tool_name=f"{action} on {target}",
        parameters=parameters,
        decision=verdict.status,
        justification=verdict.reason
    ))

    # Map Verdict back to helper status for extension (ALLOW/DENY/HITL)
    status = verdict.status
    if status == "PERMIT":
        status = "ALLOW"
    elif status == "PROHIBITION":
        status = "DENY"
    elif status == "DUTY_REQUIRED":
        status = "HITL" 

    return jsonify({
        "status": status,
        "reason": verdict.reason
    })

@app.route('/trust', methods=['POST'])
def trust_entity():
    data = request.json
    category = data.get('category')
    value = data.get('value')
    
    if not category or not value:
        return jsonify({"error": "Missing category or value"}), 400

    print(f"[Server] Trusting {category}: {value}")
    evaluator.user_policy.add_trust(category, value)
    
    return jsonify({"status": "SUCCESS", "message": f"Added {value} to trusted {category}s"})

if __name__ == '__main__':
    app.run(port=5000, debug=True)
