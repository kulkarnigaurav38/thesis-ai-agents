import time
import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import threading

# Robust path handling
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from src.policy_engine import ODRLEvaluator, AuthorizationRequest, Verdict
from src.audit_logger import AuditLogger
from src.user_config import UserPolicyStore

app = Flask(__name__)
CORS(app)

# Paths
POLICY_PATH = os.path.join(BASE_DIR, "config", "policy.yaml")
USER_CONFIG_PATH = os.path.join(BASE_DIR, "config", "user_config.json")
AUDIT_DB_PATH = os.path.join(BASE_DIR, "audit.db")

# Components
evaluator = ODRLEvaluator(POLICY_PATH, USER_CONFIG_PATH)
audit_logger = AuditLogger(AUDIT_DB_PATH)

# State for Blocking Requests
# Structure: { request_id: { "status": "PENDING" | "PERMIT" | "PROHIBITION", "data": {...} } }
pending_requests = {}
requests_lock = threading.Lock()

@app.route('/check', methods=['POST'])
def check_policy():
    data = request.json
    agent_id = data.get('agent_id', 'unknown')
    action = data.get('action') # 'navigate', 'pay'
    target = data.get('target') # URL
    context = data.get('context', {})

    print(f"[Server] Check Request: {action} on {target} by {agent_id}")

    # 1. Evaluate Policy
    auth_req = AuthorizationRequest(
        assignee=agent_id,
        action=action,
        target=target,
        context=context
    )
    verdict = evaluator.evaluate(auth_req)

    # 2. Handle CONSENT_NEEDED (Blocking)
    if verdict.status == "CONSENT_NEEDED":
        request_id = str(uuid.uuid4())
        
        print(f"[Server] Consent Needed. ID: {request_id}")
        
        with requests_lock:
            pending_requests[request_id] = {
                "id": request_id,
                "agent_id": agent_id,
                "action": action,
                "target": target,
                "reason": verdict.reason,
                "status": "PENDING",
                "timestamp": time.time()
            }
        
        # Audit Log (Attempt)
        audit_logger.log_event(agent_id, action, target, "PENDING", verdict.reason)

        # Wait for User Resolution (Long Polling / Loop)
        # Timeout after 60 seconds
        start_time = time.time()
        final_status = "PROHIBITION" # Default deny on timeout
        final_reason = "User request timed out."

        while time.time() - start_time < 60:
            with requests_lock:
                req_state = pending_requests.get(request_id)
                if req_state and req_state['status'] != "PENDING":
                    final_status = req_state['status']
                    final_reason = req_state.get('justification', "User decided.")
                    # Clean up
                    del pending_requests[request_id]
                    break
            time.sleep(0.5)
        
        # Log Final Decision
        audit_logger.log_event(agent_id, action, target, final_status, final_reason)

        return jsonify({
            "status": final_status,
            "reason": final_reason
        })

    # 3. Log Immediate Decision
    audit_logger.log_event(agent_id, action, target, verdict.status, verdict.reason)
    
    return jsonify({
        "status": verdict.status,
        "reason": verdict.reason
    })

@app.route('/pending_requests', methods=['GET'])
def get_pending():
    """Called by Browser Extension to see badges/notifications."""
    with requests_lock:
        # Return list of pending items
        items = [v for k, v in pending_requests.items() if v['status'] == "PENDING"]
    return jsonify(items)

@app.route('/resolve_request', methods=['POST'])
def resolve_request():
    """Called by Browser Extension to Approve/Deny."""
    data = request.json
    request_id = data.get('request_id')
    decision = data.get('decision') # 'PERMIT' or 'PROHIBITION'
    justification = data.get('justification', "User Decision")
    trust_always = data.get('trust_always', False) # If true, add to whitelist

    print(f"[Server] Resolving {request_id} -> {decision} (Trust: {trust_always})")

    with requests_lock:
        if request_id in pending_requests:
            pending_requests[request_id]['status'] = decision
            pending_requests[request_id]['justification'] = justification
            
            # handle trust update if needed
            if decision == "PERMIT" and trust_always:
                req_data = pending_requests[request_id]
                target = req_data.get('target')
                action = req_data.get('action')
                
                if action == "navigate" and target:
                    # MVP: Extract hostname from URL
                    from urllib.parse import urlparse
                    try:
                        parsed = urlparse(target)
                        host = parsed.netloc or target 
                        evaluator.user_policy.add_trust("host", host)
                        print(f"[Server] Whitelisted Host: {host}")
                    except Exception as e:
                        print(f"[Server] Error parsing target url: {e}")
                        evaluator.user_policy.add_trust("host", target)

            return jsonify({"status": "success"})
        else:
            return jsonify({"error": "Request not found"}), 404

@app.route('/audit', methods=['GET'])
def get_audit_logs():
    logs = audit_logger.get_logs(20)
    # Convert Row objects to dicts is handled in get_logs if row_factory set, 
    # but here let's ensure JSON serializable
    return jsonify(logs)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
