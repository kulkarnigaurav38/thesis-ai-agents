import http.server
import socketserver
import urllib.request
import urllib.error
import sys
import os
import json
from urllib.parse import urlparse

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.policy_engine import ODRLEvaluator, AuthorizationRequest, Verdict
from src.audit_log import AuditLogger, AuditEvent

PORT = 8080
POLICY_PATH = "config/policy.yaml"
DB_PATH = "audit.db"

evaluator = ODRLEvaluator(POLICY_PATH)
audit_logger = AuditLogger(DB_PATH)

class EgressProxyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def handle_request(self, method):
        target_url = self.path
        print(f"[Proxy] Intercepting {method} request to: {target_url}")

        # Parse Host for Policy Context
        parsed_url = urlparse(target_url)
        # If absolute URL (proxy request)
        host = parsed_url.hostname
        if not host:
             # Fallback if path is just relative (unlikely for proxy)
             host = "unknown"

        # Create Authorization Request
        # Use Case: Network Egress
        auth_req = AuthorizationRequest(
            assignee="user:sandboxed-agent",
            action="request",
            target="http://example.com/asset:network",
            context={
                "url": target_url, 
                "method": method,
                "host": host
            }
        )

        verdict = evaluator.evaluate(auth_req)

        # Log Event
        audit_logger.log_event(AuditEvent(
            agent_id=auth_req.assignee,
            tool_name=f"{auth_req.action} on {auth_req.target}",
            parameters=auth_req.context,
            decision=verdict.status,
            justification=verdict.reason
        ))

        if verdict.status == "PERMIT":
            self.proxy_request(target_url, method)
        elif verdict.status == "DUTY_REQUIRED":
            # For network proxy, we can't easily do HITL without protocol support.
            # We block and log.
            self.send_error(403, f"HITL Required (Not supported in proxy mode): {verdict.reason}")
        else:
            self.send_error(403, f"Blocked by Policy: {verdict.reason}")

    def proxy_request(self, url, method):
        try:
            req = urllib.request.Request(url, method=method)
            with urllib.request.urlopen(req) as response:
                self.send_response(response.status)
                for header, value in response.headers.items():
                    self.send_header(header, value)
                self.end_headers()
                self.wfile.write(response.read())
        except urllib.error.HTTPError as e:
            self.send_error(e.code, e.reason)
        except Exception as e:
            self.send_error(500, str(e))

if __name__ == "__main__":
    print(f"Starting Egress Proxy on port {PORT}...")
    with socketserver.TCPServer(("", PORT), EgressProxyHandler) as httpd:
        httpd.serve_forever()
