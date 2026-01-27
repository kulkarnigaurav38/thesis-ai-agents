"""
Universal Security Shim Service

A middleware adapter between different agent protocols (Browser, MCP, A2A) 
and the Policy Engine (PDP). Normalizes intents and forwards authorization 
requests to the existing Policy Engine at localhost:5000.
"""

from enum import Enum
from typing import Optional, Dict, Any, Literal
from flask import Flask, request, jsonify
from flask_cors import CORS
from pydantic import BaseModel, Field
import requests

app = Flask(__name__)
CORS(app)

# Configuration
POLICY_ENGINE_URL = "http://localhost:5000/check"


# =============================================================================
# Pydantic Models
# =============================================================================

class Protocol(str, Enum):
    """Supported agent protocols."""
    BROWSER = "BROWSER"
    MCP = "MCP"
    A2A = "A2A"


class BrowserPayload(BaseModel):
    """Payload structure for Browser protocol requests."""
    url: str
    tab_id: Optional[str] = None


class MCPPayload(BaseModel):
    """Payload structure for MCP protocol requests."""
    tool_name: str
    arguments: Optional[Dict[str, Any]] = Field(default_factory=dict)


class A2APayload(BaseModel):
    """Payload structure for A2A protocol requests."""
    sender_agent: str
    target_action: str
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)


class AuthorizeRequest(BaseModel):
    """Incoming authorization request from any agent."""
    protocol: Protocol
    payload: Dict[str, Any]


class StandardIntent(BaseModel):
    """
    Normalized intent format to send to Policy Engine.
    This is the canonical representation regardless of source protocol.
    """
    action: str
    asset: str
    constraint: Optional[Dict[str, Any]] = None


class ShimResponse(BaseModel):
    """Response from the Shim service."""
    status: Literal["PERMIT", "PROHIBITION"]
    reason: Optional[str] = None


# =============================================================================
# Intent Normalizer
# =============================================================================

class IntentNormalizer:
    """
    Translates protocol-specific payloads into a StandardIntent
    that can be sent to the Policy Engine.
    """

    @staticmethod
    def normalize(protocol: Protocol, payload: Dict[str, Any]) -> StandardIntent:
        """
        Normalize a protocol-specific payload into a StandardIntent.
        
        Args:
            protocol: The source protocol (BROWSER, MCP, A2A)
            payload: The protocol-specific payload data
            
        Returns:
            StandardIntent: Normalized intent for Policy Engine
            
        Raises:
            ValueError: If protocol is not recognized
        """
        if protocol == Protocol.BROWSER:
            return IntentNormalizer._normalize_browser(payload)
        elif protocol == Protocol.MCP:
            return IntentNormalizer._normalize_mcp(payload)
        elif protocol == Protocol.A2A:
            return IntentNormalizer._normalize_a2a(payload)
        else:
            raise ValueError(f"Unknown protocol: {protocol}")

    @staticmethod
    def _normalize_browser(payload: Dict[str, Any]) -> StandardIntent:
        """
        Normalize Browser protocol payload.
        
        Browser agents send navigation requests with URL and tab context.
        Maps to: action=NAVIGATE, asset=url
        """
        browser_data = BrowserPayload(**payload)
        return StandardIntent(
            action="navigate",  # Lowercase to match existing policy engine
            asset=browser_data.url,
            constraint={"tab_id": browser_data.tab_id} if browser_data.tab_id else None
        )

    @staticmethod
    def _normalize_mcp(payload: Dict[str, Any]) -> StandardIntent:
        """
        Normalize MCP (Model Context Protocol) payload.
        
        MCP agents execute tools with arguments.
        Maps to: action=EXECUTE, asset=tool_name, constraint=arguments
        """
        mcp_data = MCPPayload(**payload)
        return StandardIntent(
            action="execute",
            asset=mcp_data.tool_name,
            constraint=mcp_data.arguments if mcp_data.arguments else None
        )

    @staticmethod
    def _normalize_a2a(payload: Dict[str, Any]) -> StandardIntent:
        """
        Normalize A2A (Agent-to-Agent) payload.
        
        A2A agents delegate actions between agents.
        Maps to: action=DELEGATE, asset=target_action
        """
        a2a_data = A2APayload(**payload)
        return StandardIntent(
            action="delegate",
            asset=a2a_data.target_action,
            constraint={
                "sender_agent": a2a_data.sender_agent,
                **(a2a_data.context or {})
            }
        )


# =============================================================================
# Shim Endpoints
# =============================================================================

@app.route('/authorize', methods=['POST'])
def authorize():
    """
    Main authorization endpoint.
    
    Accepts requests from any agent protocol, normalizes the intent,
    and forwards to the Policy Engine for a decision.
    
    Request Body:
        {
            "protocol": "BROWSER" | "MCP" | "A2A",
            "payload": { ... protocol-specific data ... }
        }
        
    Response:
        200: {"status": "PERMIT", "reason": "..."}
        403: {"status": "PROHIBITION", "reason": "..."}
    """
    try:
        # Parse and validate incoming request
        data = request.json
        auth_request = AuthorizeRequest(**data)
        
        print(f"[Shim] Received {auth_request.protocol.value} request: {auth_request.payload}")
        
        # Normalize the intent
        normalizer = IntentNormalizer()
        intent = normalizer.normalize(auth_request.protocol, auth_request.payload)
        
        print(f"[Shim] Normalized Intent: action={intent.action}, asset={intent.asset}")
        
        # Forward to Policy Engine
        policy_response = forward_to_policy_engine(intent, auth_request.protocol)
        
        return policy_response
        
    except ValueError as e:
        print(f"[Shim] Validation Error: {e}")
        return jsonify({
            "status": "PROHIBITION",
            "reason": f"Invalid request: {str(e)}"
        }), 400
    except Exception as e:
        print(f"[Shim] Error: {e}")
        return jsonify({
            "status": "PROHIBITION",
            "reason": f"Internal error: {str(e)}"
        }), 500


def forward_to_policy_engine(intent: StandardIntent, protocol: Protocol):
    """
    Forward the normalized intent to the Policy Engine.
    
    Args:
        intent: The normalized StandardIntent
        protocol: Original protocol for context
        
    Returns:
        Flask response with PERMIT (200) or PROHIBITION (403)
    """
    try:
        # Build request for Policy Engine
        policy_request = {
            "agent_id": f"{protocol.value.lower()}_agent",
            "action": intent.action,
            "target": intent.asset,
            "context": intent.constraint or {}
        }
        
        print(f"[Shim] Forwarding to Policy Engine: {policy_request}")
        
        # Call Policy Engine
        response = requests.post(
            POLICY_ENGINE_URL,
            json=policy_request,
            timeout=65  # Slightly more than PE's 60s timeout for consent
        )
        
        result = response.json()
        status = result.get("status", "PROHIBITION")
        reason = result.get("reason", "No reason provided")
        
        print(f"[Shim] Policy Engine Response: {status} - {reason}")
        
        # Map Policy Engine response to Shim response
        if status in ["PERMIT", "DUTY_REQUIRED"]:
            return jsonify({
                "status": "PERMIT",
                "reason": reason
            }), 200
        elif status == "CONSENT_NEEDED":
            # CONSENT_NEEDED means the PE is waiting for user input
            # The PE blocks until resolved, so we wait for the final answer
            # If we get here, it means the consent was granted
            return jsonify({
                "status": "PERMIT",
                "reason": reason
            }), 200
        else:
            # PROHIBITION or any other status
            return jsonify({
                "status": "PROHIBITION",
                "reason": reason
            }), 403
            
    except requests.exceptions.Timeout:
        print("[Shim] Policy Engine timeout")
        return jsonify({
            "status": "PROHIBITION",
            "reason": "Policy check timed out"
        }), 403
    except requests.exceptions.ConnectionError:
        print("[Shim] Cannot connect to Policy Engine")
        return jsonify({
            "status": "PROHIBITION",
            "reason": "Policy Engine unavailable"
        }), 503
    except Exception as e:
        print(f"[Shim] Error calling Policy Engine: {e}")
        return jsonify({
            "status": "PROHIBITION",
            "reason": f"Policy check failed: {str(e)}"
        }), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "universal-security-shim"})


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("Universal Security Shim")
    print("=" * 60)
    print(f"Policy Engine: {POLICY_ENGINE_URL}")
    print("Listening on: http://127.0.0.1:8000")
    print("=" * 60)
    
    app.run(host='127.0.0.1', port=8000, debug=True)
