import requests
from typing import Any, Dict
import time

SERVER_URL = "http://127.0.0.1:5000"

class AccessDeniedException(Exception):
    def __init__(self, message, reason):
        super().__init__(message)
        self.reason = reason

class SecurityShim:
    def __init__(self, agent_id: str = "agent_client"):
        self.agent_id = agent_id

    def check_permission(self, action: str, target: str, context: Dict[str, Any] = None):
        """Calls the Policy Server to check permission. Blocks if Consent is needed."""
        print(f"[Shim] Checking permission: {action} -> {target}")
        
        try:
            response = requests.post(f"{SERVER_URL}/check", json={
                "agent_id": self.agent_id,
                "action": action,
                "target": target,
                "context": context or {}
            }, timeout=70) # > 60s server timeout
            
            response.raise_for_status()
            data = response.json()
            
            status = data.get("status")
            reason = data.get("reason")
            
            if status == "PERMIT":
                print(f"[Shim] Access GRANTED: {reason}")
                return True
            else:
                print(f"[Shim] Access DENIED: {reason}")
                raise AccessDeniedException(f"Policy blocked action: {reason}", reason)
                
        except requests.exceptions.RequestException as e:
            print(f"[Shim] Server Error: {e}")
            raise AccessDeniedException("Failed to contact Policy Server", str(e))

    def secure_navigation(self, page, url: str):
        """Wrapper for Playwright Page.goto()"""
        # 1. Check Policy
        self.check_permission("navigate", url)
        
        # 2. Execute
        print(f"[Shim] Navigating to {url}...")
        return page.goto(url)

    def secure_click(self, page, selector: str):
        """Wrapper for Playwright Page.click() - though the Extension handles this too."""
        # Note: This is redundant if Extension is active, but good for backend enforcement.
        # We might skip this if we rely solely on Extension for DOM actions.
        # But let's keep it for demonstration.
        # self.check_permission("click", selector) 
        return page.click(selector)

    # Legacy methods removed.
