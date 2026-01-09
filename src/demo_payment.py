import sys
import os
from typing import Tuple

# Robust path handling
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(BASE_DIR, "config", "policy.yaml")
USER_CONFIG_PATH = os.path.join(BASE_DIR, "config", "user_config.json")

# Add project root to path
sys.path.append(BASE_DIR)

from src.shim import ODRLShim
from src.user_config import UserPolicyStore

# Reset Config for Demo
if os.path.exists(USER_CONFIG_PATH):
    try:
        os.remove(USER_CONFIG_PATH)
    except PermissionError:
        pass # Ignore if locked

# Mock HITL Handler
def mock_hitl_handler(message: str) -> Tuple[bool, bool]:
    print(f"[MOCK REMEDY] Received request: {message}")
    
    if "EvilCorp" in message:
        print("[MOCK REMEDY] User decision: ALLOW ALWAYS (Trust EvilCorp)")
        return True, True
    
    print("[MOCK REMEDY] User decision: ALLOW ONCE")
    return True, False

# Initialize Shim with Absolute Path
shim = ODRLShim(policy_path=POLICY_PATH, hitl_handler=mock_hitl_handler)

@shim.secure_action(action="pay", asset="http://example.com/asset:payment_gateway")
def pay(amount: float, merchant: str):
    print(f"$$$ PAYMENT SUCCESSFUL: Paid ${amount} to {merchant} $$$")
    return "Success"

def main():
    print("--- Scenario 1: Safe Payment ($45 to CoffeeShop) ---")
    try:
        pay(amount=45, merchant="CoffeeShop")
    except Exception as e:
        print(f"Blocked: {e}")

    print("\n--- Scenario 2: Untrusted Merchant First Attempt (EvilCorp) ---")
    # Should trigger HITL. Mock will say "Allow Always".
    try:
        pay(amount=10, merchant="EvilCorp")
    except Exception as e:
        print(f"Blocked: {e}")

    print("\n--- Scenario 3: Untrusted Merchant Second Attempt (EvilCorp) ---")
    # Should be Auto-Allowed (Trust on First Use)
    try:
        pay(amount=10, merchant="EvilCorp")
    except Exception as e:
        print(f"Blocked: {e}")

if __name__ == "__main__":
    main()
