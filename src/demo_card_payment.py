import sys
import os
from typing import Tuple

# Robust path handling
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(BASE_DIR, "config", "policy.yaml")

# Add project root to path
sys.path.append(BASE_DIR)

from src.shim import ODRLShim
from src.user_config import UserPolicyStore

# Mock HITL Handler
def mock_hitl_handler(message: str) -> Tuple[bool, bool]:
    print(f"[MOCK REMEDY] Received request: {message}")
    print("[MOCK REMEDY] User decision: AUTO-APPROVE (Once)")
    return True, False

# Initialize Shim with Absolute Path
shim = ODRLShim(policy_path=POLICY_PATH, hitl_handler=mock_hitl_handler)

@shim.secure_action(action="charge", asset="http://example.com/asset:card_network")
def charge_card(amount: float, card_type: str, card_number: str):
    print(f"$$$ CHARGED ${amount} on {card_type} ({card_number}) $$$")
    return "Success"

def main():
    print("--- Scenario 1: Visa under Limit ($80) ---")
    try:
        charge_card(amount=80, card_type="Visa", card_number="4111...")
        print("Success: $80 Visa Allowed")
    except Exception as e:
        print(f"Blocked: {e}")

    print("\n--- Scenario 2: Visa over Limit ($150) ---")
    # Expect HITL because it fails Visa constraint, falls through to Catch-All
    try:
        charge_card(amount=150, card_type="Visa", card_number="4111...")
        print("Success: $150 Visa Allowed (via HITL)")
    except Exception as e:
        print(f"Blocked: {e}")

    print("\n--- Scenario 3: Mastercard under Limit ($200) ---")
    # Mastercard limit is 500
    try:
        charge_card(amount=200, card_type="Mastercard", card_number="5555...")
        print("Success: $200 Mastercard Allowed")
    except Exception as e:
        print(f"Blocked: {e}")

    print("\n--- Scenario 4: Unknown Card (Amex) ---")
    # Matches Catch-All -> HITL
    try:
        charge_card(amount=100, card_type="Amex", card_number="3782...")
        print("Success: Amex Allowed (via HITL)")
    except Exception as e:
        print(f"Blocked: {e}")

if __name__ == "__main__":
    main()
