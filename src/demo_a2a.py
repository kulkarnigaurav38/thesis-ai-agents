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

# Mock HITL Handler for automated demo
def mock_hitl_handler(message: str) -> Tuple[bool, bool]:
    print(f"[MOCK REMEDY] Received A2A Consent Request: {message}")
    print("[MOCK REMEDY] User decision: APPROVE")
    return True, False

# Initialize Shim with Absolute Path
shim = ODRLShim(policy_path=POLICY_PATH, hitl_handler=mock_hitl_handler)

class AirlineAgent:
    """The Provider Agent (Asset). Exposures secured tools."""
    
    @shim.secure_action(action="book_flight", asset="http://example.com/asset:airline_agent")
    def book_flight(self, destination: str, price: float):
        print(f"✈️ AIRLINE AGENT: Confirmed booking to {destination} for ${price}.")
        return {"status": "confirmed", "tkt": "12345"}

class TravelAgent:
    """The Consumer Agent (Assignee). Calls the provider."""
    def __init__(self, airline: AirlineAgent):
        self.airline = airline

    def plan_trip(self, destination: str, budget: float):
        print(f"\n🤖 TRAVEL AGENT: Planning trip to {destination} (Budget: ${budget})...")
        try:
            # Agent A calls Agent B
            result = self.airline.book_flight(destination=destination, price=budget)
            print("Travel Agent: Booking Successful!")
        except Exception as e:
            print(f"Travel Agent: Booking Failed - {e}")

def main():
    airline = AirlineAgent()
    agent_007 = TravelAgent(airline)

    # Scenario 1: Economy Class (Under Limit)
    # Policy: Price < 600 -> Permit
    agent_007.plan_trip("London", 400)

    # Scenario 2: First Class (Over Limit)
    # Policy: Catch-All -> HITL
    agent_007.plan_trip("Tokyo", 800)

if __name__ == "__main__":
    main()
