import unittest
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.shim import ODRLShim

class TestConfusedDeputy(unittest.TestCase):
    def setUp(self):
        self.shim = ODRLShim("config/policy.yaml")

    def test_browser_navigation_misuse(self):
        print("\n--- Testing Confused Deputy: Malicious Navigation ---")
        
        # 1. Agent navigates to legitimate site (Allowed)
        try:
            # Action="navigate", Asset="browser"
            @self.shim.secure_action(action="navigate", asset="http://example.com/asset:browser")
            def navigate(url):
                return "Navigated"
            
            result = navigate(url="google.com")
            print(f"Initial navigation: {result}")
        except Exception as e:
            self.fail(f"Initial navigation failed: {e}")

        # 2. Agent is tricked into navigating to malicious site (Blocked)
        print("Agent attempts secondary navigation to malicious.com...")
        try:
            navigate(url="malicious.com")
            self.fail("Malicious navigation was ALLOWED (Should be BLOCKED)")
        except PermissionError as e:
            print(f"Secondary navigation blocked: {e}")
            self.assertTrue("prohibited" in str(e).lower() or "denied" in str(e).lower())

if __name__ == '__main__':
    unittest.main()
