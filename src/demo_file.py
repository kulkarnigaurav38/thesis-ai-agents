import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.shim import ODRLShim

shim = ODRLShim("config/policy.yaml")

@shim.secure_action(action="read", asset="http://example.com/asset:filesystem")
def read_file(filename):
    print(f"Reading {filename}...")
    return "File Content"

def main():
    print("--- File Handling Demo ---")

    # 1. Allowed File
    try:
        read_file(filename="README.md")
        print("Success: Read README.md")
    except PermissionError as e:
        print(f"Failed: {e}")

    # 2. Blocked File
    try:
        read_file(filename="secret.txt")
        print("Success: Read secret.txt")
    except PermissionError as e:
        print(f"Blocked: {e}")

if __name__ == "__main__":
    main()
