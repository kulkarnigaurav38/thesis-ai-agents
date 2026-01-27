import json
import os
from typing import Dict, List, Any

class UserPolicyStore:
    def __init__(self, config_path: str = "config/user_config.json"):
        self.config_path = config_path
        self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            self.data = {"trusted": {}}
            self._save_config()
        else:
            with open(self.config_path, 'r') as f:
                self.data = json.load(f)

    def _save_config(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(self.data, f, indent=2)

    def add_trust(self, category: str, value: str):
        """Adds a value to the trusted list for a category (e.g., merchant, domain)."""
        if "trusted" not in self.data:
            self.data["trusted"] = {}
            
        if category not in self.data["trusted"]:
            self.data["trusted"][category] = []
        
        if value not in self.data["trusted"][category]:
            self.data["trusted"][category].append(value)
            self._save_config()

    def is_trusted(self, category: str, value: str) -> bool:
        """Checks if a value is in the trusted list."""
        trusted_list = self.data.get("trusted", {}).get(category, [])
        return value in trusted_list

    def revoke_trust(self, category: str, value: str):
        """Removes a value from the trusted list."""
        if category in self.data.get("trusted", {}) and value in self.data["trusted"][category]:
            self.data["trusted"][category].remove(value)
            self._save_config()

    def get_all_trusts(self) -> Dict[str, List[str]]:
        """Returns all trusted entities."""
        return self.data.get("trusted", {})
