import yaml
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

@dataclass
class AuthorizationRequest:
    assignee: str
    action: str
    target: str
    context: Dict[str, Any]

@dataclass
class Verdict:
    status: str  # PERMIT, PROHIBITION, DUTY_REQUIRED
    reason: str
    duties: List[Dict] = None

from src.user_config import UserPolicyStore

import os

# Robust path handling
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_USER_CONFIG = os.path.join(BASE_DIR, "config", "user_config.json")

class ODRLEvaluator:
    def __init__(self, policy_path: str, user_config_path: str = None):
        self.policy_path = policy_path
        self.user_policy = UserPolicyStore(user_config_path or DEFAULT_USER_CONFIG)
        self.policy = self._load_policy()

    def _load_policy(self) -> Dict:
        with open(self.policy_path, 'r') as f:
            return yaml.safe_load(f)

    def evaluate(self, request: AuthorizationRequest) -> Verdict:
        # 0. Enrich Context with Trust State (Data Plane Lookup)
        # Check Merchant Trust
        if 'merchant' in request.context:
            is_trusted = self.user_policy.is_trusted("merchant", request.context['merchant'])
            request.context['is_trusted_merchant'] = is_trusted
        
        # Check Network Host Trust
        if 'host' in request.context:
            is_trusted = self.user_policy.is_trusted("host", request.context['host'])
            request.context['is_trusted_host'] = is_trusted

        # Check File Trust
        if 'filename' in request.context:
            is_trusted = self.user_policy.is_trusted("file", request.context['filename'])
            request.context['is_trusted_file'] = is_trusted

        # 1. Check Prohibitions (Deny overrides Allow)
        for prohibition in self.policy.get('prohibition', []):
            if self._match_rule(prohibition, request):
                return Verdict(status="PROHIBITION", reason=f"Explicitly prohibited by constraint: {prohibition.get('constraint')}")

        # 2. Check Permissions
        authorized = False
        pending_duties = []
        
        matched_permission = None

        for permission in self.policy.get('permission', []):
            # Check basic match (Target, Action, Assignee)
            if not self._match_basic(permission, request):
                continue

            # Check Constraints
            if not self._check_constraints(permission.get('constraint', []), request.context):
                continue
            
            matched_permission = permission
            authorized = True
            break
        
        if not authorized:
            return Verdict(status="PROHIBITION", reason="No applicable permission found (Default Deny)")

        if not authorized:
            return Verdict(status="PROHIBITION", reason="No applicable permission found (Default Deny)")

        # 3. Check Duties related to the matched permission
        # Refactored: We now prefer Duties defined *inside* the Permission object.
        relevant_duties = self._extract_duties(matched_permission)
        
        for duty in relevant_duties:
             # Check if duty constraints are met
            if self._check_constraints(duty.get('constraint', []), request.context):
                pending_duties.append(duty)

        if pending_duties:
            return Verdict(status="DUTY_REQUIRED", reason="Obligations must be fulfilled", duties=pending_duties)

        return Verdict(status="PERMIT", reason="Permission granted and constraints met")

    def _match_basic(self, rule: Dict, request: AuthorizationRequest) -> bool:
        # Check Action
        if rule.get('action') != request.action:
            return False
        
        # Check Target (Exact match or simple wildcard suffix logic if we wanted, for now exact)
        if rule.get('target') != request.target:
            return False
            
        # Check Assignee (if present in rule)
        if 'assignee' in rule and rule.get('assignee') != request.assignee:
            return False
            
        return True

    def _match_rule(self, rule: Dict, request: AuthorizationRequest) -> bool:
        """Matches a rule (Prohibition) including constraints."""
        if not self._match_basic(rule, request):
            return False
        return self._check_constraints(rule.get('constraint', []), request.context)

    def _check_constraints(self, constraints: List[Dict], context: Dict) -> bool:
        if not constraints:
            return True

        for constraint in constraints:
            name = constraint['name']
            operator = constraint['operator']
            right_operand = constraint['rightOperand']
            
            left_operand = context.get(name)
            
            if left_operand is None:
                return False

            if operator == 'eq':
                if str(left_operand) != str(right_operand):
                    return False
            elif operator == 'lt':
                if not (float(left_operand) < float(right_operand)):
                    return False
            elif operator == 'gt':
                if not (float(left_operand) > float(right_operand)):
                    return False
            elif operator == 'gte':
                if not (float(left_operand) >= float(right_operand)):
                    return False
            elif operator == 'isAnyOf':
                if left_operand not in right_operand:
                    return False
            else:
                print(f"Unknown operator: {operator}")
                return False
        
        return True

    def _extract_duties(self, permission: Dict) -> List[Dict]:
        """Extracts duties from a permission object."""
        return permission.get('duty', [])
