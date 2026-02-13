"""
ODRL Policy Engine for AI Agent Authorization

This module evaluates authorization requests against ODRL policies.
It supports Browser, MCP, and A2A protocols with:
- Prohibition rules (always checked first)
- Permission rules with constraints
- Duty requirements (HITL consent)
- Trust-on-First-Use (TOFU) via user_config.json
"""

import yaml
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse

import os
import sys

# Robust path handling
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from src.user_config import UserPolicyStore

DEFAULT_USER_CONFIG = os.path.join(BASE_DIR, "config", "user_config.json")


@dataclass
class AuthorizationRequest:
    """Incoming authorization request from any agent."""
    assignee: str
    action: str
    target: str
    context: Dict[str, Any]


@dataclass
class Verdict:
    """Decision from the policy engine."""
    status: str  # PERMIT, PROHIBITION, CONSENT_NEEDED, DUTY_REQUIRED
    reason: str
    duties: List[Dict] = None


class ODRLEvaluator:
    """
    ODRL-based Policy Decision Point (PDP).
    
    Evaluates authorization requests against YAML policy rules.
    Order of evaluation:
    1. Prohibitions (deny always wins)
    2. Permissions with constraints
    3. Default deny if no match
    """
    
    def __init__(self, policy_path: str, user_config_path: str = None):
        self.policy_path = policy_path
        self.user_policy = UserPolicyStore(user_config_path or DEFAULT_USER_CONFIG)
        self.policy = self._load_policy()

    def _load_policy(self) -> Dict:
        with open(self.policy_path, 'r') as f:
            return yaml.safe_load(f)

    def evaluate(self, request: AuthorizationRequest) -> Verdict:
        """
        Main evaluation entry point.
        
        Args:
            request: AuthorizationRequest with assignee, action, target, context
            
        Returns:
            Verdict with status and reason
        """
        print(f"[PolicyEngine] Evaluating: {request.action} on {request.target}")
        print(f"[PolicyEngine] Context: {request.context}")
        
        # Enrich context with trust state
        self._enrich_context(request)
        
        # 1. Check Prohibitions FIRST (deny overrides all)
        for prohibition in self.policy.get('prohibition', []):
            if self._match_prohibition(prohibition, request):
                reason = self._format_prohibition_reason(prohibition, request)
                print(f"[PolicyEngine] PROHIBITION: {reason}")
                return Verdict(status="PROHIBITION", reason=reason)
        
        # 2. Special handling for MCP execute actions
        if request.action == "execute":
            return self._evaluate_mcp_action(request)
        
        # 3. Special handling for browser navigation  
        if request.action == "navigate":
            return self._evaluate_navigate_action(request)
        
        # 4. Special handling for A2A delegation
        if request.action == "delegate":
            return self._evaluate_delegate_action(request)
        
        # 5. Special handling for payments
        if request.action == "pay":
            return Verdict(status="CONSENT_NEEDED", reason="Payment requires explicit approval")
        
        # 6. Check Permissions
        for permission in self.policy.get('permission', []):
            if self._match_permission(permission, request):
                # Check for duties
                duties = permission.get('duty', [])
                if duties:
                    return Verdict(
                        status="CONSENT_NEEDED",
                        reason="Action requires user consent",
                        duties=duties
                    )
                return Verdict(status="PERMIT", reason="Permission granted")
        
        # Default deny
        return Verdict(status="PROHIBITION", reason="No applicable permission (default deny)")

    def _enrich_context(self, request: AuthorizationRequest):
        """Add trust state to context based on user_config.json."""
        ctx = request.context
        
        # Check host trust
        if 'host' in ctx:
            ctx['is_trusted_host'] = self.user_policy.is_trusted("host", ctx['host'])
        
        # Check merchant trust  
        if 'merchant' in ctx:
            ctx['is_trusted_merchant'] = self.user_policy.is_trusted("merchant", ctx['merchant'])
        
        # Check agent trust
        if 'sender_agent' in ctx:
            ctx['is_trusted_agent'] = self.user_policy.is_trusted("agent", ctx['sender_agent'])

    def _evaluate_mcp_action(self, request: AuthorizationRequest) -> Verdict:
        """
        Evaluate MCP tool execution requests.
        
        MCP tools are evaluated based on:
        1. Tool name (from context or target)
        2. Arguments (path, command, url, etc.)
        3. Whether operation is within project scope
        """
        ctx = request.context
        tool_name = ctx.get('tool_name', request.target)
        
        # Check for dangerous tools
        dangerous_tools = ['delete_file', 'rm', 'remove', 'unlink', 'eval', 'exec']
        if tool_name.lower() in dangerous_tools:
            return Verdict(
                status="PROHIBITION",
                reason=f"Tool '{tool_name}' is prohibited (dangerous operation)"
            )
        
        # Check for dangerous path access
        if 'path_contains' in ctx:
            return Verdict(
                status="PROHIBITION", 
                reason=f"Access to sensitive path blocked: {ctx['path_contains']}"
            )
        
        if 'path_starts_with' in ctx:
            return Verdict(
                status="PROHIBITION",
                reason=f"Access to system directory blocked: {ctx['path_starts_with']}"
            )
        
        # Check for dangerous commands
        if 'command_contains' in ctx:
            return Verdict(
                status="PROHIBITION",
                reason=f"Dangerous command pattern blocked: {ctx['command_contains']}"
            )
        
        # Check for exfiltration attempts
        if 'url_contains' in ctx:
            return Verdict(
                status="PROHIBITION",
                reason=f"Data exfiltration attempt blocked: {ctx['url_contains']}"
            )
        
        # Safe operations within project
        safe_tools = ['list_directory', 'ls', 'dir', 'find', 'glob', 
                      'search', 'grep', 'ripgrep', 'find_in_files',
                      'read_file', 'view_file']
        
        if tool_name.lower() in safe_tools:
            if ctx.get('is_within_project', False):
                return Verdict(status="PERMIT", reason=f"Tool '{tool_name}' permitted within project")
            elif tool_name.lower() in ['list_directory', 'ls', 'dir', 'search', 'grep']:
                # Read-only operations are generally safe
                return Verdict(status="PERMIT", reason=f"Read-only tool '{tool_name}' permitted")
        
        # Write operations require consent
        write_tools = ['write_file', 'create_file', 'edit_file', 'replace']
        if tool_name.lower() in write_tools:
            if ctx.get('is_within_project', False):
                return Verdict(status="PERMIT", reason=f"Write tool '{tool_name}' permitted within project")
            else:
                return Verdict(status="CONSENT_NEEDED", reason=f"Write operation outside project requires consent")
        
        # Shell commands require consent
        shell_tools = ['run_command', 'execute_command', 'shell', 'bash', 'cmd', 'terminal']
        if tool_name.lower() in shell_tools:
            return Verdict(status="CONSENT_NEEDED", reason="Shell commands require user consent")
        
        # Default: require consent for unknown tools
        return Verdict(status="CONSENT_NEEDED", reason=f"Unknown tool '{tool_name}' requires consent")

    def _evaluate_navigate_action(self, request: AuthorizationRequest) -> Verdict:
        """Evaluate browser navigation requests."""
        ctx = request.context
        url = ctx.get('url', request.target)
        host = ctx.get('host', '')
        
        # Extract host if not provided
        if not host:
            try:
                parsed = urlparse(url)
                host = parsed.netloc
            except:
                host = url
        
        # Normalize host (remove www. prefix for consistent matching)
        normalized_host = host.lower()
        if normalized_host.startswith('www.'):
            normalized_host_no_www = normalized_host[4:]
        else:
            normalized_host_no_www = normalized_host
        
        # CHECK BLACKLIST FIRST (user-defined blocked sites)
        if self.user_policy.is_blocked("host", host) or self.user_policy.is_blocked("host", normalized_host_no_www):
            return Verdict(
                status="PROHIBITION",
                reason=f"Host '{host}' is blacklisted by user"
            )
        
        # Check trusted hosts (whitelist)
        if self.user_policy.is_trusted("host", host) or self.user_policy.is_trusted("host", normalized_host_no_www):
            return Verdict(status="PERMIT", reason=f"Host '{host}' is trusted")
        
        # Check pre-approved hosts
        approved_hosts = ['github.com', 'stackoverflow.com', 'docs.python.org', 
                         'developer.mozilla.org', 'pypi.org', 'npmjs.com']
        if host in approved_hosts or normalized_host_no_www in approved_hosts:
            return Verdict(status="PERMIT", reason=f"Host '{host}' is pre-approved")
        
        # Check for blocked patterns
        blocked_patterns = ['checkout', 'payment', 'billing', 'pay.']
        url_lower = url.lower()
        for pattern in blocked_patterns:
            if pattern in url_lower:
                return Verdict(
                    status="PROHIBITION",
                    reason=f"Navigation to payment/checkout pages blocked"
                )
        
        # Unknown hosts require consent
        return Verdict(status="CONSENT_NEEDED", reason=f"Navigation to '{host}' requires consent")

    def _evaluate_delegate_action(self, request: AuthorizationRequest) -> Verdict:
        """Evaluate A2A delegation requests."""
        ctx = request.context
        sender = ctx.get('sender_agent', 'unknown')
        target_action = request.target
        
        # Check if sender is trusted
        if ctx.get('is_trusted_agent', False):
            return Verdict(status="PERMIT", reason=f"Trusted agent '{sender}' delegation permitted")
        
        # All delegation requires consent
        return Verdict(
            status="CONSENT_NEEDED",
            reason=f"Delegation from '{sender}' to '{target_action}' requires consent"
        )

    def _match_prohibition(self, prohibition: Dict, request: AuthorizationRequest) -> bool:
        """
        Check if a prohibition rule matches the request.
        Uses flexible matching for MCP actions.
        """
        rule_action = prohibition.get('action')
        rule_target = prohibition.get('target', '')
        
        # Match action
        if rule_action and rule_action != request.action:
            return False
        
        # For MCP tools, target is generic but we check tool_name in constraints
        if 'mcp_tool' in rule_target and request.action == 'execute':
            # Check constraints against context
            return self._check_constraints(prohibition.get('constraint', []), request.context)
        
        # For browser, check URL matching
        if 'browser' in rule_target and request.action == 'navigate':
            return self._check_constraints(prohibition.get('constraint', []), request.context)
        
        # Exact target match
        if rule_target and rule_target != request.target:
            return False
        
        # Check constraints
        return self._check_constraints(prohibition.get('constraint', []), request.context)

    def _match_permission(self, permission: Dict, request: AuthorizationRequest) -> bool:
        """Check if a permission rule matches the request."""
        rule_action = permission.get('action')
        rule_target = permission.get('target', '')
        
        if rule_action and rule_action != request.action:
            return False
        
        if rule_target and rule_target != request.target:
            return False
        
        return self._check_constraints(permission.get('constraint', []), request.context)

    def _check_constraints(self, constraints: List[Dict], context: Dict) -> bool:
        """
        Evaluate constraints against request context.
        
        Supported operators:
        - eq: Equal
        - lt, gt, gte, lte: Numeric comparisons
        - isAnyOf: Value in list
        - contains: String contains
        """
        if not constraints:
            return True

        for constraint in constraints:
            name = constraint.get('name', '')
            operator = constraint.get('operator', 'eq')
            right_operand = constraint.get('rightOperand')
            
            left_operand = context.get(name)
            
            # If constraint field not in context, constraint doesn't match
            if left_operand is None:
                return False

            # Evaluate based on operator
            if operator == 'eq':
                if str(left_operand).lower() != str(right_operand).lower():
                    return False
            elif operator == 'neq':
                if str(left_operand).lower() == str(right_operand).lower():
                    return False
            elif operator == 'lt':
                try:
                    if not (float(left_operand) < float(right_operand)):
                        return False
                except (ValueError, TypeError):
                    return False
            elif operator == 'gt':
                try:
                    if not (float(left_operand) > float(right_operand)):
                        return False
                except (ValueError, TypeError):
                    return False
            elif operator == 'gte':
                try:
                    if not (float(left_operand) >= float(right_operand)):
                        return False
                except (ValueError, TypeError):
                    return False
            elif operator == 'lte':
                try:
                    if not (float(left_operand) <= float(right_operand)):
                        return False
                except (ValueError, TypeError):
                    return False
            elif operator == 'isAnyOf':
                if isinstance(right_operand, list):
                    if left_operand not in right_operand:
                        return False
                else:
                    return False
            elif operator == 'contains':
                if str(right_operand).lower() not in str(left_operand).lower():
                    return False
            else:
                print(f"[PolicyEngine] Unknown operator: {operator}")
                return False
        
        return True

    def _format_prohibition_reason(self, prohibition: Dict, request: AuthorizationRequest) -> str:
        """Format a human-readable prohibition reason."""
        constraints = prohibition.get('constraint', [])
        ctx = request.context
        
        if 'path_contains' in ctx:
            return f"Access to sensitive file pattern blocked: {ctx['path_contains']}"
        if 'command_contains' in ctx:
            return f"Dangerous command pattern blocked: {ctx['command_contains']}"
        if 'url_contains' in ctx:
            return f"Data exfiltration attempt blocked: {ctx['url_contains']}"
        
        for c in constraints:
            if c.get('name') == 'tool_name':
                return f"Tool '{c.get('rightOperand')}' is explicitly prohibited"
        
        return f"Action prohibited by policy rule"
