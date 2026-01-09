from typing import Callable, Any, Dict, Tuple
from src.policy_engine import ODRLEvaluator, AuthorizationRequest, Verdict
from src.audit_log import AuditLogger, AuditEvent

import os

# Robust path handling
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "audit.db")

class ODRLShim:
    def __init__(self, policy_path: str, db_path: str = None, hitl_handler: Callable[[str], Tuple[bool, bool]] = None):
        self.evaluator = ODRLEvaluator(policy_path)
        self.audit_logger = AuditLogger(db_path or DEFAULT_DB_PATH)
        self.hitl_handler = hitl_handler or self._default_hitl_handler

    def _default_hitl_handler(self, message: str) -> Tuple[bool, bool]:
        print(f"\n[REMEDY REQUIRED] {message}")
        print("Options: (y)es, (n)o, (a)lways")
        user_input = input("Grant Consent? ").lower()
        if user_input == 'a':
            return True, True
        elif user_input == 'y':
            return True, False
        return False, False

    def secure_action(self, action: str, asset: str, assignee: str = "user:agent-007"):
        """Decorator to secure a function acting as an ODRL Action on an Asset."""
        def decorator(func: Callable):
            def wrapper(*args, **kwargs):
                # 1. Create Context (Map args/kwargs to context)
                context = kwargs.copy()

                # 2. Create Authorization Request
                request = AuthorizationRequest(
                    assignee=assignee,
                    action=action,
                    target=asset,
                    context=context
                )

                # 3. Evaluate Policy (Checks User Policy Store internally)
                verdict = self.evaluator.evaluate(request)

                # 4. Log "Attempt"
                self._log_event(request, verdict, "EVALUATED")

                # 5. Enforce Verdict
                if verdict.status == "PERMIT":
                    return func(*args, **kwargs)
                
                elif verdict.status == "DUTY_REQUIRED":
                    # Handle Duties (HITL)
                    duty_names = [d.get('action') for d in verdict.duties]
                    reason = f"Duties: {duty_names}. Context: {context}"
                    
                    approved, allow_always = self.hitl_handler(reason)
                    
                    if approved:
                        # Handle Allow Always (Trust on First Use)
                        if allow_always:
                            self._handle_allow_always(context)

                        # Log fulfillment
                        self._log_event(request, Verdict(status="PERMIT", reason="Duty Fulfilled (Consent Granted)"), "FULFILLED")
                        return func(*args, **kwargs)
                    else:
                         # Log failure
                        self._log_event(request, Verdict(status="PROHIBITION", reason="Duty Failed (Consent Denied)"), "DENIED")
                        raise PermissionError(f"Action denied. Failed to fulfill duties: {duty_names}")

                else: # PROHIBITION
                    self._log_event(request, verdict, "DENIED")
                    raise PermissionError(f"Action prohibited: {verdict.reason}")

            return wrapper
        return decorator

    def _handle_allow_always(self, context: Dict[str, Any]):
        """Updates User Policy Store based on context keys."""
        if 'merchant' in context:
            self.evaluator.user_policy.add_trust("merchant", context['merchant'])
            print(f"[Shim] Added '{context['merchant']}' to Trusted Merchants.")
        
        if 'host' in context:
            self.evaluator.user_policy.add_trust("host", context['host'])
            print(f"[Shim] Added '{context['host']}' to Trusted Hosts.")
            
        if 'url' in context:
             # Basic host extraction or just trust the exact URL (MVP: simple)
             # For now, let's assume if 'url' provided, we trust it as a 'host' if it looks like one, or skip
             # Better to define trust categories clearly. 
             pass

        if 'filename' in context:
            self.evaluator.user_policy.add_trust("file", context['filename'])
            print(f"[Shim] Added '{context['filename']}' to Trusted Files.")

    def _log_event(self, request: AuthorizationRequest, verdict: Verdict, stage: str):
        self.audit_logger.log_event(AuditEvent(
            agent_id=request.assignee,
            tool_name=f"{request.action} on {request.target}",
            parameters=request.context,
            decision=verdict.status,
            justification=f"[{stage}] {verdict.reason}"
        ))
