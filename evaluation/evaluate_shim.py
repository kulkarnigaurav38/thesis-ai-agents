"""
evaluate_shim.py — DSR Evaluation Runner

Loads evaluation_dataset.json (with manually-curated ground truth labels)
and evaluates each request through the actual Shim normalizer + Policy Engine.

Uses direct Python imports (no HTTP) to avoid 60s blocking on
CONSENT_NEEDED while testing the exact same code paths.

Latency is measured around evaluator.evaluate() ONLY — not normalization.

Classification scheme:
  TP:             malicious + actual is not PERMIT (blocked or escalated)
  TN:             benign + actual is PERMIT
  FP:             benign + actual is not PERMIT (over-blocked)
  FN:             malicious + actual is PERMIT (security failure)
  CORRECT_HITL:   expected was hitl + actual is CONSENT_NEEDED

Outputs evaluation_results.csv with per-request metrics.
"""

import json
import csv
import time
import sys
import os

# Add project root to path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from src.policy_engine import PolicyEvaluator, AuthorizationRequest
from src.shim_service import IntentNormalizer, Protocol

# =============================================================================
# Configuration
# =============================================================================

POLICY_PATH = os.path.join(PROJECT_ROOT, "config", "policy.json")
DATASET_PATH = os.path.join(os.path.dirname(__file__), "evaluation_dataset.json")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "evaluation_results.csv")

# Verdict mapping: PolicyEngine status → evaluation label
VERDICT_MAP = {"PERMIT": "allow", "PROHIBITION": "block", "CONSENT_NEEDED": "hitl"}
# Reverse mapping for "correct" comparison
EXPECTED_MAP = {"allow": "PERMIT", "block": "PROHIBITION", "hitl": "CONSENT_NEEDED"}


def map_verdict(status: str) -> str:
    """Map PolicyEngine verdict to evaluation action."""
    return VERDICT_MAP.get(status, "block")  # Fail-safe: unknown → block


def classify(expected: str, actual: str, is_malicious: bool) -> str:
    """
    Classify the result into TP/TN/FP/FN/CORRECT_HITL.

    CORRECT_HITL: expected was "hitl" AND actual is "hitl".
      These are cases where CONSENT_NEEDED is the deliberately correct
      answer (e.g. unknown A2A agents). Tracked separately so they
      don't inflate FP counts.

    Binary (security-focused):
      TP: Malicious + actual != allow (blocked or escalated to human)
      TN: Benign + actual == allow
      FP: Benign + actual != allow (over-blocked)
      FN: Malicious + actual == allow (security failure — worst case)
    """
    # HITL-specific: expected was hitl and system correctly escalated
    if expected == "hitl" and actual == "hitl":
        return "CORRECT_HITL"

    # Binary classification
    if is_malicious:
        if actual != "allow":
            return "TP"   # Correctly caught
        else:
            return "FN"   # Missed — malicious got through
    else:
        if actual == "allow":
            return "TN"   # Correctly allowed
        else:
            return "FP"   # Over-blocked benign request


def run_evaluation():
    """Run the full evaluation pipeline."""
    # Load evaluator and normalizer
    print(f"[Eval] Loading policy from: {POLICY_PATH}")
    evaluator = PolicyEvaluator(POLICY_PATH)
    normalizer = IntentNormalizer()

    # Load dataset (manually curated — DO NOT re-derive expected values)
    print(f"[Eval] Loading dataset from: {DATASET_PATH}")
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    print(f"[Eval] Evaluating {len(dataset)} requests...\n")

    results = []
    counters = {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "CORRECT_HITL": 0}
    total_latency = 0

    for entry in dataset:
        entry_id = entry["id"]
        vector = entry["vector"]
        is_malicious = entry["is_malicious"]
        expected = entry["expected_shim_action"]  # from curated dataset
        protocol_payload = entry["protocol_payload"]

        try:
            # Step 1: Normalize (outside latency measurement)
            protocol = Protocol(protocol_payload["protocol"])
            payload = protocol_payload["payload"]
            intent = normalizer.normalize(protocol, payload)

            # Step 2: Build auth request
            auth_req = AuthorizationRequest(
                target=intent.target,
                details=intent.details or {}
            )

            # Step 3: Measure ONLY evaluator.evaluate() latency
            start = time.perf_counter()
            verdict = evaluator.evaluate(auth_req)
            end = time.perf_counter()
            latency_ms = (end - start) * 1000

            # Step 4: Map and classify
            actual = map_verdict(verdict.status)
            correct = (expected == actual)
            classification = classify(expected, actual, is_malicious)

            counters[classification] += 1
            total_latency += latency_ms

            results.append({
                "id": entry_id,
                "vector": vector,
                "description": entry["description"],
                "is_malicious": is_malicious,
                "attack_type": entry.get("attack_type", ""),
                "expected": expected,
                "actual": actual,
                "verdict_reason": verdict.reason,
                "correct": correct,
                "classification": classification,
                "latency_ms": round(latency_ms, 3)
            })

        except Exception as e:
            classification = "FN" if is_malicious else "FP"
            results.append({
                "id": entry_id,
                "vector": vector,
                "description": entry["description"],
                "is_malicious": is_malicious,
                "attack_type": entry.get("attack_type", ""),
                "expected": expected,
                "actual": "error",
                "verdict_reason": f"ERROR: {str(e)}",
                "correct": False,
                "classification": classification,
                "latency_ms": 0
            })
            counters[classification] += 1
            print(f"  [ERROR] {entry_id}: {e}")

    # ==========================================================================
    # Write CSV
    # ==========================================================================

    fieldnames = ["id", "vector", "description", "is_malicious", "attack_type",
                  "expected", "actual", "verdict_reason", "correct",
                  "classification", "latency_ms"]

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[Eval] Results saved to: {OUTPUT_PATH}")

    # ==========================================================================
    # Print Summary
    # ==========================================================================

    total = len(results)
    correct_count = sum(1 for r in results if r["correct"])
    avg_latency = total_latency / total if total > 0 else 0

    tp = counters["TP"]
    tn = counters["TN"]
    fp = counters["FP"]
    fn = counters["FN"]
    c_hitl = counters["CORRECT_HITL"]

    # Binary metrics (TP/TN/FP/FN only — excludes CORRECT_HITL)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    binary_total = tp + tn + fp + fn
    accuracy_binary = ((tp + tn) / binary_total) * 100 if binary_total > 0 else 0
    accuracy_incl_hitl = (correct_count / total) * 100 if total > 0 else 0

    print(f"\n{'='*60}")
    print(f"  EVALUATION SUMMARY")
    print(f"{'='*60}")
    print(f"  Total Requests:      {total}")
    print(f"  Correct (strict):    {correct_count}/{total} ({accuracy_incl_hitl:.1f}%)")
    print(f"  Binary Accuracy:     {tp+tn}/{binary_total} ({accuracy_binary:.1f}%) [excl. CORRECT_HITL entries]")
    print(f"  Avg Latency:         {avg_latency:.3f} ms")
    print(f"")
    print(f"  Confusion Matrix:")
    print(f"    TP (malicious caught):    {tp}")
    print(f"    TN (benign allowed):      {tn}")
    print(f"    FP (benign over-blocked): {fp}")
    print(f"    FN (malicious missed):    {fn}")
    print(f"    CORRECT_HITL:             {c_hitl}")
    print(f"")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall:    {recall:.3f}")
    print(f"  F1 Score:  {f1:.3f}")
    print(f"{'='*60}")

    # Per-vector breakdown
    for vec in ["MCP", "A2A", "WEB"]:
        vec_results = [r for r in results if r["vector"] == vec]
        vec_correct = sum(1 for r in vec_results if r["correct"])
        vec_total = len(vec_results)
        vec_acc = (vec_correct / vec_total * 100) if vec_total > 0 else 0
        vec_lat = sum(r["latency_ms"] for r in vec_results) / vec_total if vec_total > 0 else 0
        print(f"  {vec}: {vec_correct}/{vec_total} correct ({vec_acc:.1f}%), avg latency {vec_lat:.3f}ms")

    # Latency percentiles
    latencies = sorted([r["latency_ms"] for r in results if r["latency_ms"] > 0])
    if latencies:
        p50 = latencies[len(latencies) // 2]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]
        print(f"\n  Latency Percentiles: P50={p50:.3f}ms  P95={p95:.3f}ms  P99={p99:.3f}ms")

    print()


if __name__ == "__main__":
    run_evaluation()
