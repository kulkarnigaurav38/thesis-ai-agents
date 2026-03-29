# General Security Shim for AI Agents

A policy-enforcing middleware shim that sits between AI agents and their execution environments. It intercepts and authorizes requests from three agent protocols — **MCP** (Model Context Protocol / local tools), **A2A** (Agent-to-Agent delegation), and **Browser DOM** — before any action is taken.

---

## System Architecture

```
AI Agent (MCP / A2A / Browser)
        |
        ▼
  Shim Service  (port 5001)   ← intercepts all agent actions
        |
        ▼
  Policy Engine (port 5000)   ← evaluates against policy rules
        |
        ▼
  Decision: PERMIT / PROHIBITION / CONSENT_NEEDED
        |
   (if CONSENT_NEEDED)
        ▼
  Browser Extension           ← user approves / denies in real time
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10 or later |
| pip | bundled with Python |
| Google Chrome | any recent version (for browser extension) |

No Docker required to run the core system.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/kulkarnigaurav38/thesis-ai-agents.git
cd thesis-ai-agents

# 2. Create and activate a virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install flask flask-cors pydantic requests
```

---

## Running the System

The system has **two servers** that must both be running. Open two terminal windows.

### Terminal 1 — Policy Engine (port 5000)

```bash
python src/server.py
```

Expected output:
```
 * Running on http://127.0.0.1:5000
```

### Terminal 2 — Shim Service (port 5001)

```bash
python src/shim_service.py
```

Expected output:
```
============================================================
General Security Shim
============================================================
Policy Engine: http://localhost:5000/check
Endpoints:
  POST /authorize   - Generic authorization (all protocols)
  POST /mcp         - MCP JSON-RPC proxy
  GET  /demo        - Visual test dashboard
 * Running on http://127.0.0.1:5001
```

---

## Quick Verification (Demo Dashboard)

With both servers running, open your browser and go to:

```
http://localhost:5001/demo
```

This opens an interactive dashboard where you can click buttons to test:
- ✅ Safe MCP tool calls (list directory, search)
- 🚫 Blocked attacks (read `/etc/passwd`, `rm -rf /`, SSH key theft)
- 🌐 Browser navigation (trusted sites vs malicious URLs)
- 🤖 A2A agent delegation

---

## Installing the Browser Extension (Chrome)

1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle, top right)
3. Click **Load unpacked**
4. Select the `src/browser_extension/` folder
5. The shield icon (🛡️) will appear in your toolbar

The extension intercepts navigation events and checks them against the Policy Engine in real time. If a request needs user consent, a popup appears for approval/denial.

---

## Policy Configuration

Policies are defined in `config/policy.json` as a rules array:

```json
{
  "rules": [
    {
      "type": "PERMIT",
      "contains": "github.com",
      "description": "Trust GitHub"
    },
    {
      "type": "PROHIBITION",
      "contains": "/etc/passwd",
      "description": "Block sensitive system files"
    },
    {
      "type": "CONSENT_NEEDED",
      "contains": "unknown-site.com",
      "description": "Ask user before visiting unknown sites"
    }
  ]
}
```

You can also edit rules live through the browser extension's **Policies** tab (accessible from the toolbar icon).

---

## Running the Evaluation

The evaluation tests 150 cases (50 per protocol) against known-malicious and benign inputs.

```bash
# Run evaluation (both servers must be running)
python evaluation/evaluate_shim.py

# Re-generate graphs and summary table from results
cd evaluation
python generate_graphs.py
```

Outputs are saved to `evaluation/graphs/`:
- `confusion_matrices.png`
- `latency_boxplot.png`
- `consent_fatigue.png`
- `summary_metrics.csv` — paste into Word/LaTeX as a table

---

## Running the Tests

```bash
# Unit tests
python -m pytest tests/test_confused_deputy.py tests/test_prompt_injection.py -v

# PowerShell integration test (Windows)
.\tests\test_shim.ps1
```

---

## Project Structure

```
thesis-ai-agents/
├── config/
│   └── policy.json          # Policy rules (editable)
├── src/
│   ├── server.py            # Policy Engine (port 5000)
│   ├── shim_service.py      # Shim middleware (port 5001)
│   ├── policy_engine.py     # ODRL-inspired rule evaluator
│   ├── audit_logger.py      # SQLite audit trail
│   ├── user_config.py       # Runtime policy persistence
│   └── browser_extension/   # Chrome extension (load unpacked)
├── evaluation/
│   ├── evaluate_shim.py     # Runs 150-case evaluation
│   ├── evaluation_dataset.json
│   ├── evaluation_results.csv
│   └── generate_graphs.py   # Produces thesis figures
└── tests/
    ├── test_confused_deputy.py
    └── test_prompt_injection.py
```

---

## Appendix Reference

```
Release URL : https://github.com/kulkarnigaurav38/thesis-ai-agents/releases/tag/v1.0.0
SHA-256     : 01d13cc4e26e711d9ed4c8c399db3e2ca753c897b6c5e693d258e4bbc0d342b2d
```

To verify integrity after downloading the source zip:
```bash
# Windows PowerShell
(Get-FileHash thesis-ai-agents-1.0.0.zip -Algorithm SHA256).Hash

# macOS / Linux
sha256sum thesis-ai-agents-1.0.0.zip
```
