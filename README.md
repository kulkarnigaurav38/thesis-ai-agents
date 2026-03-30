# General Security Shim for AI Agents

A policy-enforcing middleware shim that intercepts and authorizes requests from AI agents before any action is taken. It supports three agent communication protocols: **MCP** (Model Context Protocol — local tool calls), **A2A** (Agent-to-Agent delegation), and **Browser** (DOM navigation via a Chrome extension).

---

## System Architecture

```
AI Agent (MCP / A2A / Browser Extension)
            |
            ▼
    Shim Service  :8000       ← normalizes and intercepts all agent actions
            |
            ▼
    Policy Engine :5000       ← evaluates requests against policy rules
            |
            ▼
  PERMIT / PROHIBITION / CONSENT_NEEDED
            |
     (if CONSENT_NEEDED)
            ▼
    Browser Extension         ← presents approval UI to the user (HITL)
            |
            ▼
    PERMIT or PROHIBITION
```

**Files created automatically at runtime** (not committed to the repo):
- `audit.db` — SQLite audit trail of all decisions (created in project root)
- `config/user_config.json` — persists user trust/block decisions across sessions

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10 or later |
| pip | bundled with Python |
| Google Chrome | any recent version (for browser extension only) |

No Docker is required to run the core system. The `Dockerfile` and `docker-compose.yml` are included for containerized deployment but are not needed for local evaluation.

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
pip install flask flask-cors pydantic requests pyyaml
```

---

## Running the System

The core system requires **two servers running simultaneously**. Open two terminal windows.

### Terminal 1 — Policy Engine (port 5000)

```bash
python src/server.py
```

Expected output:
```
 * Running on http://127.0.0.1:5000
```

### Terminal 2 — Shim Service (port 8000)

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
  - POST /authorize  - Generic authorization
  - POST /mcp        - MCP JSON-RPC proxy
  - GET  /demo       - Visual testing dashboard
  - GET  /health     - Health check
============================================================
Listening on: http://127.0.0.1:8000
============================================================
```

---

## Quick Verification — Demo Dashboard

With both servers running, open your browser and go to:

```
http://localhost:8000/demo
```

This opens an interactive dashboard to test the shim with pre-configured scenarios:

| Button | Protocol | Expected result |
|---|---|---|
| List Directory (Safe) | MCP | PERMIT |
| Read /etc/passwd | MCP | PROHIBITION |
| Read SSH Key | MCP | PROHIBITION |
| `rm -rf /` command | MCP | PROHIBITION |
| GitHub | Browser | PERMIT |
| Unknown site | Browser | CONSENT_NEEDED → user popup |
| Delegate to unknown agent | A2A | CONSENT_NEEDED |

---

## Installing the Browser Extension (Chrome)

The browser extension acts as the **Policy Enforcement Point (PEP)** for browser navigation. It intercepts navigation events, checks them against the Policy Engine, and presents a consent UI when needed.

1. Open Chrome → navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle, top-right corner)
3. Click **Load unpacked**
4. Select the folder: `src/browser_extension/`
5. The "Agent Authorization PEP" extension icon appears in the toolbar

The extension communicates with:
- **Port 5000** — to poll for pending HITL consent requests
- **Port 8000** — to authorize intercepted browser navigation actions

---

## Policy Configuration

Policies are defined in `config/policy.json` as a flat `rules` array. Each rule has three fields:

| Field | Values | Meaning |
|---|---|---|
| `type` | `"allow"` or `"block"` | Decision when a match is found |
| `contains` | array of strings | If any string appears in the request target, the rule fires |
| `description` | string | Human-readable label (shown in the extension UI) |

Rules are evaluated top-to-bottom. The first match wins. If no rule matches, the request is escalated to the user for consent (`CONSENT_NEEDED`).

Example `config/policy.json`:
```json
{
  "rules": [
    {
      "type": "allow",
      "contains": ["github.com", "stackoverflow.com"],
      "description": "Allow developer resources"
    },
    {
      "type": "block",
      "contains": ["/etc/passwd", ".ssh", "credentials"],
      "description": "Block sensitive system files"
    },
    {
      "type": "block",
      "contains": ["malicious.com", "phishing-example.com"],
      "description": "Block known malicious sites"
    }
  ]
}
```

User trust decisions made via the browser extension's "Trust Always" button are persisted separately in `config/user_config.json` and take precedence over the default policy.

---

## Running the Tests

The test suite uses Python's built-in `unittest` module. Both tests require **both servers to be running** (port 5000 and port 8000).

```bash
# From the project root

# Test 1: Confused Deputy attack scenario
python -m pytest tests/test_confused_deputy.py -v

# Test 2: Indirect Prompt Injection scenario
python -m pytest tests/test_prompt_injection.py -v
```

Alternatively, use the PowerShell integration test which sends real HTTP requests to the live endpoints:

```powershell
# Windows PowerShell (both servers must be running)
.\tests\test_shim.ps1
```

The PowerShell test hits `localhost:8000` directly and verifies that safe requests are permitted and dangerous ones (e.g., reading `/etc/passwd`) are blocked with a `403` response.

---

## Evaluation

> **Note:** The `evaluation/` directory is excluded from the repository via `.gitignore` (output files are large and regenerable). To reproduce the evaluation, use the scripts below with both servers running.

```bash
# Step 1: Run the 150-case evaluation (50 per protocol: MCP, A2A, Browser)
python evaluation/evaluate_shim.py
# Produces: evaluation/evaluation_results.csv

# Step 2: Generate thesis figures and summary table
python evaluation/generate_graphs.py
# Produces in evaluation/graphs/:
#   confusion_matrices.png
#   latency_boxplot.png
#   consent_fatigue.png
#   summary_metrics.csv
```

---

## Project Structure

```
thesis-ai-agents/
├── config/
│   └── policy.json              # Policy rules (JSON, editable)
├── src/
│   ├── server.py                # Policy Engine / PDP (port 5000)
│   ├── shim_service.py          # Shim middleware / PEP (port 8000)
│   ├── policy_engine.py         # ODRL rule evaluator
│   ├── audit_logger.py          # SQLite-backed audit trail
│   ├── user_config.py           # Runtime trust/block persistence
│   └── browser_extension/       # Chrome extension (load unpacked)
│       ├── manifest.json
│       ├── background.js        # Service worker: navigation interception
│       ├── checking.html/js     # Policy check loading screen
│       ├── popup.html/js        # Toolbar popup UI
│       └── policies.html/js     # Policy rule editor UI
├── evaluation/                  # (gitignored — regenerable)
│   ├── evaluate_shim.py         # 150-case automated evaluation
│   ├── evaluation_dataset.json  # Test cases per protocol
│   ├── evaluation_results.csv   # Raw results
│   └── generate_graphs.py       # Thesis figure generator
└── tests/
    ├── test_confused_deputy.py  # Unit test: confused deputy scenario
    ├── test_prompt_injection.py # Unit test: indirect prompt injection
    └── test_shim.ps1            # Integration test (PowerShell, hits port 8000)
```

---

## Appendix Reference

```
Release URL : https://github.com/kulkarnigaurav38/thesis-ai-agents/releases/tag/v1.0.0
SHA-256     : 03a4452b397affa171bc3a8ebf69f1b44538c04f1b2c84de0d499811da5c486d0
```

To verify integrity after downloading the source zip:
```powershell
# Windows PowerShell
(Get-FileHash thesis-ai-agents-1.0.0.zip -Algorithm SHA256).Hash

# macOS / Linux
sha256sum thesis-ai-agents-1.0.0.zip
```
