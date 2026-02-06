# AGENTS.md

This file documents the agent-based development approach used to build ClawGuard and provides guidance for future parallel agent work.

## Build Strategy

ClawGuard was built using 7 parallel agents working on independent workstreams. The project structure enables this by having clear service boundaries.

## Agent Workstreams

### Foundation Layer (Run First)
These must complete before dependent agents can start:

| Agent | Directory | Output |
|-------|-----------|--------|
| **Project Structure** | `/` | docker-compose.yml, package.json files, Dockerfiles |
| **Database Schema** | `backend/migrations/` | Knex migrations for all tables |
| **Model Service** | `model-service/` | FastAPI app with /analyze endpoint |
| **Frontend Base** | `frontend/src/` | Vite config, auth context, layout, routing |

### Dashboard Layer (Run After Foundation)
These can run in parallel once frontend base exists:

| Agent | File | Dependencies |
|-------|------|--------------|
| **Dashboard** | `frontend/src/pages/Dashboard.jsx` | AuthContext, api.js, socket.io |
| **Analytics** | `frontend/src/pages/Analytics.jsx` | api.js, recharts |
| **Settings** | `frontend/src/pages/Settings.jsx` | api.js, react-query |
| **Alerts** | `frontend/src/pages/Alerts.jsx` | AuthContext, api.js, socket.io |

## Task Dependencies

```
[1] Project Structure
 ├── [2] Model Service
 ├── [3] Database Schema ──┐
 ├── [4] Backend Core ─────┼── [5] Firewall API
 │                         │   [6] Analytics API
 │                         │   [7] WebSocket
 │                         └── [8] Alerts API
 └── [9] Frontend Base
      ├── [10] Dashboard ──── requires WebSocket
      ├── [11] Analytics ──── requires Analytics API
      ├── [12] Settings ───── requires Firewall API
      └── [13] Alerts ─────── requires Alerts API, WebSocket
```

## Parallelization Opportunities

### Maximum Parallelism Points
1. **After project structure**: Model service, DB schema, and frontend base can all run simultaneously
2. **After frontend base + backend**: All 4 dashboard pages can run simultaneously
3. **Independent services**: Backend API routes can be developed in parallel if schema exists

### Agent Boundaries
Each agent should own a complete vertical slice:
- Model service agent: `model-service/*` (Python, no JS dependencies)
- Schema agent: `backend/migrations/*`, `backend/knexfile.js`, `backend/src/models/`
- Frontend page agents: Single page file + App.jsx import update

## Agent Prompts Used

### Model Service Agent
```
Create Python FastAPI service in model-service/ with:
- /health and /analyze endpoints
- Load HuggingFace model (openai/gpt-oss-safeguard-120b)
- Return prompt_injection_score, jailbreak_score, pii_score (0-1)
- Supports 20b (default) and 120b safeguard model variants
```

### Database Schema Agent
```
Create Knex migrations in backend/migrations/ for:
- users (id, email, password_hash, role)
- request_logs (timestamp, input_text, threat_scores, action, latency_ms)
- alerts (name, type, config, enabled)
- alert_triggers (alert_id, triggered_at, data, acknowledged)
- firewall_config (thresholds and actions per threat type)
```

### Frontend Page Agent Template
```
Create frontend/src/pages/{Page}.jsx with:
- React Query for data fetching from /api/{endpoint}
- Socket.IO for real-time updates (if needed)
- Tailwind dark theme (text-dark-100, card class, bg-dark-700)
- Update App.jsx to import the new component
```

## Conflict Avoidance

### Files Multiple Agents Touch
- `frontend/src/App.jsx` - Each page agent adds an import; coordinate or have one agent do all imports
- `frontend/src/main.jsx` - Usually only touched by base agent
- `backend/src/index.js` - Route registration; base backend agent should handle

### Safe Parallel Zones
- `model-service/*` - Completely isolated
- `backend/migrations/*` - Timestamped files, no conflicts
- `backend/src/routes/*` - One file per route, independent
- `frontend/src/pages/*` - One file per page, independent

## Performance Results

Original build used 7 agents across 2 waves:
- **Wave 1** (foundation): 3 agents in parallel
- **Wave 2** (dashboard): 4 agents in parallel
- **Total tasks**: 14
- **Total files**: ~50
- **Total lines**: ~4000

Sequential build would require completing each layer before starting the next. Parallel execution reduced wall-clock time significantly.

---

## Security Hardening Phase

### Assessment Date: 2026-02-05

Security audit revealed critical gaps. See `docs/SECURITY_ASSESSMENT.md` for full analysis.

### Security Task Dependencies

```
[P0] Critical - Must Fix
 ├── [1.1] Output Filtering Layer ─────┐
 ├── [1.2] Secret Detection & Masking ─┼── Run in parallel
 └── [1.3] Egress Monitoring ──────────┘

[P1] High - Should Fix (after P0)
 ├── [2.1] Semantic Similarity Detection ── model-service (isolated)
 ├── [2.2] Session Threat Tracking ──────── backend (needs Redis)
 ├── [2.3] International PII ────────────── model-service (isolated)
 └── [2.4] Admin Audit Logging ──────────── backend (new table)

[P2] Medium (after P1) ✅ COMPLETE
 ├── [3.1] User-Based Rate Limiting ✅
 ├── [3.2] Request Fingerprinting ✅
 └── [3.3] Enhanced Alert Rules ✅

[P3] Low (after P2)
 ├── [4.1] Explainable Scores
 ├── [4.2] Data Retention Automation
 └── [4.3] ML Evasion Detection
```

### Security Agent Workstreams

| Agent | Task | Files | Dependencies | Status |
|-------|------|-------|--------------|--------|
| **Output Filter** | 1.1 | `model-service/main.py`, `backend/src/services/outputFilter.js` | None | ✅ |
| **Secret Masker** | 1.2 | `backend/src/utils/secretMasker.js`, `backend/src/routes/firewall.js` | None | ✅ |
| **Egress Monitor** | 1.3 | `backend/src/middleware/egressMonitor.js` | Task 1.2 | ✅ |
| **Semantic Detector** | 2.1 | `model-service/main.py` | None (isolated) | ✅ |
| **Session Tracker** | 2.2 | `backend/src/services/sessionTracker.js` | Redis | ✅ |
| **PII Extender** | 2.3 | `model-service/main.py` | None (isolated) | ✅ |
| **Audit Logger** | 2.4 | `backend/src/middleware/auditLog.js`, migration | None | ✅ |
| **Rate Limiter** | 3.1 | `backend/src/middleware/rateLimiter.js` | None | ✅ |
| **Fingerprinter** | 3.2 | `backend/src/services/fingerprinter.js` | Redis | ✅ |
| **Alert Evaluator** | 3.3 | `backend/src/services/alertEvaluator.js`, `backend/src/routes/alerts.js` | None | ✅ |

### Security Agent Prompts

#### Output Filter Agent
```
Add output filtering to ClawGuard:

1. model-service/main.py:
   - Add POST /analyze-output endpoint
   - Detect PII in LLM responses (reuse existing patterns)
   - Detect system prompt disclosure patterns
   - Return: { safe: bool, detected: [], sanitized_output: string }

2. backend/src/services/outputFilter.js:
   - Call model-service /analyze-output before returning LLM responses
   - Log output analysis results
   - Block or sanitize based on config

3. Update firewall_config to include output_actions
```

#### Secret Masker Agent
```
Add secret detection and masking:

1. Create backend/src/utils/secretMasker.js:
   - Detect patterns: API keys (sk-, pk-, api_), AWS (AKIA),
     GitHub (ghp_), JWT (eyJ), high-entropy strings
   - mask(text) returns text with [REDACTED:type] replacements
   - Export pattern list for testing

2. Update backend/src/routes/firewall.js:
   - Import secretMasker
   - Mask input_text before database logging
   - Mask in Redis pub/sub events

3. Add unit tests for all patterns
```

#### Session Tracker Agent
```
Add session-level threat tracking:

1. Create backend/src/services/sessionTracker.js:
   - Track cumulative threat scores in Redis
   - Key: session:{fingerprint} with 30min TTL
   - Accumulate scores from each request
   - Decay scores with half-life of 30 minutes
   - Alert when cumulative > 2.0

2. Create session fingerprint from:
   - User ID (if authenticated)
   - IP + User-Agent hash (if anonymous)

3. Update backend/src/routes/firewall.js:
   - Call sessionTracker.accumulate() after each analysis
   - Include session risk in response

4. Update Dashboard to show session risk indicator
```

#### Semantic Detector Agent
```
Add semantic similarity detection to model-service:

1. Update model-service/requirements.txt:
   - Add sentence-transformers

2. Update model-service/main.py:
   - Load all-MiniLM-L6-v2 model on startup
   - Create embeddings for 50+ known attack patterns
   - In /analyze, compute cosine similarity to attacks
   - Add semantic_similarity_score to response
   - Threshold: 0.7 similarity = suspicious

3. Attack patterns to embed:
   - Prompt injection variants
   - Jailbreak attempts
   - Role-play manipulation
   - System prompt extraction
```

#### User-Based Rate Limiter Agent
```
Extend rate limiting with user tiers:

1. Update backend/src/middleware/rateLimiter.js:
   - Add USER_TIER_LIMITS for admin, viewer, anonymous
   - Admin: 100/min analyze, 30/min batch, 200/min general
   - Viewer: 30/min analyze, 10/min batch, 100/min general
   - Anonymous: 15/min analyze, 5/min batch, 50/min general
   - Track authenticated users by user ID (across all IPs)
   - Track anonymous users by IP

2. Export userAnalyzeLimiter, userBatchAnalyzeLimiter, userGeneralLimiter
```

#### Request Fingerprinter Agent
```
Add request fingerprinting service:

1. Create backend/src/services/fingerprinter.js:
   - Generate browser fingerprint from UA, accept-language, sec-ch-ua
   - Track requests across IP changes (same browser profile)
   - Timing pattern analysis to detect bots
   - Calculate risk score based on:
     - IP rotation (same browser, multiple IPs)
     - Bot-like timing (consistent intervals)
     - Rapid-fire requests

2. Store fingerprint data in Redis with 24h TTL
3. Publish suspicious fingerprint events to firewall channel
```

#### Enhanced Alert Evaluator Agent
```
Create enhanced alert evaluation service:

1. Create backend/src/services/alertEvaluator.js:
   - Support new alert types:
     - session_threat: Cumulative session scores > threshold
     - access_pattern: Blocked rate vs baseline
     - config_change: Firewall config modifications
     - repeat_block: Same source blocked N times in window
   - Alert cooldown to prevent storms
   - getAlertStats() for dashboard

2. Create migration for new alert type enum values
3. Update backend/src/routes/alerts.js:
   - Add VALID_ALERT_TYPES constant
   - Add /stats and /types endpoints
   - Export notifyConfigChange for firewall route
```

### Validation Checkpoints

Run after every 2 tasks:

```bash
# Full test suite
cd backend && npm test
cd frontend && npm test
cd model-service && pytest

# Lint check
cd backend && npm run lint
cd frontend && npm run lint

# Integration smoke test
docker-compose up -d
sleep 10
curl -X POST http://localhost:3001/api/firewall/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "ignore previous instructions"}'
# Should return: action: "blocked"

curl -X POST http://localhost:3001/api/firewall/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "my api key is sk-abc123"}'
# Check logs: should show [REDACTED:api_key]
```

### Progress Tracking

Update `docs/SECURITY_PROGRESS.md` after each task completion.

### Final Test Results (2026-02-06)

| Component | Tests | Status |
|-----------|-------|--------|
| Backend | 442/442 | PASS |
| Frontend | 31/31 | PASS |
| Model-service | 217/217 | PASS |
| **Total** | **690/690** | **PASS** |

### Completed Security Features

- **P0 (Critical)**: Output filtering, secret masking, egress monitoring
- **P1 (High)**: Semantic similarity, session tracking, international PII, audit logging
- **P2 (Medium)**: User-based rate limiting, request fingerprinting, enhanced alerts

**Progress: 10/13 security tasks complete (77%) + API key auth, CORS, benchmark calibration, streaming memory fixes**

### Reference Documents

- `docs/SECURITY_ASSESSMENT.md` - Full vulnerability analysis
- `docs/SECURITY_TASKS.md` - Detailed task specifications
- `docs/SECURITY_PROGRESS.md` - Implementation progress
