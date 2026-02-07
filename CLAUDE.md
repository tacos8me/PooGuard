# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PooGuard is an LLM firewall system that detects and blocks malicious inputs (prompt injection, jailbreaks, PII) before they reach language models. It consists of three services:

- **model-service** (Python/FastAPI): Runs the HuggingFace safeguard model for threat classification
- **backend** (Node.js/Express): API server with JWT + API key auth, OAI-compatible LLM proxy, WebSocket events, and PostgreSQL/Redis
- **frontend** (React/Vite): Dashboard with real-time monitoring, analytics, and configuration

## Development Commands

### Full Stack (Docker)
```bash
# Development with hot reload (GPU required)
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Production
docker-compose up --build
```

### Backend (Node.js)
```bash
cd backend
npm install
npm run dev          # Start with nodemon
npm run migrate      # Run database migrations
npm run migrate:rollback
```

### Frontend (React)
```bash
cd frontend
npm install
npm run dev          # Vite dev server on :5173
npm run build        # Production build
npm run lint         # ESLint
```

### Model Service (Python)
```bash
cd model-service
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000  # Requires GPU
```

## Architecture

### Data Flow (Analysis Mode)
1. Client sends text to `POST /api/firewall/analyze`
2. Backend calls model-service `/analyze` for threat scores (includes semantic similarity)
3. Backend applies configured thresholds and actions (block/flag/allow)
4. Secret masker redacts sensitive data before logging
5. Session tracker updates cumulative threat scores
6. Result logged to PostgreSQL, event published to Redis
7. Egress monitor scans outgoing responses for sensitive data
8. WebSocket broadcasts `firewall:event` to connected dashboard clients
9. Alert evaluator checks all alert types and triggers notifications

### Data Flow (LLM Proxy Mode)
1. External client sends OAI-format request to `POST /v1/chat/completions` with API key
2. `proxyAuth` middleware authenticates via JWT or API key (SHA-256 lookup in `api_keys` table)
3. Backend extracts user messages, calls model-service `/analyze` for threat scores (cached via `analyzeTextCached` with Redis)
4. If blocked → return OAI-formatted error (`content_filter`)
5. If safe → forward request to configured upstream LLM endpoint
6. Collect response (streaming SSE or JSON), run egress scan
7. Return upstream response to client

### Backend Structure
- `src/routes/` - Express routers (auth, firewall, analytics, alerts, proxy, apikeys)
  - Health endpoints: `/health`, `/ready`, `/live`
  - Proxy endpoints: `/v1/chat/completions`, `/v1/models` (OAI-compatible, API key or JWT auth)
  - API key management: `/api/apikeys` (admin CRUD — create, list, revoke)
  - Session endpoints: `/api/analytics/sessions/elevated`, `/:sessionId`
  - Audit endpoints: `/api/analytics/audit` (admin only)
  - Alert endpoints: `/api/alerts/stats`, `/api/alerts/types`
  - Model config: `/api/firewall/model/discover`, `/api/firewall/model/test`
- `src/services/` - Business logic (redis pub/sub, model client, logger)
  - `sessionTracker.js` - Cumulative threat scoring with decay
  - `fingerprinter.js` - Request fingerprinting and pattern detection
  - `outputFilter.js` - LLM output safety analysis
  - `alertEvaluator.js` - Enhanced alert rule evaluation
- `src/middleware/`
  - `auth.js` - JWT verification, role-based access (dashboard API)
  - `proxyAuth.js` - Dual-path auth for /v1 routes: JWT first, then API key (SHA-256 hash lookup)
  - `rateLimiter.js` - User-based tiered rate limiting (admin/viewer/api_key/anonymous tiers)
  - `egressMonitor.js` - Outbound sensitive data detection
  - `auditLog.js` - Immutable admin action logging
- `src/utils/secretMasker.js` - Secret detection and masking
- `src/models/index.js` - Knex database instance
- `migrations/` - Database schema (users, api_keys, request_logs, alerts, firewall_config, audit_logs, egress_logs)

### Frontend Structure
- `src/pages/` - Dashboard, Analytics, Settings, Rules, Login/Register
  - Rules page: Detection thresholds, response actions, and alert configuration
  - Settings page: Two-column layout — Proxy/Model config (left), System/Testing (right)
- `src/context/AuthContext.jsx` - JWT auth state and API
- `src/lib/api.js` - Axios instance with auth interceptor
- `src/components/Layout.jsx` - Sidebar navigation wrapper
- `src/context/SocketContext.jsx` - WebSocket connection management with auto-reconnect
- `src/components/ProtectedRoute.jsx` - Auth-gated route wrapper
- `src/components/ErrorBoundary.jsx` - React error boundary with fallback UI
- `src/components/ConnectionStatus.jsx` - Real-time WebSocket connection indicator
- `src/components/ConfirmDialog.jsx` - Confirmation dialog for destructive actions

### Real-time Events
Backend uses Redis pub/sub with Socket.IO:
- `firewall:events` channel → `firewall:event` socket event
- `alerts:triggered` channel → `alert:triggered` socket event

Frontend connects with JWT in `socket.handshake.auth.token`.

### Model Service
- Runs `openai/gpt-oss-safeguard-20b` (21B MoE, 3.6B active) on GPU
- Returns `prompt_injection_score`, `jailbreak_score`, `pii_score` (0-1)
- `semantic_similarity_score` - Embedding-based attack pattern matching (182 patterns across 28 categories)
- `/analyze-output` endpoint for LLM output safety checking
- Model variant (20b/120b) configurable via Settings page or `/config` endpoint
- Thresholds configured in `firewall_config` table
- **Performance Optimizations**:
  - `torch.inference_mode()` for inference (no gradient tracking)
  - `torch.compile(model.forward, mode="reduce-overhead")` with try/except fallback
  - GPU semaphore (`threading.Semaphore(1)`) serializes all GPU access in `_run_inference()`
  - `SafeguardStoppingCriteria` — early-exit when final JSON verdict is complete
  - `max_new_tokens=96` (reduced from 256) to minimize generation overhead
  - `device_map="cuda:0"` instead of `"auto"` — skip accelerate auto-mapping
  - Async `/analyze` via `run_in_executor()`; `/analyze-output` runs inline (pure CPU regex)
  - `_reload_model()` runs in executor to prevent 60s event loop block
  - Startup pre-warm inference to eliminate cold-start penalty on first request
  - Policy KV cache built at startup (stored, deferred to GPU integration testing)
  - Template overhead tokens computed eagerly at startup
  - HTTP keep-alive agents on backend→model-service and backend→upstream proxy connections
  - In-memory `firewall_config` cache with 10s TTL eliminates per-request DB queries
- **Score Calibration**: Platt scaling (logistic sigmoid) applied after raw inference, before threshold comparison
  - `POST /calibrate` fits per-category calibrators from benchmark data
  - `GET /calibration` returns current calibration state
  - Calibration params persisted to `calibration_params.json`; NoOp pass-through if file absent

### Calibrated Threshold Defaults

Default thresholds use the "Balanced" preset (maximize F1 score on 360-example benchmark):

| Category | Default Threshold | F1 Score | Env Override |
|----------|------------------|----------|-------------|
| Prompt Injection | 0.70 | 0.79 | `PROMPT_INJECTION_THRESHOLD` |
| Jailbreak | 0.70 | 0.65 | `JAILBREAK_THRESHOLD` |
| PII | 0.70 | 0.89 | `PII_THRESHOLD` |
| Semantic Similarity | 0.42 | 0.81 | `SEMANTIC_SIMILARITY_THRESHOLD` |

Three preset profiles are available on the Rules page:

| Preset | PI | JB | PII | Semantic | Use Case |
|--------|-----|-----|-----|----------|----------|
| High Security | 0.40 | 0.40 | 0.50 | 0.28 | Maximize detection, accept more false positives |
| Balanced | 0.70 | 0.70 | 0.70 | 0.42 | Best F1 score (default) |
| Low Friction | 0.90 | 0.90 | 0.90 | 0.50 | Minimize false positives, accept missed threats |

### Calibration Benchmarks
- Benchmark dataset: `model-service/benchmarks/calibration_dataset.json` (294 labeled examples)
- Run benchmark: `python model-service/benchmarks/run_benchmark.py`
- Run full calibration pipeline: `python model-service/benchmarks/run_calibration_pipeline.py`
- Optimize thresholds only: `python model-service/benchmarks/optimize_thresholds.py`
- Reports: `model-service/benchmarks/calibration_report.md`, `optimal_thresholds.json`

## Security Features

### Input Protection
- **Threat Detection**: Prompt injection, jailbreak attempts, PII exposure
- **Semantic Similarity**: 182 attack pattern embeddings across 28 categories for evasion detection
- **International PII**: UK NI, NHS, IBAN, Canadian SIN, Australian TFN, passports
- **Secret Masking**: API keys, AWS credentials, GitHub tokens, JWTs auto-redacted

### Session Security
- **Session Tracking**: Cumulative threat scores with 30-min half-life decay
- **Request Fingerprinting**: Browser profile tracking across IP changes
- **User-Based Rate Limiting**: Tiered limits (admin: 100/min, api_key: 60/min, viewer: 30/min, anon: 15/min)

### Output Protection
- **Output Filtering**: PII, system prompt disclosure, secret detection in responses
- **Egress Monitoring**: All API responses scanned for sensitive data leakage

### Request Security
- **CSRF Protection**: Double-submit cookie pattern for all state-changing API requests
- **Trust Proxy**: Express configured to read client IP from X-Forwarded-For behind nginx

### Monitoring & Audit
- **Alert Types**: threshold, rate, session_threat, access_pattern, config_change, repeat_block
- **Audit Logging**: Immutable log of all admin actions with before/after values
- **Real-time Events**: WebSocket broadcast of firewall events and alerts

## Key Configuration

Environment variables (see `.env.example`):
- `DATABASE_URL` - PostgreSQL connection
- `REDIS_URL` - Redis connection
- `JWT_SECRET` - Token signing key
- `MODEL_SERVICE_URL` - Internal model service URL
- `MODEL_NAME` - Safeguard model HuggingFace name
- `SAFEGUARD_MODEL_SIZE` - Model variant: `20b` or `120b`
- `HF_TOKEN` - HuggingFace token for model download
- `PYTORCH_ALLOC_CONF` - PyTorch CUDA memory allocator settings (e.g., `expandable_segments:True,max_split_size_mb:256,garbage_collection_threshold:0.8`)

Default credentials (dev): `admin@pooguard.local` / (randomly generated -- check seed console output)
