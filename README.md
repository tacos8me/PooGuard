<div align="center">

# PooGuard

**Real-time threat detection for every LLM request.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-690%20passing-brightgreen.svg)](#testing)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg)](#quick-start)
[![GPU](https://img.shields.io/badge/GPU-CUDA%2012.8-76B900.svg)](#prerequisites)

</div>

---

<div align="center">

![PooGuard Dashboard](docs/poo.png)

</div>

PooGuard is an open-source LLM firewall that sits between your chat clients and upstream language models, analyzing every message for prompt injection, jailbreak attempts, PII leakage, and semantic evasion attacks. It uses a real 21-billion parameter MoE model running on-device GPU inference — not regex, not keyword matching — to score threats in real time, blocking or flagging dangerous inputs before they reach your LLM.

Deploy it as a drop-in OAI-compatible proxy. Point SillyTavern, Open WebUI, Chatbox, or any OpenAI-compatible client at PooGuard, and every request gets analyzed, scored, and logged with zero changes to your existing setup.

## Key Features

- **ML-Powered Threat Classification** — A 21B-parameter MoE safeguard model (3.6B active) runs on your GPU, classifying prompt injection, jailbreak, and PII threats with calibrated confidence scores. No cloud API calls, no third-party dependencies.

- **OAI-Compatible Proxy** — Drop-in replacement for any OpenAI base URL. External clients authenticate with API keys, and PooGuard transparently analyzes, blocks, or forwards every request to your upstream LLM.

- **Semantic Evasion Detection** — 121 attack pattern embeddings across 18 categories (prompt injection, persona hijacking, data exfiltration, agent-to-agent attacks, tool-use injection, and more) catch obfuscated and novel attacks that keyword filters miss.

- **Input Deobfuscation** — Decodes base64, hex, URL encoding, Unicode homoglyphs, l33tspeak, zero-width characters, and whitespace insertion before analysis. Attackers can't hide behind encoding tricks.

- **Egress Monitoring** — Scans every LLM response for leaked secrets, PII, and system prompt disclosure before it reaches the client. Secrets are redacted automatically.

- **Real-Time Dashboard** — Live WebSocket feed showing every request with per-category threat scores (INJ/JB/PII/SEM), timeline charts, threat breakdown analytics, and hourly distribution views.

- **Configurable Threshold Presets** — Three calibrated profiles out of the box: High Security (maximize detection), Balanced (best F1: 0.79/0.65/0.89/0.81), and Low Friction (minimize false positives). Or set custom thresholds per category.

- **Session Threat Tracking** — Cumulative threat scoring with 30-minute half-life decay detects slow-burn attacks that spread malicious intent across multiple messages.

- **Secret Masking & Audit Trail** — API keys, AWS credentials, GitHub tokens, and JWTs are auto-redacted in logs. Every admin action is recorded in an immutable audit log with before/after values.

- **Alert System** — Six alert types (threshold, rate, session_threat, access_pattern, config_change, repeat_block) with real-time WebSocket notifications to your dashboard.

## Request Flow

```
Request ➜ Auth ➜ Extract ➜ Normalize ➜ Classify ➜ Evaluate ➜ Forward ➜ Upstream LLM
                                                      |               |
                                                    Block         Response
                                                      |               |
                                                      ▼               ▼
                                                   Client  ◀── Egress Scan
```

1. **Authentication** — `/v1/chat/completions` accepts JWT tokens or PooGuard API keys (`sk-pg-*`). The `proxyAuth` middleware validates credentials via SHA-256 hash lookup.
2. **Rate Limiting** — User-based tiered limits (admin: 100/min, API key: 60/min, viewer: 30/min, anonymous: 15/min) using Redis-backed sliding windows.
3. **Text Extraction** — User messages are extracted from the OpenAI-format `messages` array, including multi-part content.
4. **Input Normalization** — Multi-layer deobfuscation: invisible Unicode stripping, NFKC normalization, homoglyph replacement, whitespace collapse, iterative decoding (base64, hex, URL, l33t, ROT13).
5. **Threat Classification** — The safeguard model runs inference on normalized text, returning per-category scores for prompt injection, jailbreak, and PII.
6. **Semantic Similarity** — Input embedding compared against 121 attack pattern embeddings across 18 categories.
7. **Threshold Evaluation** — Calibrated scores compared against configurable thresholds. Each category independently triggers block, flag, or allow.
8. **Forward or Block** — Safe requests forwarded to upstream LLM. Both streaming (SSE) and non-streaming responses supported.
9. **Egress Monitoring** — Response body scanned for leaked secrets, PII, and sensitive data before delivery.
10. **Event Broadcast** — Request logged to PostgreSQL, event published to Redis, dashboard updated via WebSocket in real time.

## Prerequisites

- **NVIDIA GPU** with 16 GB+ VRAM (RTX 4080 or better; RTX 5090 recommended)
- **Docker** and **Docker Compose v2** ([install guide](https://docs.docker.com/engine/install/))
- **NVIDIA Container Toolkit** for GPU passthrough ([install guide](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html))
- **HuggingFace account** with an access token — accept the [model license](https://huggingface.co/openai/gpt-oss-safeguard-20b) before first run

## Quick Start

```bash
git clone https://github.com/tacos8me/PooGuard.git
cd PooGuard
cp .env.example .env
# Edit .env -- set at minimum: HF_TOKEN, JWT_SECRET, DB_PASSWORD
docker compose up            # first run downloads the ~13 GB model
```

| Service   | URL                          |
|-----------|------------------------------|
| Dashboard | http://localhost:3000         |
| API       | http://localhost:3001         |
| Proxy     | http://localhost:3001/v1      |

Default login: `admin@clawguard.local` / (randomly generated -- check seed console output, or set `ADMIN_PASSWORD` env var)

> **Tip:** The model download is cached in a Docker volume. Subsequent starts are fast.

## Connecting Chat Clients

PooGuard exposes an OpenAI-compatible proxy at `/v1`. Any client that supports a custom OpenAI base URL works out of the box.

### Create an API Key

Log in to the dashboard, go to **Settings > API Keys**, and create a key. It will look like `sk-pg-<hex chars>`. Copy it immediately — it is shown only once.

### curl

```bash
curl http://localhost:3001/v1/chat/completions \
  -H "Authorization: Bearer sk-pg-YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "any-model-name",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### SillyTavern

1. Open **Settings > API Connections**
2. Set API type to **Chat Completion (OpenAI)**
3. Set base URL to `http://your-server:3001/v1`
4. Paste your `sk-pg-` API key
5. Pick any model — PooGuard forwards to whatever upstream you configured

### Open WebUI

1. Go to **Settings > Connections**
2. Add an OpenAI-compatible connection
3. Set URL to `http://your-server:3001/v1`
4. Paste your API key

### Any OAI-Compatible Client

```bash
export OPENAI_BASE_URL=http://your-server:3001/v1
export OPENAI_API_KEY=sk-pg-YOUR_KEY
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HF_TOKEN` | Yes | — | HuggingFace token for model download |
| `JWT_SECRET` | Yes | — | Token signing key (min 32 chars) |
| `DB_PASSWORD` | Yes | — | PostgreSQL password |
| `MODEL_NAME` | No | `openai/gpt-oss-safeguard-20b` | HuggingFace model name |
| `SAFEGUARD_MODEL_SIZE` | No | `20b` | Model variant: `20b` or `120b` |
| `MODEL_SERVICE_API_KEY` | No | — | Backend-to-model-service auth key |
| `ALLOWED_ORIGINS` | No | `http://localhost:3000,http://localhost:5173` | CORS allowed origins |

### Detection Thresholds

Tune detection sensitivity from the dashboard **Settings** page. Three built-in presets:

| Preset | Prompt Injection | Jailbreak | PII | Semantic |
|--------|-----------------|-----------|-----|----------|
| **Balanced** (default) | 0.70 | 0.70 | 0.70 | 0.42 |
| **High Security** | 0.40 | 0.40 | 0.50 | 0.28 |
| **Low Friction** | 0.90 | 0.90 | 0.90 | 0.50 |

Lower thresholds = more aggressive blocking. The model produces bimodal scores (near 0.0 or 0.8–0.95), so small threshold changes in the middle range have little practical effect.

## Development

### Running with Docker (recommended)

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

This mounts source directories for hot reload — backend with nodemon, frontend with Vite HMR, model service with live `main.py` mounting. Dev mode also exposes PostgreSQL (5432) and Redis (6379) for direct access.

### Running Services Individually

```bash
# Backend
cd backend && npm install && npm run migrate && npm run dev

# Frontend
cd frontend && npm install && npm run dev

# Model service (requires GPU)
cd model-service && pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Testing

```bash
# Backend — 442 tests
cd backend && npx jest --no-coverage

# Model service — 217 tests
cd model-service && python -m pytest tests/ -v

# Frontend — 31 tests
cd frontend && npx vitest run
```

| Suite | Framework | Tests | Coverage |
|-------|-----------|-------|----------|
| Backend | Jest + Supertest | 442 | Routes, middleware, services, utilities |
| Model Service | pytest | 217 | Inference, normalization, semantic similarity, API |
| Frontend | Vitest | 31 | Components, auth flows, settings |

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| ML Inference | PyTorch (CUDA 12.8), Transformers | GPU model inference with MXFP4 quantization |
| Embeddings | sentence-transformers | Semantic similarity attack detection |
| Model API | Python 3.12, FastAPI, Uvicorn | Threat classification service |
| Backend | Node.js, Express 4 | REST API, WebSocket, LLM proxy |
| Auth | jsonwebtoken, bcrypt | JWT + SHA-256 hashed API keys |
| Database | PostgreSQL 16, Knex.js | Request logs, config, audit trail, alerts |
| Cache / PubSub | Redis 7 | Rate limiting, cache, real-time event bus |
| Real-time | Socket.IO 4 | WebSocket events to dashboard |
| Frontend | React 18, Vite 5, TailwindCSS 3 | Monitoring dashboard |
| Charts | Recharts 2 | Analytics visualizations |
| Security | Helmet, CORS, CSRF | HTTP hardening |
| Containerization | Docker Compose | Multi-service orchestration with GPU passthrough |

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment with TLS/HTTPS, database backups, and infrastructure hardening.

## Security

See [docs/SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md) for the full threat model, benchmark results, and implementation status.

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Run the test suites before submitting
4. Open a pull request

## License

[MIT](LICENSE)
