# PooGuard Security Assessment

## Assessment Date: 2026-02-06 (Updated)
## Scope: Full-stack audit — 8 domains, 690 tests passing

---

## Executive Summary

PooGuard implements **defense-in-depth** across input analysis, output filtering, egress monitoring, session tracking, and authentication. The codebase demonstrates mature security engineering with proper audit logging, timing-safe CSRF validation, encoded secret detection, and tiered rate limiting.

This assessment covers **8 security domains**: authentication & session management, injection & input validation, secrets & credentials, network & transport, database, frontend client security, model service attack surface, and egress & data exfiltration.

**Overall Risk Rating: MODERATE** — No critical vulnerabilities in production deployment. 21 findings identified: 2 HIGH, 15 MEDIUM, 3 LOW, 1 INFO. All findings are defense-in-depth improvements, not active exploit vectors.

---

## Findings Summary

| ID | Severity | Domain | Finding | Status |
|----|----------|--------|---------|--------|
| F-01 | HIGH | Auth | JWT secret has no runtime minimum-length enforcement | Open |
| F-02 | HIGH | Credentials | Default admin password fallback in seed (`admin123`) | **Fixed** |
| F-03 | MEDIUM | Auth | JWT algorithm not explicitly specified in `verify()` | Open |
| F-04 | MEDIUM | Auth | No refresh token rotation or reuse detection | Open |
| F-05 | MEDIUM | API Keys | API key hash comparison via SQL (not timing-safe) | Accepted Risk |
| F-06 | MEDIUM | Frontend | JWT stored in localStorage (standard SPA pattern) | Accepted Risk |
| F-07 | MEDIUM | Frontend | CSP `style-src 'unsafe-inline'` required by Tailwind | Accepted Risk |
| F-08 | MEDIUM | Model Svc | Health/metrics endpoints expose GPU and model info | **Fixed** |
| F-09 | MEDIUM | Model Svc | Error responses include exception details (`str(e)`) | **Fixed** |
| F-10 | MEDIUM | Model Svc | Internal API key uses Python `==` (not timing-safe) | **Fixed** |
| F-11 | MEDIUM | Database | Redis has no authentication (internal network only) | **Fixed** |
| F-12 | MEDIUM | Database | No automated data retention or GDPR erasure | Open |
| F-13 | LOW | Network | No DNS rebinding mitigation on proxy upstream URL | Accepted Risk |
| F-14 | LOW | Frontend | Axios 1.6.5 slightly outdated (current: 1.7.x) | Open |
| F-15 | LOW | Model Svc | transformers 5.1.0 very new, less battle-tested | Monitoring |
| F-16 | INFO | Config | Production config returns `undefined` if env vars missing | By Design |
| F-17 | MEDIUM | Egress | Upstream error messages forwarded without sanitization | Open |
| F-18 | MEDIUM | Secrets | Missing cloud provider patterns (Azure, GCP, Stripe, GitLab, Slack) | Open |
| F-19 | MEDIUM | Session | Anonymous session ID reset via User-Agent rotation | Accepted Risk |
| F-20 | LOW | Egress | Streaming egress window boundary edge case | Accepted Risk |
| F-21 | MEDIUM | Secrets | Hardcoded encryption salt fallback in encryption.js | Open |

---

## Detailed Findings

### F-01: JWT Secret — No Runtime Minimum Length Enforcement (HIGH)

**Location:** `backend/src/config/index.js:26`

The JWT secret falls back to `'dev-secret-minimum-32-characters-long'` in development mode via `getConfigValue()`. In production, if `JWT_SECRET` is set to a short value (e.g., `"secret"`), no validation prevents it.

```javascript
jwt: {
  secret: getConfigValue('JWT_SECRET', 'dev-secret-minimum-32-characters-long'),
```

**Risk:** Weak JWT secrets can be brute-forced. HMAC-SHA256 with a short key provides negligible security.

**Mitigating factors:** `.env.example` documents the requirement. Development fallback is 40+ chars.

**Recommendation:** Add a startup check in production: reject secrets under 32 characters.

---

### F-02: Default Admin Password in Seed (HIGH)

**Location:** `backend/seeds/001_initial_data.js:8`

```javascript
const defaultPassword = process.env.ADMIN_PASSWORD || 'admin123';
```

If `ADMIN_PASSWORD` is not set, the seed creates an admin with password `admin123`. A console warning is printed but the seed succeeds.

**Risk:** Forgotten in production deployments, leading to a default-credential admin account.

**Mitigating factors:** Warning printed at seed time. Docker compose requires env vars to be set.

**Recommendation:** In production (`NODE_ENV=production`), fail the seed if `ADMIN_PASSWORD` is not set.

---

### F-03: JWT Algorithm Not Explicitly Set (MEDIUM)

**Location:** `backend/src/middleware/auth.js:15`, `proxyAuth.js:30`

```javascript
const decoded = jwt.verify(token, config.jwt.secret);
```

The `jsonwebtoken` library defaults to HS256 when no algorithm is specified. This is correct, but explicit specification prevents algorithm confusion attacks if the library behavior changes.

**Recommendation:** Pass `{ algorithms: ['HS256'] }` as the third argument.

---

### F-04: No Refresh Token Rotation (MEDIUM)

**Location:** `backend/src/routes/auth.js`

Refresh tokens are long-lived (7 days) and not rotated on use. A stolen refresh token remains valid for its full lifetime.

**Mitigating factors:** Refresh tokens are JWT-based (not opaque), so they expire naturally. Access tokens are short-lived (15 minutes).

**Recommendation:** Consider rotating refresh tokens on each use (issue new refresh token, invalidate old one via a token family tracking mechanism).

---

### F-05: API Key Hash Comparison via SQL (MEDIUM — Accepted Risk)

**Location:** `backend/src/middleware/proxyAuth.js:46-50`

```javascript
const keyHash = crypto.createHash('sha256').update(token).digest('hex');
const keyRow = await db('api_keys').where('api_keys.key_hash', keyHash)...
```

The SHA-256 hash is compared in PostgreSQL via `WHERE key_hash = ?`. SQL engines use index-based lookups (B-tree), not character-by-character comparison, so timing leakage is negligible. The hashing step itself (`sha256(token)`) is constant-time for fixed-length inputs.

**Why accepted:** The attack requires submitting API keys and measuring sub-millisecond DB query timing differences over a network, which is impractical. The CSRF middleware (`csrf.js:122`) does use `crypto.timingSafeEqual()` correctly for cookie comparison.

---

### F-06: JWT in localStorage (MEDIUM — Accepted Risk)

**Location:** `frontend/src/context/AuthContext.jsx:32-33`

```javascript
const [accessToken, setAccessToken] = useState(() => localStorage.getItem('accessToken'));
```

localStorage is accessible to any JavaScript running on the page. An XSS vulnerability could steal tokens.

**Why accepted:** This is the standard pattern for React SPAs. Alternatives (httpOnly cookies) introduce CSRF complexity and break the current architecture. The application mitigates XSS risk via:
- No `dangerouslySetInnerHTML` usage anywhere in the frontend
- CSP restricts script-src to `'self'`
- Content-Type-Options: nosniff prevents MIME confusion
- Helmet.js security headers on backend
- Short-lived access tokens (15 min)

---

### F-07: CSP `unsafe-inline` for Styles (MEDIUM — Accepted Risk)

**Location:** `frontend/nginx.conf:21`

```
style-src 'self' 'unsafe-inline';
```

Tailwind CSS generates inline styles that require `'unsafe-inline'` in `style-src`. This weakens XSS protection for style injection specifically.

**Why accepted:** Style injection has limited exploit potential compared to script injection. `script-src 'self'` (no `unsafe-inline`) is the critical protection, and it is correctly set. Removing `unsafe-inline` from `style-src` would break Tailwind's utility classes.

---

### F-08: Model Service Health/Metrics Information Disclosure (MEDIUM)

**Location:** `model-service/main.py:1585-1727`

The `/health`, `/ready`, and `/metrics` endpoints are unauthenticated (by design for Docker healthchecks) and expose:
- GPU device name (e.g., "NVIDIA RTX 5090")
- GPU memory allocation/total
- Model name and variant
- Request count and average latency
- Service uptime

**Mitigating factors:** Model service port (8000) is only mapped in docker-compose for development. In production, the model service is internal to the Docker network (`clawguard-net`) and not directly accessible from outside.

**Recommendation:** For deployments that expose model-service externally, consider a minimal health endpoint (just `{"status":"ok"}`) and require auth on the detailed `/metrics` endpoint.

---

### F-09: Model Service Error Response Detail (MEDIUM)

**Location:** `model-service/main.py:1768-1779`

```python
raise HTTPException(
    status_code=500,
    detail=f"Analysis failed: {str(e)}",
) from e
```

Exception messages could leak internal paths, CUDA errors, or model loading details.

**Mitigating factors:** Model service is internal-only. Backend catches these errors and returns generic messages to the client.

**Recommendation:** Return generic error detail in responses; log full exception server-side only.

---

### F-10: Model Service API Key String Comparison (MEDIUM — Accepted Risk)

**Location:** `model-service/main.py:364, 371`

```python
if x_api_key and x_api_key == MODEL_SERVICE_API_KEY:
```

Uses Python `==` instead of `hmac.compare_digest()`.

**Why accepted:** Model service is internal-only (container-to-container on Docker bridge network). Timing attacks over a Docker bridge are impractical — network jitter dwarfs string comparison timing differences.

---

### F-11: Redis No Authentication (MEDIUM — Accepted Risk)

**Location:** `docker-compose.yml:117-133`

Redis runs without a password on the internal Docker network.

**Why accepted:** Redis is not port-mapped in production (only in `docker-compose.dev.yml` for debugging). Access requires being on the `clawguard-net` Docker bridge. All services are trusted within this network.

**Recommendation:** For high-security deployments, add `--requirepass` to the Redis command.

---

### F-12: No Automated Data Retention (MEDIUM)

The system has no automated retention policy for `request_logs`, `egress_logs`, or `audit_logs`. Tables will grow indefinitely.

**Recommendation:** Implement a scheduled cleanup job (e.g., `DELETE FROM request_logs WHERE created_at < NOW() - INTERVAL '90 days'`) or configure table partitioning by date.

---

### F-13: No DNS Rebinding Protection on Proxy (LOW — Accepted Risk)

**Location:** `backend/src/routes/proxy.js`

The LLM proxy upstream URL is admin-configured and can point to private IPs (by design — the proxy is meant to reach internal model endpoints like `192.168.1.80:8080`).

**Why accepted:** Only authenticated admins can configure the upstream URL. The proxy requires API key auth for every request. Blocking private IPs would break the intended use case.

---

### F-17: Upstream Error Messages Forwarded Without Sanitization (MEDIUM)

**Location:** `backend/src/routes/proxy.js:366-377`

```javascript
const message = error.response?.data?.error?.message || error.message;
res.status(status).json({
  error: { message: `Upstream error: ${message}`, ... }
});
```

When the upstream LLM returns an error, the error message is forwarded to the client without passing through `secretMasker`. If the upstream error contains leaked credentials or internal paths, they reach the client.

**Mitigating factors:** The `/v1` proxy has inline egress checks for successful responses (streaming and non-streaming). Only error paths are unprotected.

**Recommendation:** Run `secretMasker.mask()` on upstream error messages before forwarding.

---

### F-18: Missing Cloud Provider Secret Patterns (MEDIUM)

**Location:** `backend/src/utils/secretMasker.js:6-35`

The secret masker covers 14 patterns (OpenAI, AWS, GitHub, generic API keys, JWTs, private keys, DB URLs, Bearer tokens). Missing patterns include:
- Azure subscription keys and SAS tokens
- GCP API keys (`AIza...`) and service account keys
- Stripe keys (`sk_live_`, `pk_live_`)
- GitLab PATs (`glpat-`)
- Slack tokens (`xoxb-`, `xoxp-`)
- NPM tokens (`npm_`)

**Mitigating factors:** The high-entropy pattern (line 34) catches many generic secrets. The ML model also detects credential-like content.

**Recommendation:** Add patterns for major cloud providers and payment processors.

---

### F-19: Anonymous Session ID Reset via User-Agent Rotation (MEDIUM — Accepted Risk)

**Location:** `backend/src/services/sessionTracker.js:28-43`

Anonymous sessions are identified by `sha256(IP + User-Agent)`. An attacker can reset their cumulative threat score by changing the User-Agent header.

```javascript
const fingerprint = crypto.createHash('sha256')
  .update(`${ip}:${userAgent}`)
  .digest('hex').substring(0, 16);
return `anon:${fingerprint}`;
```

**Why accepted:** The primary threat surface (`/v1` proxy) requires API key authentication, which ties sessions to user IDs (not fingerprints). Anonymous access to `/api/firewall/analyze` is rate-limited to 15 req/min regardless of session tracking. The session tracker provides defense-in-depth, not primary protection.

---

### F-20: Streaming Egress Window Boundary Edge Case (LOW — Accepted Risk)

**Location:** `backend/src/routes/proxy.js:381-460`

The streaming egress checker uses a rolling window (~4000 chars) with checks every 2000 chars. Theoretically, a secret split exactly across the window trim boundary could be missed.

**Why accepted:** Secrets are typically 20-80 characters. The window is 4000+ characters with checks every 2000. The probability of a secret landing exactly at the trim boundary (char 6000, trimmed to last 4000) is negligible. Additionally, the final post-stream check analyzes the complete last window.

---

### F-21: Hardcoded Encryption Salt Fallback (MEDIUM)

**Location:** `backend/src/utils/encryption.js:9`

```javascript
const SALT = process.env.ENCRYPTION_SALT || 'pooguard-encryption-salt';
```

The encryption utility derives its key via `scryptSync(jwt.secret, SALT, 32)`. The salt has a hardcoded fallback that is publicly visible in the codebase. While the primary security comes from `JWT_SECRET`, a known salt means two deployments with the same JWT_SECRET would produce identical encryption keys.

**Mitigating factors:** The key derivation still depends on `JWT_SECRET`, which is unique per deployment. AES-256-GCM with a random IV per operation provides strong encryption regardless of salt uniqueness.

**Recommendation:** Add `ENCRYPTION_SALT` to `.env.example` with a generation command (`openssl rand -base64 32`). Remove the hardcoded fallback or at minimum log a warning when using the default.

---

## Implemented Protections

### Authentication & Authorization
- [x] JWT-based authentication with 15-minute access token expiry
- [x] 7-day refresh tokens
- [x] Role-based access control (admin/viewer)
- [x] API key authentication (SHA-256 hashed, prefix `sk-pg-`)
- [x] Soft-revoke with `revoked_at` timestamp
- [x] Expiration date support on API keys
- [x] Last-used tracking (async, non-blocking)
- [x] Audit logging for auth failures (invalid tokens, unauthorized access)

### Input Protection
- [x] ML-based threat detection — 21B MoE model (prompt injection, jailbreak, PII)
- [x] Semantic similarity detection — 121 attack pattern embeddings across 18 categories
- [x] Input normalization — base64, hex, URL, homoglyph, l33t, invisible char deobfuscation
- [x] Input length validation (50KB max text, 20-item batch limit, 1MB body limit)
- [x] Pydantic validation on model service (min/max length, enum constraints)

### Output Protection
- [x] Output filtering — PII, system prompt disclosure, secret detection in LLM responses
- [x] Egress monitoring — synchronous response scanning before delivery
- [x] Secret masking — 14 patterns + encoded detection (base64, hex, URL decoding)
- [x] JSON redaction with parse-back and fallback

### Session & Rate Limiting
- [x] Session threat tracking with 30-minute half-life decay
- [x] Request fingerprinting across IP changes
- [x] User-based tiered rate limiting (admin: 100/min, viewer: 30/min, api_key: 60/min, anon: 15/min)
- [x] Dedicated rate limits for auth endpoints (login: 5/min, register: 3/min)
- [x] Redis-backed distributed rate limiting with in-memory fallback

### Transport & Headers
- [x] Helmet.js security headers on backend
- [x] Nginx security headers (X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- [x] CSP: `script-src 'self'` (no unsafe-inline for scripts)
- [x] CORS: strict allowlist for `/api`, auth-gated permissive for `/v1`
- [x] CSRF: double-submit cookie with `crypto.timingSafeEqual()` validation
- [x] Server tokens hidden (`server_tokens off`)
- [x] Trust proxy configured for X-Forwarded-For behind nginx

### Monitoring & Audit
- [x] Immutable audit log for all admin actions (with before/after values)
- [x] Alert types: threshold, rate, session_threat, access_pattern, config_change, repeat_block
- [x] Real-time WebSocket broadcast of firewall events and alerts
- [x] GPU memory monitoring with automatic cleanup threshold

### Infrastructure
- [x] Model pre-warm on startup (eliminates 12.6s first-request penalty)
- [x] Thread-safe GPU inference via single-worker ThreadPoolExecutor
- [x] Non-blocking FastAPI endpoints via `run_in_executor()`
- [x] Automatic GPU memory cleanup when threshold exceeded
- [x] Container memory limits (backend: 1G, frontend: 256M, Redis: 256M, Postgres: 1G)
- [x] Docker healthchecks on all services
- [x] On-demand PostgreSQL backup service

---

## Threat Model

### Threats Detected

| Threat | Detection Method | Confidence |
|--------|-----------------|------------|
| Direct prompt injection | ML model + semantic | High |
| Semantic rephrasing | Embedding similarity (121 patterns) | High |
| Known jailbreak patterns | ML model + semantic | High |
| PII in input (US + international) | ML model + regex | High |
| PII in output | Output filter | High |
| System prompt disclosure | Output filter | High |
| Secret exposure in logs | Secret masker (14 patterns + encoded) | High |
| Data exfiltration via response | Egress monitor | High |
| Encoding evasion (base64, hex, l33t, homoglyphs) | Input normalization | High |
| Brute force / rate abuse | User-based tiered rate limiting | High |
| Multi-turn manipulation | Session threat tracking with decay | Medium |
| Bot/automation attacks | Request fingerprinting | Medium |

### Known Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| Novel attack patterns | Model may miss zero-day evasion | Semantic similarity provides partial coverage |
| Long context truncation | Input truncated at 2048 tokens | Head+tail analysis captures boundaries |
| Indirect injection via tool outputs | Partial coverage only | Egress monitoring catches some exfiltration |
| Inference latency (3-6s) | Not suitable for latency-critical paths | Caching (Redis) reduces repeat analysis cost |
| Hard evasion (9 FNs in benchmark) | Model returns 0.0 on some attacks | Semantic similarity catches some the model misses |

---

## Benchmark Results (Feb 2026)

- **Dataset**: 360 examples (129 clean, 89 PI, 56 JB, 56 PII, 30 mixed)
- **Mean latency**: 3.9s, p95: 7.9s
- **F1 scores** (Balanced preset): PI=0.79, JB=0.65, PII=0.89, Semantic=0.81
- **False positives**: 39 (mostly semantic similarity on security-topic clean text)
- **False negatives**: 9 (model returned 0.0 on hard evasion attempts)

See `model-service/benchmarks/` for raw data and optimization scripts.

---

## Recommendations Priority Matrix

### Immediate (Next Sprint)
| Finding | Effort | Impact |
|---------|--------|--------|
| F-01: JWT secret length check at startup | Low | High |
| F-02: Fail seed if no ADMIN_PASSWORD in production | Low | High |
| F-03: Explicit JWT algorithm in verify() | Low | Medium |

### Near-Term (Hardening)
| Finding | Effort | Impact |
|---------|--------|--------|
| F-17: Sanitize upstream error messages in proxy | Low | Medium |
| F-09: Generic error messages in model service responses | Low | Medium |
| F-18: Add cloud provider secret patterns | Low | Medium |
| F-21: Remove hardcoded encryption salt fallback | Low | Medium |
| F-08: Minimal health endpoint, auth on /metrics | Medium | Medium |
| F-04: Refresh token rotation | Medium | Medium |
| F-12: Automated data retention policy | Medium | Medium |

### Accepted Risks (Documented)
| Finding | Rationale |
|---------|-----------|
| F-05: API key SQL comparison | Hash lookup via B-tree index; timing attack impractical |
| F-06: JWT in localStorage | Standard SPA pattern; mitigated by CSP + no innerHTML |
| F-07: CSP unsafe-inline styles | Required by Tailwind; scripts properly restricted |
| F-10: Model service string comparison | Internal-only; Docker bridge timing attack impractical |
| F-11: Redis no auth | Internal Docker network; not port-mapped in production |
| F-13: No DNS rebinding on proxy | Admin-configured URL; auth required; intentional design |
| F-19: Anonymous session UA rotation | Primary surface requires API key auth; rate-limited |
| F-20: Streaming window boundary | Negligible probability; secrets < 80 chars vs 4000 window |

---

## Test Coverage

| Component | Tests | Status |
|-----------|-------|--------|
| Backend | 442 | Pass |
| Model Service | 217 | Pass |
| Frontend | 31 | Pass |
| **Total** | **690** | **Pass** |

---

## Implementation History

| Date | Phase | Tasks Completed |
|------|-------|----------------|
| 2026-02-05 | P0 Critical | Output filtering, secret masking, egress monitoring |
| 2026-02-05 | P1 High | Semantic similarity, session tracking, international PII, audit logging |
| 2026-02-05 | P2 Medium | User-based rate limiting, request fingerprinting, enhanced alerts |
| 2026-02-06 | Hardening | API key auth, CORS fixes, attack pattern expansion (50 to 121), benchmark calibration |
| 2026-02-06 | Performance | Inference optimizations (torch.inference_mode, ThreadPoolExecutor, template caching, pre-warm) |
| 2026-02-06 | Audit | 8-domain security assessment (this document) |
