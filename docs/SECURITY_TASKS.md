# Security Hardening Task List

## Reference: docs/SECURITY_ASSESSMENT.md

---

## Phase 1: Critical Fixes (P0)

### Task 1.1: Output Filtering Layer
**Priority**: P0 - Critical
**Effort**: Large
**Files**:
- `model-service/main.py` - Add `/analyze-output` endpoint
- `backend/src/services/outputFilter.js` - New service
- `backend/src/routes/firewall.js` - Integrate output checking

**Requirements**:
- Analyze LLM responses before returning to user
- Detect PII leakage in outputs
- Detect system prompt disclosure
- Detect instruction-following violations
- Support configurable output policies

**Acceptance Criteria**:
- [ ] POST /analyze-output endpoint exists
- [ ] Detects SSN/CC/email in output
- [ ] Detects "system prompt" or instruction leak patterns
- [ ] Returns sanitized output or blocks
- [ ] Configurable via firewall_config

---

### Task 1.2: Secret Detection & Masking
**Priority**: P0 - Critical
**Effort**: Medium
**Files**:
- `backend/src/utils/secretMasker.js` - New utility
- `backend/src/routes/firewall.js` - Mask before logging
- `backend/src/routes/analytics.js` - Mask in responses

**Requirements**:
- Detect common secret patterns:
  - API keys (sk-, pk-, api_, bearer)
  - AWS credentials (AKIA...)
  - GitHub tokens (ghp_, gho_, ghs_)
  - JWT tokens (eyJ...)
  - Generic high-entropy strings
- Replace with `[REDACTED:type]`
- Never log unmasked secrets

**Acceptance Criteria**:
- [ ] secretMasker.mask(text) function
- [ ] Detects 10+ secret patterns
- [ ] Database logs contain no raw secrets
- [ ] API responses mask secrets
- [ ] Unit tests for all patterns

---

### Task 1.3: Egress Monitoring
**Priority**: P0 - Critical
**Effort**: Medium
**Files**:
- `backend/src/middleware/egressMonitor.js` - New middleware
- `backend/src/index.js` - Apply to responses

**Requirements**:
- Monitor all API responses for sensitive data
- Log egress events separately
- Alert on potential data exfiltration
- Block responses exceeding sensitivity threshold

**Acceptance Criteria**:
- [ ] All /api responses pass through monitor
- [ ] Sensitive data patterns detected
- [ ] Egress events logged to separate table
- [ ] Alert triggers on high-sensitivity egress
- [ ] Dashboard shows egress metrics

---

## Phase 2: High Priority (P1)

### Task 2.1: Semantic Similarity Detection
**Priority**: P1 - High
**Effort**: Large
**Files**:
- `model-service/main.py` - Add embedding comparison
- `model-service/requirements.txt` - Add sentence-transformers

**Requirements**:
- Load lightweight embedding model (all-MiniLM-L6-v2)
- Maintain vector store of known attack patterns
- Compare input embedding to attack embeddings
- Return similarity score alongside keyword score

**Acceptance Criteria**:
- [ ] Embedding model loads on startup
- [ ] 50+ attack pattern embeddings stored
- [ ] Similarity score in /analyze response
- [ ] "Disregard prior guidance" detected as injection
- [ ] < 50ms latency impact

---

### Task 2.2: Session-Level Threat Tracking
**Priority**: P1 - High
**Effort**: Medium
**Files**:
- `backend/src/services/sessionTracker.js` - New service
- `backend/src/routes/firewall.js` - Integrate tracking
- `backend/migrations/` - session_threats table

**Requirements**:
- Track threat scores per session/user
- Accumulate scores across requests
- Trigger alerts on cumulative thresholds
- Decay scores over time (30 min half-life)

**Acceptance Criteria**:
- [ ] Session identified by JWT or IP+UA fingerprint
- [ ] Cumulative score stored in Redis
- [ ] Alert triggers at cumulative > 2.0
- [ ] Scores decay over time
- [ ] Dashboard shows session risk

---

### Task 2.3: International PII Patterns
**Priority**: P1 - High
**Effort**: Small
**Files**:
- `model-service/main.py` - Extended regex

**Requirements**:
Add detection for:
- UK National Insurance (AB123456C)
- UK NHS Number (123 456 7890)
- EU IBAN (DE89370400440532013000)
- Canadian SIN (123-456-789)
- Australian TFN (123 456 789)
- Passport numbers (various formats)
- Driver's license (state-specific)

**Acceptance Criteria**:
- [ ] 10+ international PII patterns
- [ ] Each pattern has unit test
- [ ] Detection works with safeguard model
- [ ] Configurable by region

---

### Task 2.4: Admin Audit Logging
**Priority**: P1 - High
**Effort**: Medium
**Files**:
- `backend/src/middleware/auditLog.js` - New middleware
- `backend/migrations/` - audit_logs table
- `backend/src/routes/` - Apply to admin routes

**Requirements**:
- Log all admin actions (config changes, user management)
- Include: who, what, when, old value, new value
- Immutable log (no delete/update API)
- Queryable via admin dashboard

**Acceptance Criteria**:
- [ ] audit_logs table exists
- [ ] All PUT/DELETE to /api/firewall/config logged
- [ ] All /api/admin/* actions logged
- [ ] Dashboard shows audit trail
- [ ] Logs include before/after values

---

## Phase 3: Medium Priority (P2)

### Task 3.1: User-Based Rate Limiting
**Priority**: P2 - Medium
**Effort**: Small
**Files**:
- `backend/src/middleware/rateLimiter.js` - Extend

**Requirements**:
- Rate limit by user ID (not just IP) for authenticated requests
- Separate limits per user tier
- Track across all IPs for same user

---

### Task 3.2: Request Fingerprinting
**Priority**: P2 - Medium
**Effort**: Medium
**Files**:
- `backend/src/services/fingerprinter.js` - New service

**Requirements**:
- Generate fingerprint from IP + UA + timing patterns
- Detect distributed attacks from same actor
- Link requests across IP changes

---

### Task 3.3: Enhanced Alert Rules
**Priority**: P2 - Medium
**Effort**: Medium
**Files**:
- `backend/src/services/alertEvaluator.js` - Extend

**Requirements**:
- Alert on cumulative session threats
- Alert on unusual access patterns
- Alert on config changes
- Alert on repeated blocked attempts

---

## Phase 4: Low Priority (P3)

### Task 4.1: Explainable Scores
- Show which keywords/patterns triggered detection
- Highlight suspicious text spans
- Provide confidence intervals

### Task 4.2: Data Retention Automation
- Auto-delete logs older than X days
- GDPR deletion endpoint
- Anonymization for analytics

### Task 4.3: ML Evasion Detection
- Train classifier on known evasion techniques
- Detect encoding/obfuscation attempts
- Flag suspicious character patterns

---

## Validation Checkpoints

After every 2 tasks, run full validation:

```bash
# Backend tests
cd backend && npm test

# Frontend tests
cd frontend && npm test

# Model service tests
cd model-service && pytest

# Lint all
cd backend && npm run lint
cd frontend && npm run lint
cd model-service && black --check . && flake8

# Integration check
docker-compose up -d
curl http://localhost:3001/api/health
curl http://localhost:8000/health
```

---

## Progress Tracking

See `docs/SECURITY_PROGRESS.md` for current status.
