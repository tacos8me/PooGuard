# PooGuard Calibration Benchmark Dataset

## Dataset Format

`calibration_dataset.json` contains an array of labeled examples for calibrating the safeguard model's threat detection scores.

### Schema

```json
{
  "id": 1,
  "text": "the input text to analyze",
  "category": "clean|prompt_injection|jailbreak|pii|mixed",
  "expected_threats": ["prompt_injection", "jailbreak", "pii"],
  "difficulty": "easy|medium|hard",
  "description": "brief note on what this tests"
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Unique identifier (1-indexed) |
| `text` | string | The input text to send to `/analyze` |
| `category` | string | Primary classification of the example |
| `expected_threats` | string[] | Which threat types should be detected (empty for clean) |
| `difficulty` | string | How hard this example is to classify correctly |
| `description` | string | Human-readable note explaining what this tests |

### Categories

- **clean** (110 examples): Benign inputs that should NOT trigger any threat detection. Includes false-positive candidates like security education, code snippets with `bypass()`/`inject()`, product codes resembling SSNs, angry customer complaints.
- **prompt_injection** (59 examples): Attempts to override or extract system instructions. Ranges from direct "ignore all instructions" to encoded (base64, hex, URL), multi-language, and stealth injections hidden in documents.
- **jailbreak** (49 examples): Attempts to bypass safety filters or assume unrestricted personas. Includes DAN, STAN, AIM, developer mode, academic framing, gradual escalation, and philosophical deconstruction attacks.
- **pii** (46 examples): Text containing personally identifiable information. Covers SSN, credit cards, emails, phone numbers, and international formats (UK NI, NHS, IBAN, Canadian SIN, Australian TFN, passports, API keys, JWTs).
- **mixed** (30 examples): Combinations of multiple threat types in a single input (e.g., injection + PII, jailbreak + PII, triple-threat).

### Difficulty Levels

- **easy**: Clear, unambiguous examples
- **medium**: Moderate obfuscation, context-dependent, or embedded in normal text
- **hard**: Encoded attacks, multi-language, truncation attacks, zero-width characters, sophisticated social engineering

## Usage

### Step 1: Score the benchmark dataset

Run the benchmark against the live model service:

```bash
python benchmarks/run_benchmark.py
```

Results are saved to `benchmarks/raw_scores.json`.

### Step 2: Run the full calibration pipeline

The calibration pipeline fits Platt scaling calibrators, optionally re-scores
the benchmark with calibrated model output, and generates an optimized
threshold report with before/after comparison:

```bash
# Full pipeline (score -> calibrate -> re-score -> optimize)
python benchmarks/run_calibration_pipeline.py \
  --input benchmarks/raw_scores.json \
  --output-dir benchmarks/ \
  --model-url http://localhost:8000

# Skip re-scoring (just fit calibrators and optimize existing scores)
python benchmarks/run_calibration_pipeline.py \
  --input benchmarks/raw_scores.json \
  --output-dir benchmarks/ \
  --skip-rescore
```

### Step 3: Threshold optimization only

To re-run threshold optimization on existing scores without touching the
model-service:

```bash
python benchmarks/optimize_thresholds.py \
  --input benchmarks/raw_scores.json \
  --output-dir benchmarks/
```

### Output files

| File | Description |
|------|-------------|
| `raw_scores.json` | Benchmark results with per-example model scores |
| `calibrated_scores.json` | Re-scored results after calibration (if not skipped) |
| `optimal_thresholds.json` | Computed thresholds, preset profiles, calibration params |
| `calibration_report.md` | Full markdown report with score distributions, FP/FN analysis |

## Statistics

- **Total examples**: 294
- **Expected threat counts**: prompt_injection: 77, jailbreak: 67, pii: 76
- **Difficulty distribution**: easy: 108, medium: 106, hard: 80
