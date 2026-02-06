"""
Benchmark runner for ClawGuard calibration dataset.

Sends each example to the live model-service /analyze endpoint and collects raw scores.
Results are saved to raw_scores.json for analysis.

Usage:
    python run_benchmark.py [dataset_path] [output_path]
    python run_benchmark.py  # defaults: calibration_dataset.json -> raw_scores.json
"""

import json
import os
import sys
import time

import requests

ENDPOINT = os.getenv("MODEL_SERVICE_URL", "http://localhost:8000") + "/analyze"
API_KEY = os.getenv("MODEL_SERVICE_API_KEY", "")
TIMEOUT = 60  # seconds per request


def build_headers():
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    return headers


def run_benchmark(dataset_path, output_path):
    with open(dataset_path, encoding="utf-8") as f:
        dataset = json.load(f)

    total = len(dataset)
    results = []
    errors = 0
    start_all = time.time()
    headers = build_headers()

    print(f"Running benchmark: {total} examples against {ENDPOINT}")
    print(f"{'='*80}")

    for i, example in enumerate(dataset):
        text = example["text"]

        # Skip empty/whitespace-only inputs (model requires min_length=1)
        if not text or not text.strip():
            results.append({
                **example,
                "raw_scores": {
                    "prompt_injection": 0.0,
                    "jailbreak": 0.0,
                    "pii": 0.0,
                    "semantic_similarity": 0.0,
                },
                "model_blocked": False,
                "model_threats": [],
                "latency_ms": 0.0,
                "error": None,
                "skipped": True,
            })
            print(f"[{i+1:3d}/{total}] SKIP (empty) id={example['id']}")
            continue

        try:
            resp = requests.post(
                ENDPOINT,
                json={"text": text},
                headers=headers,
                timeout=TIMEOUT,
            )
            resp.raise_for_status()
            scores = resp.json()

            results.append({
                **example,
                "raw_scores": {
                    "prompt_injection": scores["prompt_injection_score"],
                    "jailbreak": scores["jailbreak_score"],
                    "pii": scores["pii_score"],
                    "semantic_similarity": scores["semantic_similarity_score"],
                },
                "model_blocked": scores["blocked"],
                "model_threats": scores["detected_threats"],
                "latency_ms": scores["processing_time_ms"],
                "error": None,
                "skipped": False,
            })

            pi = scores["prompt_injection_score"]
            jb = scores["jailbreak_score"]
            pii = scores["pii_score"]
            sem = scores["semantic_similarity_score"]
            ms = scores["processing_time_ms"]
            cat = example["category"]
            blocked = "BLOCKED" if scores["blocked"] else "ok"

            print(
                f"[{i+1:3d}/{total}] {cat:18s} | PI={pi:.3f} JB={jb:.3f} PII={pii:.3f} SEM={sem:.3f} | {ms:6.0f}ms | {blocked}"
            )

        except Exception as e:
            errors += 1
            results.append({
                **example,
                "raw_scores": {
                    "prompt_injection": 0.0,
                    "jailbreak": 0.0,
                    "pii": 0.0,
                    "semantic_similarity": 0.0,
                },
                "model_blocked": False,
                "model_threats": [],
                "latency_ms": 0.0,
                "error": str(e),
                "skipped": False,
            })
            print(f"[{i+1:3d}/{total}] ERROR id={example['id']}: {e}")

        # Save intermediate results every 25 examples
        if (i + 1) % 25 == 0:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)

    elapsed = time.time() - start_all

    # Final save
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"{'='*80}")
    print(f"Complete: {total} examples in {elapsed:.1f}s ({elapsed/total:.1f}s avg)")
    print(f"Errors: {errors}")
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "calibration_dataset.json"
    )
    output_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "raw_scores.json"
    )
    run_benchmark(dataset_path, output_path)
