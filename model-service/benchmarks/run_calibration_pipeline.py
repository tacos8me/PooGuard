"""
End-to-end Calibration Pipeline Runner for ClawGuard.

Takes benchmark raw_scores.json (from run_benchmark.py), feeds labeled data to
the model-service POST /calibrate endpoint to fit Platt calibrators, then
re-scores the benchmark with the now-calibrated model and runs threshold
optimization on both uncalibrated and calibrated scores for a before/after
comparison.

Steps:
  1. Load raw_scores.json (uncalibrated benchmark results)
  2. Extract per-category (raw_scores, true_labels) pairs
  3. POST /calibrate to fit Platt scaling calibrators on the model-service
  4. Re-score each benchmark example via POST /analyze (now with calibration active)
  5. Run optimize_thresholds.py on both raw and calibrated scores
  6. Output final calibration_report.md with before/after delta table

Usage:
  python run_calibration_pipeline.py [options]

  --input       Path to raw_scores.json (default: raw_scores.json)
  --output-dir  Directory for output files (default: .)
  --model-url   Model-service base URL (default: http://localhost:8000)
  --api-key     Model-service API key (default: from MODEL_SERVICE_API_KEY env)
  --method      Calibration method: platt or isotonic (default: platt)
  --skip-rescore  Skip re-scoring, only fit calibrators and optimize existing scores
  --local-calibrate  Apply calibration client-side using Platt/isotonic params (no re-inference)
"""

import argparse
import json
import math
import os
import sys
import time
from pathlib import Path

import requests

# Import the optimization module (sibling file)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from optimize_thresholds import (
    CATEGORIES,
    extract_scores_and_labels,
    find_optimal_thresholds,
    compute_score_distribution,
    build_preset_profiles,
    generate_report,
)


def load_benchmark(path: str) -> list[dict]:
    """Load raw_scores.json benchmark results."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "results" in data:
        return data["results"]
    if isinstance(data, list):
        return data
    raise ValueError(f"Unexpected format in {path}")


def extract_calibration_data(entries: list[dict]) -> dict:
    """Extract per-category raw_scores and true_labels for the /calibrate endpoint.

    Returns dict in the format expected by POST /calibrate:
        {
            "prompt_injection": {"raw_scores": [...], "true_labels": [...]},
            "jailbreak": {"raw_scores": [...], "true_labels": [...]},
            "pii": {"raw_scores": [...], "true_labels": [...]}
        }
    """
    # Only the 3 categories supported by the calibration pipeline (not semantic_similarity)
    calibration_categories = ["prompt_injection", "jailbreak", "pii"]
    result = {}

    for cat in calibration_categories:
        scores, labels = extract_scores_and_labels(entries, cat)
        if scores:
            result[cat] = {
                "raw_scores": scores,
                "true_labels": labels,
            }
            print(f"  {cat}: {len(scores)} samples ({sum(labels)} positive, {len(labels) - sum(labels)} negative)")
        else:
            print(f"  WARNING: No data for {cat}")

    return result


def call_calibrate(base_url: str, api_key: str, calibration_data: dict, method: str = "platt") -> dict:
    """Call POST /calibrate on the model-service."""
    url = f"{base_url}/calibrate"
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    payload = {
        "results": calibration_data,
        "method": method,
    }

    print(f"\nCalling POST {url} (method={method})...")
    resp = requests.post(url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    result = resp.json()
    print(f"  Status: {result.get('status')}")
    print(f"  Calibrated: {result.get('calibrated')}")
    for cat, params in result.get("categories", {}).items():
        cal_type = params.get("type", "unknown")
        if cal_type == "platt":
            print(f"  {cat}: Platt(A={params.get('A', 0):.4f}, B={params.get('B', 0):.4f})")
        elif cal_type == "isotonic":
            n_points = len(params.get("x_points", []))
            print(f"  {cat}: Isotonic({n_points} interpolation points)")
        else:
            print(f"  {cat}: {cal_type}")
    return result


def rescore_benchmark(base_url: str, api_key: str, entries: list[dict]) -> list[dict]:
    """Re-score each benchmark example via POST /analyze with calibration active.

    Returns entries with a new 'calibrated_scores' field containing the
    calibrated model scores.
    """
    url = f"{base_url}/analyze"
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    total = len(entries)
    rescored = []

    print(f"\nRe-scoring {total} examples with calibrated model...")
    start_time = time.time()

    for i, entry in enumerate(entries):
        text = entry.get("text", "")
        if not text:
            rescored.append(entry)
            continue

        try:
            resp = requests.post(url, json={"text": text}, headers=headers, timeout=60)
            resp.raise_for_status()
            result = resp.json()

            # Store calibrated scores alongside the original raw_scores
            calibrated = {
                "prompt_injection": result.get("prompt_injection_score", 0.0),
                "jailbreak": result.get("jailbreak_score", 0.0),
                "pii": result.get("pii_score", 0.0),
                "semantic_similarity": result.get("semantic_similarity_score", 0.0),
            }
            entry_copy = {**entry, "calibrated_scores": calibrated}
            rescored.append(entry_copy)

        except requests.RequestException as e:
            print(f"  ERROR scoring entry {i}: {e}")
            rescored.append(entry)

        # Progress
        if (i + 1) % 25 == 0 or (i + 1) == total:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            eta = (total - i - 1) / rate if rate > 0 else 0
            print(f"  [{i+1}/{total}] {rate:.1f} examples/sec, ETA: {eta:.0f}s")

    return rescored


def apply_calibration_locally(entries: list[dict], calibration_params: dict) -> list[dict]:
    """Apply calibration client-side using params from POST /calibrate response.

    Supports Platt (sigmoid) and isotonic (piecewise-linear) calibration.
    Much faster than re-scoring via POST /analyze since it skips model inference.

    Args:
        entries: Benchmark entries with raw_scores.{category} fields.
        calibration_params: The 'categories' dict from the /calibrate response,
            e.g. {"prompt_injection": {"type": "platt", "A": 3.93, "B": -1.96}, ...}

    Returns:
        Entries with a new 'calibrated_scores' field.
    """
    calibrated_categories = ["prompt_injection", "jailbreak", "pii"]
    result = []

    for entry in entries:
        raw = entry.get("raw_scores", {})
        cal_scores = {}

        for cat in calibrated_categories:
            raw_score = raw.get(cat, 0.0)
            params = calibration_params.get(cat, {})
            cal_type = params.get("type", "noop")

            if cal_type == "platt":
                A = params.get("A", 1.0)
                B = params.get("B", 0.0)
                exponent = A * raw_score + B
                exponent = max(-500.0, min(500.0, exponent))
                cal_scores[cat] = 1.0 / (1.0 + math.exp(-exponent))
            elif cal_type == "isotonic":
                x_pts = params.get("x_points", [])
                y_pts = params.get("y_points", [])
                cal_scores[cat] = _isotonic_interpolate(raw_score, x_pts, y_pts)
            else:
                cal_scores[cat] = raw_score

        # Semantic similarity is not calibrated; pass through raw score
        cal_scores["semantic_similarity"] = raw.get("semantic_similarity", 0.0)

        result.append({**entry, "calibrated_scores": cal_scores})

    return result


def _isotonic_interpolate(score: float, x_pts: list[float], y_pts: list[float]) -> float:
    """Piecewise-linear interpolation for isotonic calibration."""
    if not x_pts:
        return score
    if score <= x_pts[0]:
        return y_pts[0]
    if score >= x_pts[-1]:
        return y_pts[-1]

    # Binary search for interval
    lo, hi = 0, len(x_pts) - 1
    while lo < hi - 1:
        mid = (lo + hi) // 2
        if x_pts[mid] <= score:
            lo = mid
        else:
            hi = mid

    x0, x1 = x_pts[lo], x_pts[hi]
    y0, y1 = y_pts[lo], y_pts[hi]
    if x1 == x0:
        return y0
    t = (score - x0) / (x1 - x0)
    return max(0.0, min(1.0, y0 + t * (y1 - y0)))


def extract_calibrated_scores_and_labels(
    entries: list[dict], category: str
) -> tuple[list[float], list[int]]:
    """Extract calibrated scores and labels from re-scored entries."""
    scores = []
    labels = []

    for entry in entries:
        cal_scores = entry.get("calibrated_scores")
        if cal_scores is None:
            continue

        score = cal_scores.get(category)
        if score is None:
            continue

        # Label extraction (same logic as optimize_thresholds)
        label = None
        if "expected_threats" in entry:
            expected = entry["expected_threats"]
            if category == "semantic_similarity":
                label = 1 if any(t in expected for t in ["prompt_injection", "jailbreak"]) else 0
            else:
                label = 1 if category in expected else 0

        if label is None:
            continue

        scores.append(float(score))
        labels.append(int(label))

    return scores, labels


def main():
    parser = argparse.ArgumentParser(description="End-to-end ClawGuard calibration pipeline")
    parser.add_argument("--input", "-i", default="raw_scores.json",
                        help="Path to raw_scores.json (benchmark results)")
    parser.add_argument("--output-dir", "-o", default=".",
                        help="Output directory for results")
    parser.add_argument("--model-url", default=os.getenv("MODEL_SERVICE_URL", "http://localhost:8000"),
                        help="Model-service base URL")
    parser.add_argument("--api-key", default=os.getenv("MODEL_SERVICE_API_KEY", ""),
                        help="Model-service API key")
    parser.add_argument("--method", default="platt", choices=["platt", "isotonic"],
                        help="Calibration method")
    parser.add_argument("--skip-rescore", action="store_true",
                        help="Skip re-scoring; only fit calibrators and optimize existing scores")
    parser.add_argument("--local-calibrate", action="store_true",
                        help="Apply calibration client-side using Platt/isotonic params (no re-inference)")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.api_key:
        print("ERROR: MODEL_SERVICE_API_KEY not set. Provide --api-key or set the env var.")
        sys.exit(1)

    # Step 1: Load benchmark results
    print(f"Step 1: Loading benchmark results from {args.input}...")
    entries = load_benchmark(args.input)
    print(f"  Loaded {len(entries)} entries")

    # Step 2: Extract calibration data
    print("\nStep 2: Extracting per-category calibration data...")
    calibration_data = extract_calibration_data(entries)

    # Step 3: Call POST /calibrate
    print("\nStep 3: Fitting calibrators on model-service...")
    calibration_result = call_calibrate(args.model_url, args.api_key, calibration_data, args.method)

    # Step 4: Optimize thresholds on uncalibrated scores
    print("\nStep 4: Optimizing thresholds on uncalibrated scores...")
    raw_category_results = {}
    raw_category_distributions = {}
    for cat in CATEGORIES:
        scores, labels = extract_scores_and_labels(entries, cat)
        if not scores:
            continue
        raw_category_results[cat] = find_optimal_thresholds(scores, labels)
        raw_category_distributions[cat] = compute_score_distribution(scores, labels)
        best = raw_category_results[cat]["max_f1"]
        print(f"  {cat}: F1={best.get('f1', 0):.3f} at threshold={best.get('threshold', 'N/A')}")

    # Step 5: Re-score with calibrated model (optional)
    calibrated_entries = None
    calibrated_results = None

    if args.local_calibrate:
        # Fast path: apply calibration client-side using A,B params
        cal_params = calibration_result.get("categories", {})
        print("\nStep 5: Applying calibration locally (no re-inference)...")
        rescored = apply_calibration_locally(entries, cal_params)

        # Save re-scored results
        rescored_path = output_dir / "calibrated_scores.json"
        with open(rescored_path, "w", encoding="utf-8") as f:
            json.dump(rescored, f, indent=2)
        print(f"  Saved calibrated scores to {rescored_path}")

        # Optimize thresholds on calibrated scores
        print("\nStep 6: Optimizing thresholds on locally calibrated scores...")
        calibrated_entries = rescored
        calibrated_results = {}
        for cat in CATEGORIES:
            scores, labels = extract_calibrated_scores_and_labels(rescored, cat)
            if not scores:
                continue
            calibrated_results[cat] = find_optimal_thresholds(scores, labels)
            best = calibrated_results[cat]["max_f1"]
            print(f"  {cat}: F1={best.get('f1', 0):.3f} at threshold={best.get('threshold', 'N/A')}")

    elif not args.skip_rescore:
        # Full path: re-score through model service (slow, ~3-6s per example)
        print("\nStep 5: Re-scoring benchmark with calibrated model...")
        rescored = rescore_benchmark(args.model_url, args.api_key, entries)

        # Save re-scored results
        rescored_path = output_dir / "calibrated_scores.json"
        with open(rescored_path, "w", encoding="utf-8") as f:
            json.dump(rescored, f, indent=2)
        print(f"  Saved calibrated scores to {rescored_path}")

        # Optimize thresholds on calibrated scores
        print("\nStep 6: Optimizing thresholds on calibrated scores...")
        calibrated_entries = rescored
        calibrated_results = {}
        for cat in CATEGORIES:
            scores, labels = extract_calibrated_scores_and_labels(rescored, cat)
            if not scores:
                continue
            calibrated_results[cat] = find_optimal_thresholds(scores, labels)
            best = calibrated_results[cat]["max_f1"]
            print(f"  {cat}: F1={best.get('f1', 0):.3f} at threshold={best.get('threshold', 'N/A')}")
    else:
        print("\nStep 5: Skipping re-score (--skip-rescore)")

    # Step 6/7: Build presets and generate report
    # Use calibrated results for presets if available, else raw
    final_results = calibrated_results if calibrated_results else raw_category_results
    preset_profiles = build_preset_profiles(final_results)

    print("\n--- Final Preset Profiles ---")
    for name, profile in preset_profiles.items():
        print(f"  {name}: {profile}")

    # Save optimal thresholds JSON
    thresholds_output = {
        "presets": preset_profiles,
        "per_category": {},
        "calibration": {
            "method": args.method,
            "calibrated": calibration_result.get("calibrated", False),
            "categories": calibration_result.get("categories", {}),
        },
    }
    for cat, results in final_results.items():
        thresholds_output["per_category"][cat] = {
            "max_f1_threshold": results["max_f1"].get("threshold"),
            "max_f1_score": results["max_f1"].get("f1"),
            "youden_j_threshold": results["max_youden_j"].get("threshold"),
            "precision_95_threshold": results.get("target_precision_95", {}).get("threshold"),
            "recall_95_threshold": results.get("target_recall_95", {}).get("threshold"),
        }

    thresholds_path = output_dir / "optimal_thresholds.json"
    with open(thresholds_path, "w", encoding="utf-8") as f:
        json.dump(thresholds_output, f, indent=2)
    print(f"\nSaved optimal thresholds to {thresholds_path}")

    # Generate report
    report_entries = calibrated_entries if calibrated_entries else entries
    report = generate_report(
        raw_category_results,
        raw_category_distributions,
        preset_profiles,
        entries,
        calibrated_entries,
        calibrated_results,
    )
    report_path = output_dir / "calibration_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"Saved calibration report to {report_path}")

    # Summary
    print("\n" + "=" * 60)
    print("CALIBRATION PIPELINE COMPLETE")
    print("=" * 60)
    print(f"  Method: {args.method}")
    print(f"  Calibrated: {calibration_result.get('calibrated', False)}")
    if calibrated_results:
        print("  Before/After F1 comparison:")
        for cat in CATEGORIES:
            if cat in raw_category_results and cat in calibrated_results:
                before_f1 = raw_category_results[cat]["max_f1"].get("f1", 0)
                after_f1 = calibrated_results[cat]["max_f1"].get("f1", 0)
                delta = after_f1 - before_f1
                sign = "+" if delta >= 0 else ""
                print(f"    {cat}: {before_f1:.3f} -> {after_f1:.3f} ({sign}{delta:.3f})")
    print(f"\n  Output files:")
    print(f"    {thresholds_path}")
    print(f"    {report_path}")
    if not args.skip_rescore:
        print(f"    {output_dir / 'calibrated_scores.json'}")


if __name__ == "__main__":
    main()
