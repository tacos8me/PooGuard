"""
Threshold Optimization Script for PooGuard

Consumes analysis_report.json (benchmark scores + true labels) and computes
optimal thresholds per category using multiple strategies:
  - Maximize F1 score
  - Maximize Youden's J statistic (TPR - FPR)
  - Target precision (95%) and report recall
  - Target recall (95%) and report precision

Also generates three preset profiles:
  - High Security: maximize recall (accept more false positives)
  - Balanced: maximize F1
  - Low Friction: maximize precision (accept more false negatives)

Outputs:
  - optimal_thresholds.json: recommended thresholds and preset profiles
  - calibration_report.md: full accuracy analysis report

Usage:
  python optimize_thresholds.py [--input analysis_report.json] [--calibrated calibrated_report.json]
"""

import argparse
import json
import math
import os
import sys
from collections import defaultdict
from pathlib import Path

# Categories to optimize
CATEGORIES = ["prompt_injection", "jailbreak", "pii", "semantic_similarity"]

# Score field mapping (analysis_report.json field -> category name)
SCORE_FIELDS = {
    "prompt_injection": "prompt_injection_score",
    "jailbreak": "jailbreak_score",
    "pii": "pii_score",
    "semantic_similarity": "semantic_similarity_score",
}

# Label field mapping (analysis_report.json field -> category name)
LABEL_FIELDS = {
    "prompt_injection": "is_prompt_injection",
    "jailbreak": "is_jailbreak",
    "pii": "is_pii",
    "semantic_similarity": "is_attack",  # semantic uses general attack label
}


def load_report(path: str) -> list[dict]:
    """Load analysis_report.json and return list of benchmark entries."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    # Support both {"results": [...]} and plain [...] formats
    if isinstance(data, dict) and "results" in data:
        return data["results"]
    if isinstance(data, list):
        return data
    raise ValueError(f"Unexpected format in {path}")


def compute_metrics_at_threshold(
    scores: list[float], labels: list[int], threshold: float
) -> dict:
    """Compute TP, FP, TN, FN, precision, recall, F1, FPR at a given threshold."""
    tp = fp = tn = fn = 0
    for score, label in zip(scores, labels):
        predicted = 1 if score >= threshold else 0
        if predicted == 1 and label == 1:
            tp += 1
        elif predicted == 1 and label == 0:
            fp += 1
        elif predicted == 0 and label == 0:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = recall  # same as recall

    return {
        "threshold": threshold,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "tpr": tpr,
        "accuracy": (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0,
    }


def find_optimal_thresholds(
    scores: list[float], labels: list[int]
) -> dict:
    """Find optimal thresholds using multiple strategies."""
    # Generate candidate thresholds from unique scores + fine grid
    candidates = sorted(set(scores))
    # Add a fine grid for coverage
    fine_grid = [i / 100 for i in range(0, 101)]
    candidates = sorted(set(candidates + fine_grid))

    best_f1 = {"f1": -1}
    best_youden = {"youden_j": -1}
    best_precision_95 = None  # highest recall where precision >= 0.95
    best_recall_95 = None  # highest precision where recall >= 0.95

    all_metrics = []

    for t in candidates:
        m = compute_metrics_at_threshold(scores, labels, t)
        all_metrics.append(m)

        # Best F1
        if m["f1"] > best_f1["f1"]:
            best_f1 = {**m, "strategy": "max_f1"}

        # Youden's J = TPR - FPR (= sensitivity + specificity - 1)
        youden_j = m["tpr"] - m["fpr"]
        if youden_j > best_youden.get("youden_j", -1):
            best_youden = {**m, "youden_j": youden_j, "strategy": "max_youden_j"}

        # Target precision >= 0.95, maximize recall
        if m["precision"] >= 0.95:
            if best_precision_95 is None or m["recall"] > best_precision_95["recall"]:
                best_precision_95 = {**m, "strategy": "target_precision_95"}

        # Target recall >= 0.95, maximize precision
        if m["recall"] >= 0.95:
            if best_recall_95 is None or m["precision"] > best_recall_95["precision"]:
                best_recall_95 = {**m, "strategy": "target_recall_95"}

    return {
        "max_f1": best_f1,
        "max_youden_j": best_youden,
        "target_precision_95": best_precision_95 or {"strategy": "target_precision_95", "note": "No threshold achieves 95% precision"},
        "target_recall_95": best_recall_95 or {"strategy": "target_recall_95", "note": "No threshold achieves 95% recall"},
        "all_metrics": all_metrics,
    }


def extract_scores_and_labels(
    entries: list[dict], category: str
) -> tuple[list[float], list[int]]:
    """Extract scores and labels for a given category from benchmark entries.

    Supports multiple data formats:
    1. run_benchmark.py output: raw_scores.{category}, expected_threats[]
    2. analysis_report.json: scores.{score_field}, labels.{label_field}
    3. Flat format: {score_field}, {label_field}
    """
    score_field = SCORE_FIELDS[category]
    label_field = LABEL_FIELDS[category]

    scores = []
    labels = []

    for entry in entries:
        # --- Extract score ---
        score = None
        # Format 1: raw_scores.{category} (from run_benchmark.py)
        if score is None and "raw_scores" in entry:
            score = entry["raw_scores"].get(category)
        # Format 2: scores.{score_field} (from analysis_report.json)
        if score is None and "scores" in entry:
            score = entry["scores"].get(score_field)
        # Format 3: flat {score_field}
        if score is None:
            score = entry.get(score_field)
        if score is None:
            continue

        # --- Extract label ---
        label = None
        # Format 1: expected_threats[] (from calibration_dataset.json / run_benchmark.py)
        if "expected_threats" in entry:
            expected = entry["expected_threats"]
            if category == "semantic_similarity":
                # Semantic: positive if any attack-type threat is expected
                label = 1 if any(t in expected for t in ["prompt_injection", "jailbreak"]) else 0
            else:
                label = 1 if category in expected else 0
        # Format 2: labels.{label_field}
        elif "labels" in entry:
            label = entry["labels"].get(label_field)
        # Format 3: flat {label_field}
        else:
            label = entry.get(label_field)

        if label is None:
            continue

        scores.append(float(score))
        labels.append(int(label))

    return scores, labels


def compute_score_distribution(scores: list[float], labels: list[int]) -> dict:
    """Compute score distribution statistics for positive and negative classes."""
    pos_scores = [s for s, l in zip(scores, labels) if l == 1]
    neg_scores = [s for s, l in zip(scores, labels) if l == 0]

    def stats(vals):
        if not vals:
            return {"count": 0, "min": 0, "max": 0, "mean": 0, "median": 0, "p25": 0, "p75": 0}
        sorted_vals = sorted(vals)
        n = len(sorted_vals)
        return {
            "count": n,
            "min": round(sorted_vals[0], 4),
            "max": round(sorted_vals[-1], 4),
            "mean": round(sum(sorted_vals) / n, 4),
            "median": round(sorted_vals[n // 2], 4),
            "p25": round(sorted_vals[n // 4], 4),
            "p75": round(sorted_vals[3 * n // 4], 4),
        }

    return {
        "positive_class": stats(pos_scores),
        "negative_class": stats(neg_scores),
    }


def _get_score_and_label(entry: dict, category: str) -> tuple[float | None, int | None]:
    """Extract score and label from a benchmark entry for a given category."""
    score_field = SCORE_FIELDS[category]

    # Score extraction
    score = None
    if "raw_scores" in entry:
        score = entry["raw_scores"].get(category)
    if score is None and "scores" in entry:
        score = entry["scores"].get(score_field)
    if score is None:
        score = entry.get(score_field)

    # Label extraction
    label = None
    if "expected_threats" in entry:
        expected = entry["expected_threats"]
        if category == "semantic_similarity":
            label = 1 if any(t in expected for t in ["prompt_injection", "jailbreak"]) else 0
        else:
            label = 1 if category in expected else 0
    elif "labels" in entry:
        label_field = LABEL_FIELDS[category]
        label = entry["labels"].get(label_field)
    else:
        label_field = LABEL_FIELDS[category]
        label = entry.get(label_field)

    return (float(score) if score is not None else None,
            int(label) if label is not None else None)


def find_false_positive_examples(
    entries: list[dict], category: str, threshold: float, top_n: int = 5
) -> list[dict]:
    """Find the top-N clean examples that score highest (false positives)."""
    fps = []
    for entry in entries:
        score, label = _get_score_and_label(entry, category)
        if score is None or label is None:
            continue
        if label == 0 and score >= threshold:
            fps.append({
                "text": entry.get("text", "")[:120],
                "score": round(score, 4),
                "category": category,
                "description": entry.get("description", ""),
            })
    fps.sort(key=lambda x: x["score"], reverse=True)
    return fps[:top_n]


def find_false_negative_examples(
    entries: list[dict], category: str, threshold: float, top_n: int = 5
) -> list[dict]:
    """Find the top-N threat examples that score lowest (false negatives)."""
    fns = []
    for entry in entries:
        score, label = _get_score_and_label(entry, category)
        if score is None or label is None:
            continue
        if label == 1 and score < threshold:
            fns.append({
                "text": entry.get("text", "")[:120],
                "score": round(score, 4),
                "category": category,
                "description": entry.get("description", ""),
            })
    fns.sort(key=lambda x: x["score"])
    return fns[:top_n]


def build_preset_profiles(category_results: dict) -> dict:
    """Build three preset profiles based on optimization results.

    - High Security: maximize recall (use target_recall_95 threshold, or lower F1 threshold)
    - Balanced: maximize F1 score
    - Low Friction: maximize precision (use target_precision_95 threshold, or higher threshold)
    """
    profiles = {
        "high_security": {},
        "balanced": {},
        "low_friction": {},
    }

    for cat, results in category_results.items():
        # Balanced = max F1
        balanced_t = results["max_f1"].get("threshold", 0.5)

        # High Security = target 95% recall (lower threshold to catch more threats)
        if "threshold" in results.get("target_recall_95", {}):
            high_sec_t = results["target_recall_95"]["threshold"]
        else:
            # Fallback: use Youden's J threshold or 20% below balanced
            high_sec_t = results["max_youden_j"].get("threshold", max(0.1, balanced_t - 0.2))

        # Low Friction = target 95% precision (higher threshold, fewer false positives)
        if "threshold" in results.get("target_precision_95", {}):
            low_fric_t = results["target_precision_95"]["threshold"]
        else:
            # Fallback: use 20% above balanced
            low_fric_t = min(0.95, balanced_t + 0.2)

        profiles["high_security"][cat] = round(high_sec_t, 2)
        profiles["balanced"][cat] = round(balanced_t, 2)
        profiles["low_friction"][cat] = round(low_fric_t, 2)

    return profiles


def generate_report(
    category_results: dict,
    category_distributions: dict,
    preset_profiles: dict,
    entries: list[dict],
    calibrated_entries: list[dict] | None = None,
    calibrated_results: dict | None = None,
) -> str:
    """Generate the full calibration report as markdown."""
    lines = []
    lines.append("# PooGuard Threshold Calibration Report")
    lines.append("")
    lines.append(f"Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Dataset size: {len(entries)} examples")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("This report presents the optimal detection thresholds for PooGuard's threat")
    lines.append("classification system. Thresholds were computed by analyzing model scores against")
    lines.append("a labeled benchmark dataset and optimizing for different operational goals.")
    lines.append("")

    # Preset Profiles
    lines.append("## Recommended Preset Profiles")
    lines.append("")
    lines.append("| Profile | Use Case | PI Threshold | JB Threshold | PII Threshold | Semantic Threshold |")
    lines.append("|---------|----------|-------------|-------------|--------------|-------------------|")
    for profile_name, profile_desc in [
        ("high_security", "Maximize detection (accept more false positives)"),
        ("balanced", "Best F1 score (balanced precision/recall)"),
        ("low_friction", "Minimize false positives (accept some missed threats)"),
    ]:
        p = preset_profiles[profile_name]
        pi = p.get("prompt_injection", "N/A")
        jb = p.get("jailbreak", "N/A")
        pii = p.get("pii", "N/A")
        sem = p.get("semantic_similarity", "N/A")
        label = profile_name.replace("_", " ").title()
        lines.append(f"| {label} | {profile_desc} | {pi} | {jb} | {pii} | {sem} |")
    lines.append("")

    # Per-Category Analysis
    for cat in CATEGORIES:
        if cat not in category_results:
            continue

        results = category_results[cat]
        dist = category_distributions.get(cat, {})
        cat_label = cat.replace("_", " ").title()

        lines.append(f"## {cat_label}")
        lines.append("")

        # Score Distribution
        lines.append("### Score Distribution")
        lines.append("")
        pos = dist.get("positive_class", {})
        neg = dist.get("negative_class", {})
        lines.append(f"- **Positive examples** (true threats): {pos.get('count', 0)} samples")
        lines.append(f"  - Range: [{pos.get('min', 0)}, {pos.get('max', 0)}], Mean: {pos.get('mean', 0)}, Median: {pos.get('median', 0)}")
        lines.append(f"  - IQR: [{pos.get('p25', 0)}, {pos.get('p75', 0)}]")
        lines.append(f"- **Negative examples** (clean inputs): {neg.get('count', 0)} samples")
        lines.append(f"  - Range: [{neg.get('min', 0)}, {neg.get('max', 0)}], Mean: {neg.get('mean', 0)}, Median: {neg.get('median', 0)}")
        lines.append(f"  - IQR: [{neg.get('p25', 0)}, {neg.get('p75', 0)}]")
        lines.append("")

        # Optimal Thresholds
        lines.append("### Optimal Thresholds")
        lines.append("")
        lines.append("| Strategy | Threshold | Precision | Recall | F1 | FPR |")
        lines.append("|----------|-----------|-----------|--------|-----|-----|")
        for strategy_key, strategy_label in [
            ("max_f1", "Max F1"),
            ("max_youden_j", "Max Youden's J"),
            ("target_precision_95", "Precision >= 95%"),
            ("target_recall_95", "Recall >= 95%"),
        ]:
            r = results.get(strategy_key, {})
            if "threshold" in r:
                lines.append(
                    f"| {strategy_label} | {r['threshold']:.2f} | "
                    f"{r.get('precision', 0):.3f} | {r.get('recall', 0):.3f} | "
                    f"{r.get('f1', 0):.3f} | {r.get('fpr', 0):.3f} |"
                )
            else:
                note = r.get("note", "Not achievable")
                lines.append(f"| {strategy_label} | - | - | - | - | {note} |")
        lines.append("")

        # False Positive Analysis
        balanced_t = results["max_f1"].get("threshold", 0.5)
        fps = find_false_positive_examples(entries, cat, balanced_t)
        if fps:
            lines.append("### False Positive Analysis (at balanced threshold)")
            lines.append("")
            lines.append("Clean examples with highest scores (most likely to be incorrectly flagged):")
            lines.append("")
            for i, fp in enumerate(fps, 1):
                lines.append(f"{i}. Score: {fp['score']} -- `{fp['text']}`")
            lines.append("")

        # False Negative Analysis
        fns = find_false_negative_examples(entries, cat, balanced_t)
        if fns:
            lines.append("### False Negative Analysis (at balanced threshold)")
            lines.append("")
            lines.append("Threat examples with lowest scores (most likely to be missed):")
            lines.append("")
            for i, fn in enumerate(fns, 1):
                lines.append(f"{i}. Score: {fn['score']} -- `{fn['text']}`")
            lines.append("")

    # Before/After Calibration (if calibrated data available)
    if calibrated_entries and calibrated_results:
        lines.append("## Before vs After Calibration")
        lines.append("")
        lines.append("| Category | Metric | Before | After | Delta |")
        lines.append("|----------|--------|--------|-------|-------|")
        for cat in CATEGORIES:
            if cat not in category_results or cat not in calibrated_results:
                continue
            before = category_results[cat]["max_f1"]
            after = calibrated_results[cat]["max_f1"]
            if "f1" in before and "f1" in after:
                for metric in ["f1", "precision", "recall"]:
                    b = before.get(metric, 0)
                    a = after.get(metric, 0)
                    delta = a - b
                    sign = "+" if delta >= 0 else ""
                    cat_label = cat.replace("_", " ").title()
                    lines.append(
                        f"| {cat_label} | {metric.title()} | {b:.3f} | {a:.3f} | {sign}{delta:.3f} |"
                    )
        lines.append("")

    # Methodology
    lines.append("## Methodology")
    lines.append("")
    lines.append("### Threshold Selection Strategies")
    lines.append("")
    lines.append("1. **Max F1 Score**: Finds the threshold that maximizes the harmonic mean of")
    lines.append("   precision and recall. Best for balanced operational use.")
    lines.append("")
    lines.append("2. **Max Youden's J**: Finds the threshold that maximizes TPR - FPR (equivalent")
    lines.append("   to maximizing sensitivity + specificity - 1). Optimal operating point on the")
    lines.append("   ROC curve.")
    lines.append("")
    lines.append("3. **Target Precision 95%**: Finds the lowest threshold where precision remains")
    lines.append("   at or above 95%. Reports the recall at that point. Best for low false-positive")
    lines.append("   requirements.")
    lines.append("")
    lines.append("4. **Target Recall 95%**: Finds the highest threshold where recall remains at or")
    lines.append("   above 95%. Reports the precision at that point. Best for high-security")
    lines.append("   environments where missing a threat is unacceptable.")
    lines.append("")
    lines.append("### Preset Profiles")
    lines.append("")
    lines.append("- **High Security**: Uses the target-recall-95% threshold. Catches nearly all")
    lines.append("  threats but may flag some clean inputs. Recommended for regulated environments,")
    lines.append("  financial systems, or when handling sensitive data.")
    lines.append("")
    lines.append("- **Balanced**: Uses the max-F1 threshold. Best overall accuracy with equal")
    lines.append("  weight on catching threats and avoiding false alarms. Recommended default for")
    lines.append("  most deployments.")
    lines.append("")
    lines.append("- **Low Friction**: Uses the target-precision-95% threshold. Very few false")
    lines.append("  positives at the cost of potentially missing some subtle attacks. Recommended")
    lines.append("  for high-traffic, low-risk workloads where user experience is paramount.")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Optimize PooGuard detection thresholds")
    parser.add_argument(
        "--input", "-i",
        default="analysis_report.json",
        help="Path to analysis_report.json (benchmark scores + true labels)",
    )
    parser.add_argument(
        "--calibrated", "-c",
        default=None,
        help="Path to calibrated analysis report (optional, for before/after comparison)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=".",
        help="Output directory for results",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load benchmark results
    print(f"Loading benchmark results from {args.input}...")
    entries = load_report(args.input)
    print(f"Loaded {len(entries)} benchmark entries")

    # Optimize thresholds per category
    category_results = {}
    category_distributions = {}

    for cat in CATEGORIES:
        scores, labels = extract_scores_and_labels(entries, cat)
        if not scores:
            print(f"  WARNING: No data for category '{cat}', skipping")
            continue

        n_pos = sum(labels)
        n_neg = len(labels) - n_pos
        print(f"\n  {cat}: {len(scores)} examples ({n_pos} positive, {n_neg} negative)")

        results = find_optimal_thresholds(scores, labels)
        category_results[cat] = results
        category_distributions[cat] = compute_score_distribution(scores, labels)

        # Print summary
        best = results["max_f1"]
        print(f"    Max F1: threshold={best.get('threshold', 'N/A'):.2f}, "
              f"F1={best.get('f1', 0):.3f}, "
              f"P={best.get('precision', 0):.3f}, R={best.get('recall', 0):.3f}")

        youden = results["max_youden_j"]
        print(f"    Max Youden's J: threshold={youden.get('threshold', 'N/A'):.2f}, "
              f"J={youden.get('youden_j', 0):.3f}")

    # Load calibrated results if provided
    calibrated_entries = None
    calibrated_results = None
    if args.calibrated and os.path.exists(args.calibrated):
        print(f"\nLoading calibrated results from {args.calibrated}...")
        calibrated_entries = load_report(args.calibrated)
        calibrated_results = {}
        for cat in CATEGORIES:
            scores, labels = extract_scores_and_labels(calibrated_entries, cat)
            if scores:
                calibrated_results[cat] = find_optimal_thresholds(scores, labels)

    # Build preset profiles
    preset_profiles = build_preset_profiles(category_results)

    print("\n--- Preset Profiles ---")
    for name, profile in preset_profiles.items():
        print(f"  {name}: {profile}")

    # Save optimal thresholds JSON
    thresholds_output = {
        "presets": preset_profiles,
        "per_category": {},
    }
    for cat, results in category_results.items():
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

    # Generate and save report
    report = generate_report(
        category_results,
        category_distributions,
        preset_profiles,
        entries,
        calibrated_entries,
        calibrated_results,
    )
    report_path = output_dir / "calibration_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"Saved calibration report to {report_path}")


if __name__ == "__main__":
    main()
