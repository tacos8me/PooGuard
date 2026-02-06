"""
Analyze benchmark results and compute optimal thresholds.

Reads raw_scores.json (output of run_benchmark.py) and produces:
- Per-category score distributions
- Confusion matrices
- Precision, recall, F1 per threat type
- Optimal thresholds via ROC analysis
- Summary report saved to analysis_report.json

Usage:
    python analyze_scores.py [raw_scores_path] [report_path]
"""

import json
import os
import sys
from collections import defaultdict


def compute_stats(values):
    """Compute descriptive statistics for a list of values."""
    if not values:
        return {"count": 0, "mean": 0, "median": 0, "std": 0, "min": 0, "max": 0,
                "p5": 0, "p25": 0, "p75": 0, "p95": 0}

    values = sorted(values)
    n = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    std = variance ** 0.5

    def percentile(p):
        k = (n - 1) * p / 100
        f = int(k)
        c = f + 1 if f + 1 < n else f
        d = k - f
        return values[f] + d * (values[c] - values[f])

    return {
        "count": n,
        "mean": round(mean, 4),
        "median": round(percentile(50), 4),
        "std": round(std, 4),
        "min": round(values[0], 4),
        "max": round(values[-1], 4),
        "p5": round(percentile(5), 4),
        "p25": round(percentile(25), 4),
        "p75": round(percentile(75), 4),
        "p95": round(percentile(95), 4),
    }


def compute_confusion_matrix(labels, predictions):
    """Compute TP, FP, TN, FN from binary labels and predictions."""
    tp = sum(1 for l, p in zip(labels, predictions) if l == 1 and p == 1)
    fp = sum(1 for l, p in zip(labels, predictions) if l == 0 and p == 1)
    tn = sum(1 for l, p in zip(labels, predictions) if l == 0 and p == 0)
    fn = sum(1 for l, p in zip(labels, predictions) if l == 1 and p == 0)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def compute_metrics(cm):
    """Compute precision, recall, F1 from confusion matrix."""
    tp, fp, fn = cm["tp"], cm["fp"], cm["fn"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (cm["tp"] + cm["tn"]) / (tp + fp + cm["tn"] + fn) if (tp + fp + cm["tn"] + fn) > 0 else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def find_optimal_threshold(labels, scores, method="f1"):
    """Find optimal threshold by sweeping and maximizing F1 or Youden's J."""
    best_threshold = 0.5
    best_metric = 0.0
    results_at_best = {}

    for t_int in range(1, 100):
        threshold = t_int / 100.0
        predictions = [1 if s >= threshold else 0 for s in scores]
        cm = compute_confusion_matrix(labels, predictions)
        metrics = compute_metrics(cm)

        if method == "f1":
            metric_value = metrics["f1"]
        elif method == "youden":
            # Youden's J = Sensitivity + Specificity - 1 = Recall + TNR - 1
            tnr = cm["tn"] / (cm["tn"] + cm["fp"]) if (cm["tn"] + cm["fp"]) > 0 else 0
            metric_value = metrics["recall"] + tnr - 1
        else:
            metric_value = metrics["f1"]

        if metric_value > best_metric:
            best_metric = metric_value
            best_threshold = threshold
            results_at_best = {**metrics, **cm, "threshold": threshold}

    return best_threshold, round(best_metric, 4), results_at_best


def analyze(raw_scores_path, report_path):
    with open(raw_scores_path, encoding="utf-8") as f:
        results = json.load(f)

    total = len(results)
    skipped = sum(1 for r in results if r.get("skipped"))
    errored = sum(1 for r in results if r.get("error"))
    valid_results = [r for r in results if not r.get("skipped") and not r.get("error")]

    print(f"Analyzing {total} results ({len(valid_results)} valid, {skipped} skipped, {errored} errors)")

    # ---- Score distributions by category ----
    score_distributions = {}
    threat_types = ["prompt_injection", "jailbreak", "pii", "semantic_similarity"]
    categories = ["clean", "prompt_injection", "jailbreak", "pii", "mixed"]

    for cat in categories:
        cat_results = [r for r in valid_results if r["category"] == cat]
        if not cat_results:
            continue
        score_distributions[cat] = {}
        for threat in threat_types:
            scores = [r["raw_scores"][threat] for r in cat_results]
            score_distributions[cat][threat] = compute_stats(scores)

    # ---- Current accuracy with default thresholds ----
    default_thresholds = {
        "prompt_injection": 0.7,
        "jailbreak": 0.7,
        "pii": 0.5,
        "semantic_similarity": 0.75,
    }

    current_metrics = {}
    for threat in ["prompt_injection", "jailbreak", "pii"]:
        labels = []
        scores = []
        for r in valid_results:
            expected = 1 if threat in r["expected_threats"] else 0
            labels.append(expected)
            scores.append(r["raw_scores"][threat])

        threshold = default_thresholds[threat]
        predictions = [1 if s >= threshold else 0 for s in scores]
        cm = compute_confusion_matrix(labels, predictions)
        metrics = compute_metrics(cm)
        current_metrics[threat] = {
            "threshold": threshold,
            **metrics,
            **cm,
        }

    # ---- Optimal thresholds (F1-maximizing) ----
    optimal_thresholds = {}
    for threat in ["prompt_injection", "jailbreak", "pii"]:
        labels = []
        scores = []
        for r in valid_results:
            expected = 1 if threat in r["expected_threats"] else 0
            labels.append(expected)
            scores.append(r["raw_scores"][threat])

        best_t_f1, best_f1, details_f1 = find_optimal_threshold(labels, scores, method="f1")
        best_t_youden, best_youden, details_youden = find_optimal_threshold(labels, scores, method="youden")

        optimal_thresholds[threat] = {
            "f1_optimal": {
                "threshold": best_t_f1,
                "f1": best_f1,
                **details_f1,
            },
            "youden_optimal": {
                "threshold": best_t_youden,
                "youden_j": best_youden,
                **details_youden,
            },
        }

    # ---- Semantic similarity analysis ----
    sem_labels = []
    sem_scores = []
    for r in valid_results:
        is_attack = 1 if r["category"] in ["prompt_injection", "jailbreak", "mixed"] else 0
        sem_labels.append(is_attack)
        sem_scores.append(r["raw_scores"]["semantic_similarity"])

    best_sem_t, best_sem_f1, sem_details = find_optimal_threshold(sem_labels, sem_scores, method="f1")
    sem_current_preds = [1 if s >= 0.75 else 0 for s in sem_scores]
    sem_current_cm = compute_confusion_matrix(sem_labels, sem_current_preds)
    sem_current_metrics = compute_metrics(sem_current_cm)

    optimal_thresholds["semantic_similarity"] = {
        "current": {"threshold": 0.75, **sem_current_metrics, **sem_current_cm},
        "f1_optimal": {"threshold": best_sem_t, "f1": best_sem_f1, **sem_details},
    }

    # ---- Latency statistics ----
    latencies = [r["latency_ms"] for r in valid_results if r["latency_ms"] > 0]
    latency_stats = compute_stats(latencies)

    # ---- Per-difficulty breakdown ----
    difficulty_analysis = {}
    for difficulty in ["easy", "medium", "hard"]:
        diff_results = [r for r in valid_results if r["difficulty"] == difficulty]
        if not diff_results:
            continue

        # Overall blocking accuracy for this difficulty
        correct = 0
        for r in diff_results:
            expected_blocked = len(r["expected_threats"]) > 0
            if r["model_blocked"] == expected_blocked:
                correct += 1

        difficulty_analysis[difficulty] = {
            "total": len(diff_results),
            "blocking_accuracy": round(correct / len(diff_results), 4),
        }

    # ---- False positive / false negative analysis ----
    false_positives = []
    false_negatives = []
    for r in valid_results:
        expected_blocked = len(r["expected_threats"]) > 0
        if r["model_blocked"] and not expected_blocked:
            false_positives.append({
                "id": r["id"],
                "text_preview": r["text"][:100],
                "category": r["category"],
                "scores": r["raw_scores"],
            })
        elif not r["model_blocked"] and expected_blocked:
            false_negatives.append({
                "id": r["id"],
                "text_preview": r["text"][:100],
                "category": r["category"],
                "difficulty": r["difficulty"],
                "expected_threats": r["expected_threats"],
                "scores": r["raw_scores"],
            })

    # ---- Build report ----
    report = {
        "summary": {
            "total_examples": total,
            "valid_examples": len(valid_results),
            "skipped": skipped,
            "errors": errored,
            "latency": latency_stats,
        },
        "score_distributions": score_distributions,
        "current_metrics": current_metrics,
        "optimal_thresholds": optimal_thresholds,
        "difficulty_analysis": difficulty_analysis,
        "false_positives": {
            "count": len(false_positives),
            "examples": false_positives[:20],
        },
        "false_negatives": {
            "count": len(false_negatives),
            "examples": false_negatives[:20],
        },
        "recommended_thresholds": {
            "prompt_injection": optimal_thresholds["prompt_injection"]["f1_optimal"]["threshold"],
            "jailbreak": optimal_thresholds["jailbreak"]["f1_optimal"]["threshold"],
            "pii": optimal_thresholds["pii"]["f1_optimal"]["threshold"],
            "semantic_similarity": optimal_thresholds["semantic_similarity"]["f1_optimal"]["threshold"],
        },
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # ---- Print summary ----
    print(f"\n{'='*80}")
    print("CALIBRATION ANALYSIS REPORT")
    print(f"{'='*80}")

    print(f"\nTotal: {total} examples ({len(valid_results)} valid)")
    print(f"Latency: mean={latency_stats['mean']:.0f}ms, p50={latency_stats['median']:.0f}ms, p95={latency_stats['p95']:.0f}ms")

    print(f"\n--- Current Metrics (default thresholds) ---")
    for threat, m in current_metrics.items():
        print(f"  {threat:20s}: threshold={m['threshold']:.2f} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} (TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']})")

    print(f"\n--- Optimal Thresholds (F1-maximizing) ---")
    for threat in ["prompt_injection", "jailbreak", "pii", "semantic_similarity"]:
        opt = optimal_thresholds[threat]["f1_optimal"]
        print(f"  {threat:20s}: threshold={opt['threshold']:.2f} F1={opt['f1']:.3f} P={opt['precision']:.3f} R={opt['recall']:.3f}")

    print(f"\n--- Difficulty Breakdown ---")
    for diff, m in difficulty_analysis.items():
        print(f"  {diff:8s}: {m['total']} examples, blocking_accuracy={m['blocking_accuracy']:.3f}")

    print(f"\n--- Error Analysis ---")
    print(f"  False positives (clean blocked):  {len(false_positives)}")
    print(f"  False negatives (threats missed): {len(false_negatives)}")

    if false_positives:
        print(f"\n  Top false positives:")
        for fp in false_positives[:5]:
            print(f"    id={fp['id']}: {fp['text_preview'][:60]}...")

    if false_negatives:
        print(f"\n  Top false negatives:")
        for fn in false_negatives[:5]:
            print(f"    id={fn['id']} ({fn['difficulty']}): {fn['text_preview'][:60]}...")

    print(f"\n--- Recommended Thresholds ---")
    for threat, t in report["recommended_thresholds"].items():
        print(f"  {threat:20s}: {t:.2f}")

    print(f"\nFull report saved to: {report_path}")

    return report


if __name__ == "__main__":
    raw_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "raw_scores.json"
    )
    report_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "analysis_report.json"
    )
    analyze(raw_path, report_path)
