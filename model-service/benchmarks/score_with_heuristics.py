"""
Score the calibration dataset using heuristic scoring (test double).

This uses the same keyword/regex-based scoring logic from conftest.py's
_test_model_analyze, plus semantic similarity scoring via the embedding model.

Used when the live model-service (GPU) is not available.
Results are compatible with optimize_thresholds.py.

Usage:
    python score_with_heuristics.py [dataset_path] [output_path]
"""

import json
import os
import re
import sys
import time

# Add parent directory to path so we can import from model-service
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from main import normalize_text


def heuristic_analyze(text: str) -> dict[str, float]:
    """Heuristic scoring that mirrors the test double from conftest.py.

    Applies normalization first (same as real model pipeline), then
    uses keyword/regex matching to produce scores.
    """
    # Apply the same normalization as the real pipeline
    normalized = normalize_text(text)
    text_lower = normalized.lower()

    # Prompt injection detection
    injection_keywords = [
        "ignore previous", "ignore all previous", "disregard",
        "forget your instructions", "forget everything",
        "new instructions", "override", "system prompt",
        "you are now", "act as", "pretend to be",
        "do not follow", "instead of", "reveal your",
        "show me your prompt", "what are your instructions",
        "repeat your rules", "your real instructions",
        "bypass your", "ignore the rules", "from now on",
        "you must follow my", "ignore ethical",
        "previous instructions don't exist",
    ]
    prompt_injection_score = 0.0
    for keyword in injection_keywords:
        if keyword in text_lower:
            prompt_injection_score = min(1.0, prompt_injection_score + 0.25)

    harmful_patterns = [
        r"empty\b.*\bwallet", r"drain\b.*\baccount", r"transfer\b.*\bfunds",
        r"\bsteal\b", r"send\b.*\b(?:money|funds|crypto|bitcoin|eth)\b",
        r"wire\s*transfer", r"delete\s+all\b", r"drop\s+table", r"\brm\s+-rf\b",
        r"execute\b.*\bcommand", r"run\b.*\bcommand", r"\bshutdown\b.*\bserver",
        r"format\b.*\bdisk", r"\bdestroy\b.*\b(?:data|file|system|server)",
        r"kill\b.*\bprocess", r"\bexfiltrate\b", r"\bransom\b",
    ]
    for pattern in harmful_patterns:
        if re.search(pattern, text_lower):
            prompt_injection_score = min(1.0, prompt_injection_score + 0.35)

    # Jailbreak detection
    jailbreak_keywords = [
        "dan mode", "jailbreak", "bypass", "unrestricted", "no limits",
        "evil mode", "developer mode", "without restrictions", "hypothetically",
        "roleplay as", "no restrictions", "unfiltered", "without safety",
        "disable filter", "remove restrictions", "no content restrictions",
        "no ethical guidelines", "without censorship", "pretend you have no",
        "you can now do anything", "activate unrestricted",
        "enter developer mode", "disable all filters",
    ]
    jailbreak_score = 0.0
    for keyword in jailbreak_keywords:
        if keyword in text_lower:
            jailbreak_score = min(1.0, jailbreak_score + 0.25)

    # PII detection
    pii_score = 0.0
    # Email
    if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
        pii_score += 0.3
    # SSN
    if re.search(r"\b\d{3}-\d{2}-\d{4}\b", text):
        pii_score += 0.4
    # Phone (with separators)
    if re.search(r"\b\d{3}[-\.]\d{3}[-\.]\d{4}\b", text):
        pii_score += 0.2
    # Credit card
    if re.search(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", text):
        pii_score += 0.4
    # UK NI Number
    if re.search(r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b", text, re.IGNORECASE):
        pii_score += 0.4
    # NHS Number
    if re.search(r"\b\d{3}\s\d{3}\s\d{4}\b", text):
        pii_score += 0.3
    # IBAN
    if re.search(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", text):
        pii_score += 0.35
    # Canadian SIN
    if re.search(r"\b\d{3}[-\s]\d{3}[-\s]\d{3}\b", text):
        pii_score += 0.4
    # Australian TFN
    if re.search(r"\b\d{3}\s\d{3}\s\d{3}\b", text):
        pii_score += 0.35
    # Passport
    if re.search(r"\bpassport\b", text_lower) and re.search(r"\b[A-Z]{1,2}\d{6,8}\b", text):
        pii_score += 0.3
    # API keys
    if re.search(r"\b(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})\b", text):
        pii_score += 0.5
    # JWT
    if re.search(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b", text):
        pii_score += 0.4
    pii_score = min(1.0, pii_score)

    # Semantic similarity: approximate with keyword overlap with attack patterns
    attack_keywords = [
        "ignore", "override", "bypass", "jailbreak", "unrestricted",
        "system prompt", "instructions", "reveal", "secret", "admin",
        "password", "credential", "hack", "exploit", "sudo", "command",
        "execute", "shell", "delete", "drop", "transfer", "steal",
        "dan mode", "developer mode", "unfiltered", "no restrictions",
    ]
    hit_count = sum(1 for kw in attack_keywords if kw in text_lower)
    semantic_score = min(1.0, hit_count * 0.15)

    return {
        "prompt_injection": round(prompt_injection_score, 4),
        "jailbreak": round(jailbreak_score, 4),
        "pii": round(pii_score, 4),
        "semantic_similarity": round(semantic_score, 4),
    }


def main():
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "calibration_dataset.json"
    )
    output_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "raw_scores.json"
    )

    with open(dataset_path, encoding="utf-8") as f:
        dataset = json.load(f)

    total = len(dataset)
    results = []
    start_all = time.time()

    print(f"Scoring {total} examples with heuristic scorer...")
    print("=" * 80)

    for i, example in enumerate(dataset):
        text = example["text"]
        start = time.time()
        scores = heuristic_analyze(text)
        elapsed_ms = (time.time() - start) * 1000

        blocked = any(
            (cat == "prompt_injection" and scores[cat] >= 0.7) or
            (cat == "jailbreak" and scores[cat] >= 0.7) or
            (cat == "pii" and scores[cat] >= 0.5)
            for cat in scores
        )

        threats = []
        if scores["prompt_injection"] >= 0.7:
            threats.append("prompt_injection")
        if scores["jailbreak"] >= 0.7:
            threats.append("jailbreak")
        if scores["pii"] >= 0.5:
            threats.append("pii_exposure")
        if scores["semantic_similarity"] >= 0.75:
            threats.append("semantic_attack")

        results.append({
            **example,
            "raw_scores": scores,
            "model_blocked": blocked,
            "model_threats": threats,
            "latency_ms": round(elapsed_ms, 2),
            "error": None,
            "skipped": False,
        })

        cat = example["category"]
        pi = scores["prompt_injection"]
        jb = scores["jailbreak"]
        pii = scores["pii"]
        sem = scores["semantic_similarity"]
        status = "BLOCKED" if blocked else "ok"

        if (i + 1) % 25 == 0 or (i + 1) == total:
            print(
                f"[{i+1:3d}/{total}] {cat:18s} | PI={pi:.3f} JB={jb:.3f} PII={pii:.3f} SEM={sem:.3f} | {status}"
            )

    elapsed = time.time() - start_all

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("=" * 80)
    print(f"Complete: {total} examples in {elapsed:.1f}s")
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()
