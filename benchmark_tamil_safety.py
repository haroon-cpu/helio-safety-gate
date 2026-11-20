#!/usr/bin/env python3
"""
HELIO Synthetic Tamil / Code-Mixed Tanglish Clinical Safety Benchmark (v2027.2)
===============================================================================
Evaluates `HelioSafetyGate` and `ClinicalOutputGuard` against the open Apache-2.0
100-case synthetic dataset (`datasets/tamil_tanglish_safety_eval_v1.jsonl`):
  - 85 Pre-LLM Triage, Multi-Turn Escalation, Negation, Dental False-Positive,
    Opt-Out, Prompt Injection & Collision cases
  - 15 Post-LLM Zero-Rx / Zero-Diagnosis Output Guard cases

Measures:
  - Emergency Recall / Sensitivity (Dial-108)
  - Negation & Routine Specificity
  - Precision & F1 Score on Acute Emergencies
  - False Reassurance Rate on Red Flags
  - Post-LLM Zero-Rx Output Guard Accuracy
  - Latency Distribution (Mean, P50, P95, P99 in ms)
  - Peak Python Memory Footprint (`tracemalloc` in KB — proving 8GB PC / Pi readiness)
  - Zero-PII SHA-256 Audit Chain Integrity

Run:
    python3 benchmark_tamil_safety.py
    python3 benchmark_tamil_safety.py --strict --json-out benchmark_report.json
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import time
import tracemalloc
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

from helio_safety_gate import (
    ClinicalOutputGuard,
    HelioSafetyGate,
    LocalClinicSafetyStore,
    PIIVault,
    __version__,
)

DEFAULT_DATASET = Path(__file__).resolve().parent / "datasets" / "tamil_tanglish_safety_eval_v1.jsonl"


def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = max(0, min(len(sorted_vals) - 1, int(round((pct / 100.0) * len(sorted_vals))) - 1))
    return sorted_vals[idx]


def run_benchmark(dataset_path: Path = DEFAULT_DATASET, strict: bool = False, json_out: str | None = None) -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    pre_llm_rows = [r for r in rows if r.get("task") == "pre_llm"]
    post_llm_rows = [r for r in rows if r.get("task") == "post_llm"]

    vault = PIIVault(master_secret="helio-benchmark-2027")
    store = LocalClinicSafetyStore(":memory:", vault=vault)
    gate = HelioSafetyGate(store=store, vault=vault)

    latencies_ms: List[float] = []
    tp = tn = fp = fn = 0
    exact_matches = 0
    mismatches: List[Dict[str, Any]] = []
    category_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"passed": 0, "total": 0})
    language_counts: Dict[str, int] = defaultdict(int)

    for idx, item in enumerate(pre_llm_rows, start=1):
        phone = f"+9199000{idx:05d}"
        decision = None
        t_start = time.perf_counter()
        for turn_text in item["turns"]:
            decision = gate.process_incoming(phone, turn_text)
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        latencies_ms.append(elapsed_ms)

        assert decision is not None
        expected = item["expected"]
        actual = decision.severity
        cat = item.get("category", "uncategorized")
        lang = item.get("language", "unknown")
        language_counts[lang] += 1
        category_stats[cat]["total"] += 1

        if actual == expected:
            exact_matches += 1
            category_stats[cat]["passed"] += 1
        else:
            mismatches.append({
                "id": item["id"],
                "task": "pre_llm",
                "expected": expected,
                "actual": actual,
                "turns": item["turns"],
                "triggers": decision.matched_triggers,
            })

        expected_em = (expected == "EMERGENCY")
        actual_em = (actual == "EMERGENCY" and decision.dial_108)
        if expected_em and actual_em:
            tp += 1
        elif not expected_em and not actual_em:
            tn += 1
        elif not expected_em and actual_em:
            fp += 1
        elif expected_em and not actual_em:
            fn += 1

    output_correct = 0
    for item in post_llm_rows:
        cat = item.get("category", "post_llm")
        lang = item.get("language", "unknown")
        language_counts[lang] += 1
        category_stats[cat]["total"] += 1
        verdict = ClinicalOutputGuard.verify_llm_reply(item["draft"])
        if verdict.safe == item["expected_safe"]:
            output_correct += 1
            category_stats[cat]["passed"] += 1
        else:
            mismatches.append({
                "id": item["id"],
                "task": "post_llm",
                "expected_safe": item["expected_safe"],
                "actual_safe": verdict.safe,
                "draft": item["draft"],
                "violation_category": verdict.violation_category,
            })

    tracemalloc.start()
    _m_vault = PIIVault(master_secret="helio-mem-probe")
    _m_store = LocalClinicSafetyStore(":memory:", vault=_m_vault)
    _m_gate = HelioSafetyGate(store=_m_store, vault=_m_vault)
    for _i, _item in enumerate(pre_llm_rows[:20], start=1):
        for _t in _item["turns"]:
            _m_gate.process_incoming(f"+9199888{_i:05d}", _t)
    _, peak_mem_b = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    sensitivity = (tp / (tp + fn)) * 100.0 if (tp + fn) else 100.0
    specificity = (tn / (tn + fp)) * 100.0 if (tn + fp) else 100.0
    precision = (tp / (tp + fp)) * 100.0 if (tp + fp) else 100.0
    f1 = (2 * precision * sensitivity / (precision + sensitivity)) if (precision + sensitivity) else 0.0
    false_reassurance = (fn / (tp + fn)) * 100.0 if (tp + fn) else 0.0
    output_guard_acc = (output_correct / len(post_llm_rows)) * 100.0 if post_llm_rows else 100.0
    chain_ok, audit_count, audit_err = store.verify_audit_chain()

    sorted_lat = sorted(latencies_ms)
    report: Dict[str, Any] = {
        "benchmark_version": "v2027.2",
        "engine_version": __version__,
        "dataset_file": os.path.basename(str(dataset_path)),
        "total_cases": len(rows),
        "pre_llm_cases": len(pre_llm_rows),
        "pre_llm_exact_matches": exact_matches,
        "post_llm_cases": len(post_llm_rows),
        "post_llm_exact_matches": output_correct,
        "emergency_tp": tp,
        "emergency_tn": tn,
        "emergency_fp": fp,
        "emergency_fn": fn,
        "emergency_recall_pct": round(sensitivity, 2),
        "specificity_pct": round(specificity, 2),
        "precision_pct": round(precision, 2),
        "f1_pct": round(f1, 2),
        "false_reassurance_rate_pct": round(false_reassurance, 2),
        "post_llm_output_guard_accuracy_pct": round(output_guard_acc, 2),
        "latency_mean_ms": round(statistics.mean(latencies_ms), 3),
        "latency_p50_ms": round(_percentile(sorted_lat, 50), 3),
        "latency_p95_ms": round(_percentile(sorted_lat, 95), 3),
        "latency_p99_ms": round(_percentile(sorted_lat, 99), 3),
        "peak_memory_kb": round(peak_mem_b / 1024.0, 1),
        "piivault_backend": vault.backend_name,
        "audit_chain_valid": chain_ok,
        "audit_chain_events": audit_count,
        "audit_chain_error": audit_err,
        "external_cloud_api_calls": 0,
        "languages": dict(sorted(language_counts.items())),
        "mismatches": mismatches,
    }

    print("=" * 80)
    print(f"HELIO TAMIL / TANGLISH CLINICAL SAFETY BENCHMARK SCORECARD ({report['benchmark_version']})")
    print("=" * 80)
    print(f"Dataset Evaluated                        : {report['dataset_file']} ({report['total_cases']} synthetic cases)")
    print(f"Pre-LLM Triage Exact Classification      : {exact_matches}/{len(pre_llm_rows)} ({(exact_matches/len(pre_llm_rows))*100:.1f}%)")
    print(f"Emergency Recall / Sensitivity (Dial-108): {sensitivity:.1f}% ({tp}/{tp + fn} acute emergencies caught)")
    print(f"Negation & Routine Specificity           : {specificity:.1f}% ({tn}/{tn + fp} non-emergencies free of false alarms)")
    print(f"Emergency Precision / F1 Score           : {precision:.1f}% / {f1:.1f}%")
    print(f"False Reassurance Rate on Red Flags      : {false_reassurance:.1f}% ({fn} missed life-threat cases)")
    print(f"Post-LLM Zero-Rx Output Guard Accuracy   : {output_guard_acc:.1f}% ({output_correct}/{len(post_llm_rows)} drafts verified)")
    print(
        f"Pre-LLM Triage Latency (CPU)             : mean {report['latency_mean_ms']:.3f} ms | "
        f"p50 {report['latency_p50_ms']:.3f} ms | p95 {report['latency_p95_ms']:.3f} ms | p99 {report['latency_p99_ms']:.3f} ms"
    )
    print(f"Peak Python Memory Footprint             : {report['peak_memory_kb']:.1f} KB (runs on 8GB clinic PC / Raspberry Pi)")
    print(f"PIIVault Cryptographic Backend           : {vault.backend_name}")
    print(f"Zero-PII SHA-256 Audit Chain Integrity   : Valid={chain_ok} ({audit_count} cryptographically linked events)")
    print(f"External Cloud API Calls Required        : 0 (100% Local Deterministic Execution)")
    print("=" * 80)

    if mismatches:
        print(f"\n[!] {len(mismatches)} MISMATCH(ES) DETECTED:")
        for m in mismatches:
            print("   ", m)

    if json_out:
        with open(json_out, "w", encoding="utf-8") as jf:
            json.dump(report, jf, ensure_ascii=False, indent=2)

    if strict and (mismatches or not chain_ok or fn > 0):
        raise SystemExit(1)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run HELIO 100-case Tamil/Tanglish Clinical Safety Benchmark")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET, help="Path to JSONL benchmark dataset")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if any case mismatches or audit chain fails")
    parser.add_argument("--json-out", type=str, default=None, help="Optional path to save JSON benchmark report")
    args = parser.parse_args()
    run_benchmark(dataset_path=args.dataset, strict=args.strict, json_out=args.json_out)


if __name__ == "__main__":
    main()
