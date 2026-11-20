# HELIO Safety Gate (`helio-safety-gate`)

**Deterministic Pre-LLM & Post-LLM Clinical Safety Gate, AES-256-GCM PIIVault, and 100-Case Tamil/Tanglish Synthetic Benchmark Commons for Human-Scale Healthcare AI**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-success.svg)](https://www.python.org/)
[![CI: GitHub Actions](https://github.com/haroon-cpu/helio-safety-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/haroon-cpu/helio-safety-gate/actions/workflows/ci.yml)
[![Execution: Zero-Cloud Deterministic](https://img.shields.io/badge/Safety_Layer-100%25_Local_Zero--Cloud-orange.svg)](#architecture-overview)

**Author:** Mohammed Haroon J — Founder, [HEONIX AI](https://heonixai.in) (Coimbatore, Tamil Nadu, India)  
**Release:** `v2.5.0-commons` (Apache-2.0 Public Safety Commons extracted from HELIO's clinical safety boundary)

---

## Why This Repository Exists

Small independent clinics (1–3 doctors) in Tamil Nadu receive daily WhatsApp messages in **Tamil script, code-mixed Romanized Tanglish, English, and Hindi**. Relying on large foreign cloud LLMs fails these clinics on three fronts: recurring cloud API bills, cross-border exposure of patient phone numbers and symptom narratives, and probabilistic hallucination on life-safety or prescription boundaries.

`helio-safety-gate` is an open-source (**Apache-2.0**), **zero-cloud, zero-mandatory-dependency** deterministic safety envelope that runs locally in single-digit milliseconds (< 20 KB peak Python memory) and enforces seven hard clinical and privacy guarantees around any downstream reception model:

1. **3-Turn Progressive Tamil & Tanglish Clinical Context Graph (`ClinicalContextGraph`):** Accumulates risk factors (age 60+, diabetes, hypertension, pregnancy, cardiac history) and prodromal symptoms across turns (e.g., Turn 1: `"Appa age 65, sugar patient"` → Turn 2: `"Nenju pakkam barama irukku"` → Turn 3: `"Ippo idadhu kai valikkudhu"`) without requiring English red-flag words, routing immediately to **Tamil Nadu Dial-108** and alerting the clinician.
2. **Unicode Indic Combining-Mark Preservation & Bilateral Negation Immunity (`IndicClinicalNormalizer`):** Preserves Tamil (`U+0B80..0BFF`) and Devanagari (`U+0900..097F`) vowel signs (`M*` category) to prevent consonant-skeleton collisions (`खाना` food vs `खून` blood) and evaluates clause-local bilateral negation (`"நெஞ்சு வலி இல்ல"`, `"nenju vali illa"`, `"सीने में दर्द नहीं है"`) so routine and dental inquiries never trigger false alarms.
3. **15-Minute Clinician Ghost-Mute Coexistence (`clinician_manual_reply`):** Immediately pauses automated replies for 900 seconds whenever the doctor replies manually from their existing clinic phone—while guaranteeing acute emergencies still break through the mute immediately. Designed directly after a Coimbatore dental clinic field visit showed that forcing doctors onto a second SIM breaks real-world workflows.
4. **4-Language Opt-Out Integrity (`en`, `ta`, `tanglish`, `hi`):** Immediate deterministic opt-out recognition (`STOP`, `UNSUBSCRIBE`, `நிறுத்து`, `வேண்டாம்`, `vendaam`, `रोकें`) backed by durable SQLite suppression.
5. **Pre-LLM Multilingual Prompt Injection Firewall (`PromptInjectionFirewall`):** Blocks system-prompt overrides and prescription-forcing jailbreaks across English, Tamil, and Tanglish—architecturally wired **after** emergency triage so a genuine life-threatening emergency is never blocked by the firewall.
6. **Post-LLM Zero-Diagnosis / Zero-Rx Output Guard (`ClinicalOutputGuard`):** Inspects every draft reply from any downstream model and blocks numeric dosages (`mg`, `ml`, `1-0-1`, `TDS`), Indian OTC/antibiotic brands (`Dolo 650`, `Amoxicillin`, `Calpol`, `Azithromycin`, `Ibuprofen`), unilateral pregnancy/pacemaker safety verdicts, and false reassurance (`"nothing to worry about"`, `"just mild acidity"`).
7. **AES-256-GCM `PIIVault`, Tamper-Evident SHA-256 Audit Chain & India DPDP Act Right-to-Erasure (`LocalClinicSafetyStore`):** Field-level authenticated encryption (`v1:`), keyed HMAC-SHA256 subject phone hashing (`h1:`), zero-PII SHA-256 hash-chained audit logs, and one-call `erase_patient_subject()` compliance.

---

## Honest Architecture Status (Prototype → Year 1 Local Small AI)

- **Layer 1 (Pre-LLM Deterministic Safety Gate) & Layer 3 (Post-LLM Zero-Rx Guard, PIIVault, Audit Chain):** **100% local today** with **0 cloud API calls** and **0 GPU required** (verifiable right now in this repo).
- **Layer 2 (Administrative Language Parsing):** The current full HELIO prototype uses the Gemini API for routine language parsing while Layers 1 & 3 run locally. During Year 1 of the Mozilla Human-Scale AI Incubator, Layer 2 migrates to a **1B–2B 4-bit quantized local model** (benchmarking `Gemma 3 1B`, `Qwen2.5 1.5B`, and `AI4Bharat IndicBERT-v3-1B` + MIT-licensed `IndicTrans2`) running offline on standard 8GB clinic PCs. See [`SMALL_AI_MIGRATION_ROADMAP.md`](./SMALL_AI_MIGRATION_ROADMAP.md).
- **Clinical Validation Status:** All 100 benchmark cases in `datasets/tamil_tanglish_safety_eval_v1.jsonl` are **100% synthetic**. Current live deployed clinic count is **0**. Before any patient-facing pilot, HELIO requires formal review by 2–3 practicing Coimbatore physicians and a CDSCO medical-device classification opinion. See [`CLINICAL_REVIEW_PROTOCOL.md`](./CLINICAL_REVIEW_PROTOCOL.md).

---

## Quickstart (Zero Mandatory External Pip Dependencies)

```bash
# 1. Run the 5-part live clinical safety & PIIVault demonstration
python3 helio_safety_gate.py

# 2. Evaluate any single message as structured JSON (zero cloud calls)
python3 helio_safety_gate.py --json "Nenju valikkudhu, idadhu kai valikkudhu"

# 3. Check a draft LLM reply against the Zero-Rx / Zero-Diagnosis Output Guard
python3 helio_safety_gate.py --check-reply "Take Dolo 650 mg twice daily."

# 4. Run all 32 unit & adversarial verification tests
python3 -m unittest test_safety_gate.py -v

# 5. Run the 100-case synthetic Tamil/Tanglish clinical safety benchmark
python3 benchmark_tamil_safety.py --strict
```

---

## Verified Benchmark Scorecard (`benchmark_tamil_safety.py` — v2027.2)

Evaluated directly against the open Apache-2.0 dataset [`datasets/tamil_tanglish_safety_eval_v1.jsonl`](./datasets/tamil_tanglish_safety_eval_v1.jsonl) (85 pre-LLM triage cases + 15 post-LLM output guard cases = **100 synthetic cases**):

| Metric | Verified Result | Details |
| :--- | :--- | :--- |
| **Pre-LLM Exact Classification** | **100.0%** | `85 / 85` exact severity matches across Tamil, Tanglish, English & Hindi |
| **Emergency Recall / Sensitivity (Dial-108)** | **100.0%** | `46 / 46` single-turn, 3-turn, pediatric, toxicology & injection-collision emergencies caught |
| **Negation & Routine Specificity** | **100.0%** | `39 / 39` negated, dental, routine, opt-out & firewall cases free of false alarms |
| **Emergency Precision / F1 Score** | **100.0% / 100.0%** | Zero false positives and zero false negatives on synthetic corpus |
| **False Reassurance Rate on Red Flags** | **0.0%** | `0` missed life-threat cases |
| **Post-LLM Zero-Rx Output Guard Accuracy** | **100.0%** | `15 / 15` unsafe Rx/verdict/reassurance drafts blocked & safe booking replies passed |
| **Pre-LLM Triage Latency (CPU)** | **~2.1 ms mean** | Single-digit millisecond deterministic CPU execution (`p50 ~2.1 ms`, `p95 ~4.5 ms`, `p99 ~5.3 ms`) |
| **Peak Python Memory Footprint** | **~18.4 KB** | Verified via `tracemalloc` — effortless on 8GB clinic PCs or Raspberry Pi |
| **Unit & Adversarial Test Suite** | **32 / 32 PASS** | `test_safety_gate.py` verified via GitHub Actions on Python 3.9–3.12 |
| **External Cloud API Calls Required** | **0** | 100% local deterministic execution + AES-256-GCM PIIVault + SHA-256 audit chain |

*(Exact live machine-measured latency and memory values for your hardware are printed on every run of `python3 benchmark_tamil_safety.py`.)*

---

## Repository Structure

| File | Purpose |
| :--- | :--- |
| [`helio_safety_gate.py`](./helio_safety_gate.py) | Core deterministic 7-layer safety gate, `PIIVault`, `IndicClinicalNormalizer`, `PromptInjectionFirewall`, `ClinicalOutputGuard`, `LocalClinicSafetyStore`, and CLI (`--json`, `--check-reply`, `--interactive`) |
| [`test_safety_gate.py`](./test_safety_gate.py) | 32 unit & adversarial tests (multi-turn escalation, post-negation, dental false-positive traps, Ghost-Mute, 4-language opt-out, output guard, audit tamper detection, DPDP erasure, CLI & dataset PII check) |
| [`benchmark_tamil_safety.py`](./benchmark_tamil_safety.py) | Executable 100-case synthetic benchmark harness with P50/P95/P99 latency, peak memory profiling, `--strict` CI gate, and JSON report export |
| [`datasets/tamil_tanglish_safety_eval_v1.jsonl`](./datasets/tamil_tanglish_safety_eval_v1.jsonl) | Open Apache-2.0 100-case synthetic Tamil/Tanglish/English/Hindi clinical safety evaluation dataset (zero real patient data) |
| [`ARCHITECTURE_AND_THREAT_MODEL.md`](./ARCHITECTURE_AND_THREAT_MODEL.md) | 3-layer human-scale architecture diagram, Indic NLP defect analysis, STRIDE threat model, and DPDP/CDSCO regulatory boundary |
| [`SMALL_AI_MIGRATION_ROADMAP.md`](./SMALL_AI_MIGRATION_ROADMAP.md) | Year-1 engineering plan migrating Layer 2 from Gemini API prototype to offline 1B–2B quantized local models on 8GB clinic PCs |
| [`MODEL_CARD_AND_EVALUATION.md`](./MODEL_CARD_AND_EVALUATION.md) | Standardized safety-gate & dataset card documenting intended use, non-diagnostic scope, and known dialect limitations |
| [`CLINICAL_REVIEW_PROTOCOL.md`](./CLINICAL_REVIEW_PROTOCOL.md) | Year-1 Gate 1 physician sign-off checklist, CDSCO non-diagnostic boundary, and Coimbatore Community Advisory Board charter |
| [`SECURITY.md`](./SECURITY.md) / [`CONTRIBUTING.md`](./CONTRIBUTING.md) / [`LICENSE`](./LICENSE) | Responsible clinical safety disclosure policy, contributor rules (synthetic-only), and full canonical Apache-2.0 license |

---

## Open-Core Commons & Non-Diagnostic Disclaimer

`helio-safety-gate` is permanently free under the **Apache-2.0 License** as a public clinical safety commons for small clinics, NGOs, and researchers. HEONIX AI's separate commercial clinic CRM, multi-tenant scheduling dashboard, and billing modules remain proprietary and are **not** included here. This software is strictly a **non-diagnostic administrative coordination and red-flag escalation gate** and does not provide medical diagnosis, prescriptions, or treatment advice.
