# HELIO Safety Gate (`helio-safety-gate`)

**Deterministic Pre-LLM & Post-LLM Clinical Safety Gate, AES-256-GCM PIIVault, and Tamil/Tanglish Benchmark Commons for Neighborhood Healthcare AI**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-success.svg)](https://www.python.org/)
[![Architecture: Local-First Human-Scale AI](https://img.shields.io/badge/Architecture-Local--First_Zero--Cloud-orange.svg)](#architecture-overview)

**Author:** Mohammed Haroon J — Founder, [HEONIX AI](https://heonixai.in) (Coimbatore, Tamil Nadu, India)  
**Release:** `v2.4.0-commons` (Open-Source Public Safety Layer extracted from HELIO `v53.0`)

---

## Overview

Neighborhood single-doctor clinics across India receive 70–150 daily WhatsApp inquiries in **Tamil script, code-mixed Romanized Tanglish, English, and Hindi**. While a small, 4-bit quantized **1B–2B local language model** running on an affordable ₹35,000 (~$420) clinic mini-PC can handle appointment booking without sending patient data to external cloud APIs, **a probabilistic language model must never be trusted with life-safety triage or prescription boundaries**.

`helio-safety-gate` is an open-source (Apache-2.0), zero-cloud deterministic safety envelope that wraps around any local reception model and enforces seven hard clinical and privacy guarantees in **< 1 millisecond**:

1. **3-Turn Progressive Tamil & Tanglish Clinical Context Graph (`ClinicalContextGraph`):** Detects multi-turn cardiac, respiratory, neurological, toxicologic, and pediatric emergencies across code-mixed turns (e.g., Turn 1: `"Appa age 64, sugar and bp irukku"` $\rightarrow$ Turn 2: `"nenju pakkam barama irukku"` $\rightarrow$ Turn 3: `"idadhu kai valikkudhu, moochu vaanga kastama irukku"`) without requiring English red-flag keywords, immediately routing the patient to **Tamil Nadu Dial-108** and alerting the clinician.
2. **Unicode Indic Combining-Mark Preservation & Bilateral Negation Immunity (`IndicClinicalNormalizer`):** Preserves Tamil (`U+0B80..0BFF`) and Devanagari (`U+0900..097F`) vowel signs (`M*` category) to prevent consonant-skeleton collisions (`खाना` food vs `खून` blood) and evaluates both pre-symptom and post-symptom negators (`"நெஞ்சு வலி இல்ல"`, `"nenju vali illa"`, `"सीने में दर्द नहीं है"`) so negated symptoms never trigger false alarms.
3. **15-Minute Clinician Ghost-Mute Coexistence (`clinician_manual_reply`):** Automatically pauses automated replies for 900 seconds the instant a doctor replies manually from their WhatsApp Business phone—while guaranteeing that acute life-threat emergencies still break through the mute immediately.
4. **4-Language Opt-Out Integrity (`en`, `ta`, `tanglish`, `hi`):** Immediate zero-LLM opt-out recognition (`STOP`, `நிறுத்து`, `vendaam`, `रोकें`) backed by durable SQLite suppression.
5. **Pre-LLM Multilingual Prompt Injection Firewall (`PromptInjectionFirewall`):** Blocks system-prompt override and prescription-forcing jailbreaks across English, Tamil, and Tanglish—wired strictly *after* emergency triage so a real emergency is never blocked by the firewall.
6. **Post-LLM Zero-Diagnosis / Zero-Rx Output Guard (`ClinicalOutputGuard`):** Inspects every draft reply from the local 2B model and blocks medication dosages (`mg`, `ml`, `1-0-1`), Indian OTC/antibiotic brands (`Dolo 650`, `Amoxicillin`, `Calpol`, `Azithromycin`), pregnancy/pacemaker safety verdicts, and false medical reassurance.
7. **AES-256-GCM `PIIVault`, Tamper-Evident SHA-256 Audit Chain & India DPDP Act Right-to-Erasure (`LocalClinicSafetyStore`):** Field-level authenticated encryption (`v1:`), keyed HMAC-SHA256 subject phone hashing (`h1:`), cryptographic SHA-256 hash-chained zero-PII audit logs, and 1-command `erase_patient_subject()` compliance.

---

## Quickstart (Zero Mandatory External Pip Dependencies)

Run the live 7-layer clinical safety demonstration, the 20-test adversarial unit suite, and the 40-case Tamil/Tanglish clinical safety benchmark using standard Python 3:

```bash
# 1. Run the interactive 7-layer clinical safety & PIIVault demonstration
python helio_safety_gate.py

# 2. Run the 20-test unit & adversarial verification suite
python test_safety_gate.py -v

# 3. Run the 40-case synthetic Tamil/Tanglish clinical safety benchmark scorecard
python benchmark_tamil_safety.py
```

---

## Benchmark Scorecard (`benchmark_tamil_safety.py` — v2027.1)

| Metric | Score | Details |
| :--- | :--- | :--- |
| **Emergency Recall / Sensitivity (Dial-108)** | **100.0%** | `18 / 18` single-turn & 3-turn Tamil/Tanglish/Hindi emergencies caught |
| **Negation & Routine Specificity** | **100.0%** | `18 / 18` negated (`"நெஞ்சு வலி இல்ல"`), routine, opt-out & firewall cases free of false alarms |
| **False Reassurance Rate on Red Flags** | **0.0%** | Zero missed cardiac, stroke, syncope, button-battery, poison, or strip-overdose cases |
| **Post-LLM Zero-Rx Output Guard Accuracy** | **100.0%** | `7 / 7` dosage leaks, clinical verdicts & false reassurances intercepted |
| **Mean Pre-LLM Triage Latency** | **< 0.45 ms** | Sub-millisecond deterministic execution on standard CPU |
| **External Cloud API Calls Required** | **0** | 100% local execution with SQLite WAL + SHA-256 hash-chained zero-PII audit log |

---

## Repository Structure

* [`helio_safety_gate.py`](./helio_safety_gate.py) — Core deterministic safety gate, `PIIVault`, `IndicClinicalNormalizer`, `PromptInjectionFirewall`, `ClinicalOutputGuard`, and `LocalClinicSafetyStore`.
* [`test_safety_gate.py`](./test_safety_gate.py) — 20 unit and adversarial tests verifying multi-turn escalation, post-negation immunity, Ghost-Mute coexistence, 4-language opt-out, output guardrails, and SHA-256 audit tamper detection.
* [`benchmark_tamil_safety.py`](./benchmark_tamil_safety.py) — Executable 40-case synthetic Tamil/Tanglish clinical safety benchmark and scorecard generator.
* [`ARCHITECTURE_AND_THREAT_MODEL.md`](./ARCHITECTURE_AND_THREAT_MODEL.md) — Deep architectural diagram, Indic NLP defect analysis, STRIDE threat model, and India DPDP Act 2023 / CDSCO regulatory boundary documentation.
* [`LICENSE`](./LICENSE) — Apache-2.0 Open-Source License.

---

## Open-Core Commons & Clinical Disclaimer

`helio-safety-gate` is released under the **Apache-2.0 License** as a public clinical safety commons for low-resource healthcare AI. HEONIX AI's commercial clinic CRM, practice-management dashboard, and multi-tenant billing workflows remain separate proprietary modules. This software is a non-diagnostic administrative routing and safety filter and does not provide medical diagnosis or treatment advice.
