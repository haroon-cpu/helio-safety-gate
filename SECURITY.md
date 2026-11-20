# Security & Clinical Safety Disclosure Policy

## Scope

`helio-safety-gate` is a non-diagnostic deterministic clinical routing and privacy safety gate designed for small outpatient clinics. Security and safety defects include:

1. **Missed Acute Red-Flag Escalations (False Negatives):** Tamil, Tanglish, English, or Hindi phrasing describing an acute life-threatening emergency that fails to route to Dial-108.
2. **Post-LLM Zero-Rx / Zero-Diagnosis Guard Bypasses:** Draft medication dosages, brand names, or false clinical reassurance phrases that pass `ClinicalOutputGuard.verify_llm_reply()`.
3. **Cryptographic or Privacy Defects:** Issues in `PIIVault` encryption, HMAC-SHA256 subject hashing, SHA-256 audit chain integrity, or India DPDP Act Right-to-Erasure (`erase_patient_subject`).
4. **Prompt Injection Precedence Regressions:** Any input that causes `PromptInjectionFirewall` to suppress a genuine emergency.

## Reporting a Vulnerability or Safety Bypass

Please do **not** open a public GitHub issue for an unpatched clinical safety bypass or cryptographic vulnerability.

- **Email:** `haroon@heonixai.in` (Subject: `[SECURITY / SAFETY] helio-safety-gate`)
- **Initial Acknowledgment Target:** Within 48 hours
- **Remediation & Regression Test:** Confirmed issues are patched with a permanent adversarial regression test added to `test_safety_gate.py` and `datasets/tamil_tanglish_safety_eval_v1.jsonl`.

## Clinical Boundary Notice

This repository contains **synthetic evaluation data only** and **never** accepts real patient records, real phone numbers, or identifiable clinical chat logs in issues, pull requests, or security reports.
