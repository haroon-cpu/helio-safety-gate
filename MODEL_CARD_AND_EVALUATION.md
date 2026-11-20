# Model & Safety-Gate Card (`helio-safety-gate` v2.5.0-commons)

## 1. Overview & Intended Use

- **Artifact:** `helio-safety-gate` (Deterministic Pre-LLM & Post-LLM Clinical Safety Gate + `tamil_tanglish_safety_eval_v1.jsonl` 100-case synthetic dataset).
- **Developer:** Mohammed Haroon J, HEONIX AI (Coimbatore, Tamil Nadu, India).
- **License:** Apache-2.0.
- **Intended Use:** Non-diagnostic administrative safety envelope for 1-to-3-doctor outpatient clinics in Tamil Nadu. Performs deterministic red-flag escalation to Tamil Nadu Dial-108, enforces 15-minute clinician Ghost-Mute coexistence, blocks prompt injections, strips/blocks hallucinated prescriptions from downstream reception models, and enforces AES-256-GCM local PII encryption + India DPDP Act erasure.

## 2. Strictly Out-of-Scope Uses

- **NOT a diagnostic tool or Software as a Medical Device (SaMD):** Must never be used to diagnose conditions, interpret lab reports, recommend medications/dosages, or replace a licensed physician.
- **NOT a replacement for emergency services:** Red-flag matches explicitly instruct patients/families to call **108** immediately and alert the human clinician.
- **NOT validated for unsupervised live patient deployment yet:** Current validation is strictly on a **100-case synthetic corpus**. Live deployment requires passing Year-1 Gate 1 physician review (`CLINICAL_REVIEW_PROTOCOL.md`).

## 3. Dataset Provenance (`datasets/tamil_tanglish_safety_eval_v1.jsonl`)

- **Size:** 100 synthetic cases (85 pre-LLM triage cases + 15 post-LLM Zero-Rx output guard cases).
- **Languages Covered:** Tamil script (`ta`), Romanized Tanglish (`tanglish`), code-mixed Tamil-English (`ta-en`), English (`en`), and Devanagari Hindi (`hi`).
- **Privacy Guarantee:** 100% synthetically authored. Zero real patient messages, zero real phone numbers (verified automatically by `test_31_open_jsonl_dataset_schema_and_no_real_pii`).

## 4. Known Limitations & Failure Modes (Radical Transparency)

1. **Synthetic vs. Real-World Dialect Gap:** Real Coimbatore Kongu Tamil, rural colloquialisms, voice-note transcripts, and extreme phonetic misspellings (e.g., `"nnju vli"`, `"mochu varla"`) will exhibit wider variance than synthetic text. Year 1 funds a clinician-validated expanded corpus and shadow-mode error analysis.
2. **Audio & Image Inputs:** Current `v2.5.0-commons` evaluates text messages only. Voice notes (common among elderly Tamil patients) require an offline Tamil ASR front-end (planned for Year 1 evaluation).
3. **Rule Maintenance Overhead:** Deterministic safety rules require ongoing clinician governance to prevent both missed novel phrasings and over-triggering on benign colloquial expressions. Governance is handled by the Year-1 Community Advisory Board.
4. **Cryptography Optional Dependency:** When `cryptography` is installed, `PIIVault` uses native AES-256-GCM; in zero-dependency environments, it falls back transparently to a stdlib HMAC-SHA256 authenticated stream cipher (`v1-stdlib:`) and explicitly logs the active backend via `vault.backend_name`. Production clinic deployments must install `cryptography>=41.0.0`.
