# HELIO Safety Gate (Public Safety Commons)

**License:** Apache-2.0 | **Author:** Mohammed Haroon J (HEONIX AI, Coimbatore, Tamil Nadu, India)

> **Important Clinical Disclaimer:** This repository is a deterministic safety and intake-coordination module. It is **not a diagnostic tool**, **not a medical device**, and **not a substitute for professional medical advice**. All test cases are synthetic.

## Why This Exists (Human-Scale AI)
Small 1-to-3-doctor outpatient clinics in Tamil Nadu serve patients speaking everyday Tamil and code-mixed Tanglish, yet cannot rely on expensive frontier cloud AI APIs or risk LLM hallucinations during medical emergencies.

**HELIO Safety Gate** runs 100% locally with zero LLM calls and provides:
1. **3-Turn Progressive Tamil/Tanglish Emergency Escalation:** Links patient risk factors (e.g., age, diabetes, hypertension) and escalating vernacular symptoms across turns to recommend Tamil Nadu's **Dial-108** ambulance service without requiring English keywords.
2. **15-Minute Clinician Ghost-Mute Coexistence Protocol:** Immediately pauses automated replies for 15 minutes whenever a human doctor replies manually, preserving clinician authority on their existing WhatsApp workflow.
3. **4-Language Opt-Out Integrity:** Respects patient opt-outs cleanly in English, Tamil, Tanglish, and Hindi.

## Quickstart (Runs Locally in <10ms, Zero API Keys Required)
```bash
python3 helio_safety_gate.py
python3 test_safety_gate.py
```

## IP Boundary
This Apache-2.0 repository forms the public safety commons of **HELIO**. HEONIX AI's proprietary commercial clinic CRM and billing engine remains closed-source, while emergency safety rules, synthetic benchmarks, and local privacy blueprints are built in the open for public benefit.
