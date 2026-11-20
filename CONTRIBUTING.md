# Contributing to `helio-safety-gate`

We welcome contributions from Tamil and Indian clinicians, public health researchers, Dravidian NLP linguists, and open-source engineers.

## High-Impact Contributions

1. **Synthetic Dialect & Tanglish Edge Cases:** Add realistic *synthetic* utterances (Coimbatore Kongu Tamil, Madurai Tamil, Chennai Tanglish, rural idioms, common misspellings) to `datasets/tamil_tanglish_safety_eval_v1.jsonl`.
2. **Negation & False-Positive Traps:** Add benign outpatient messages (dental, routine follow-ups, resolved past-tense symptoms, negated clauses) that must **not** trigger Dial-108.
3. **Post-LLM Zero-Rx Guard Patterns:** Expand detection of Indian OTC/prescription brand names, colloquial dosage phrasing, and false-reassurance templates.
4. **Clinician Review Feedback:** Flag any rule wording or escalation phrasing that requires physician revision under `CLINICAL_REVIEW_PROTOCOL.md`.

## Strict Privacy & Safety Rules for Contributors

- **NEVER submit real patient data**, real phone numbers, clinic names, or production WhatsApp logs. All test cases must be 100% synthetic.
- **Zero-Diagnosis Boundary:** Never add diagnostic conclusions, treatment recommendations, or medication dosing advice to system responses.
- **Deterministic First:** Layer 1 safety rules must run locally with zero external API calls and zero mandatory third-party pip dependencies.

## Local Verification Before Opening a Pull Request

```bash
python3 helio_safety_gate.py
python3 -m unittest test_safety_gate.py -v
python3 benchmark_tamil_safety.py --strict
```

All pull requests are licensed under **Apache-2.0**.
