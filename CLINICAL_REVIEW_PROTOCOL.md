# Clinical Review Protocol & Community Advisory Board Charter

**Status:** Pre-Validation Prototype (0 live patient-facing clinics deployed).  
**Hard Safety Rule:** No patient-facing pilot may launch until **Gate 1 (Clinician Safety Sign-Off)** and **Gate 2 (CDSCO Regulatory Opinion)** are formally completed and logged.

---

## 1. Gate 1 — Practicing Physician Safety Sign-Off (Target: Months 2–4, Apr–May 2027)

Before leaving shadow mode, **2 to 3 practicing outpatient physicians in Coimbatore, Tamil Nadu** (compensated under the Year-1 Mozilla budget) will independently audit:

1. **Red-Flag Escalation Rules:** Every Tamil, Tanglish, English, and Hindi trigger in `SEVERE_EMERGENCY_RULES`, `ELEVATED_SYMPTOM_RULES`, `HOUSEHOLD_POISON_RE`, `COUNTED_OVERDOSE_RE`, and `HYPOGLYCEMIA_CRITICAL_RE`.
2. **Escalation Wording:** Exact bilingual Tamil/English Dial-108 alert text to ensure zero diagnostic claims, zero false reassurance, and culturally clear urgency for working-class families.
3. **3-Turn Progressive Graph Thresholds:** Verify that risk-factor + prodromal symptom accumulation catches atypical/silent presentations (e.g., elderly diabetic patients) without flooding doctors with false alarms.
4. **Shadow-Mode Error Audit:** Run 3–5 Coimbatore clinics in **shadow mode** (observing anonymized/consented intake workflows without sending automated replies to patients) for 4 weeks to establish real OPD baselines and measure real-world sensitivity/specificity.

**Pass Criterion:** Zero missed acute red-flag cases in shadow-mode physician review + written sign-off from at least 2 reviewing physicians before any patient-facing rollout.

---

## 2. Gate 2 — CDSCO Regulatory & India DPDP Legal Classification

- Obtain a formal written legal opinion confirming that HELIO's strictly bounded scope (appointment coordination + deterministic Dial-108 red-flag referral + Zero-Rx output blocking) remains outside CDSCO Software as a Medical Device (SaMD) diagnostic classification—or, if any rule approaches SaMD boundaries, narrow/adjust the rule before pilot launch.
- Complete an independent cybersecurity and privacy audit verifying AES-256-GCM `PIIVault`, zero-PII audit chain, 4-language opt-out, and 22-table DPDP Act erasure compliance.
- Obtain specialist Indian FCRA, FEMA, and tax counsel (or engage an eligible fiscal sponsor if required by Mozilla's eligibility review) prior to receiving grant funds.

---

## 3. Community Advisory Board (CAB) Governance Charter

- **Composition:** 2–3 local Coimbatore physicians, 2 clinic reception/nursing staff, and 2–3 Tamil-speaking patients (all compensated for their time via the Year-1 participatory co-design budget).
- **Authority:** Reviews quarterly shadow-mode and pilot error analyses, approves updates to Tamil/Tanglish safety rules, and holds explicit **pause/halt authority** if clinic workflow friction or safety concerns arise.
- **Transparency:** All non-identifying governance minutes and rule change logs will be published openly in the `helio-governance` Apache-2.0 repository.
