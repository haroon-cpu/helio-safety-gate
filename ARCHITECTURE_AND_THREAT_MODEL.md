# HELIO Human-Scale AI Architecture, Threat Model & Regulatory Boundary

**Repository:** `helio-safety-gate` (Apache-2.0 Open-Source Clinical Safety Commons)  
**Maintainer:** Mohammed Haroon J — Founder, HEONIX AI (Coimbatore, Tamil Nadu, India)

---

## 1. Why a Deterministic Safety Commons Around a Small Local Model?

Neighborhood single-doctor clinics across India handle 70–150 daily WhatsApp inquiries in **code-mixed Tamil, Romanized Tanglish, English, and Hindi**. Relying on giant frontier cloud APIs creates three unacceptable failure modes for community healthcare:

1. **Probabilistic Hallucination on High-Stakes Boundaries:** Even a 70B cloud LLM can hallucinate medication dosages (`"Take Dolo 650 twice daily"`), miss multi-turn code-mixed cardiac escalation (`"nenju pakkam barama irukku"` $\rightarrow$ `"idadhu kai valikkudhu"`), or be tricked by prompt injection.
2. **Cloud Data Extraction & Per-Token Rent:** Streaming patient phone numbers and symptom notes to external US cloud servers violates patient sovereignty and imposes recurring API costs on low-margin neighborhood doctors.
3. **Automation Lockout of the Human Doctor:** Most clinic chatbots hijack the clinic's WhatsApp number, continuing to send automated replies even while the doctor is actively typing to a patient.

`helio-safety-gate` solves this by wrapping a fine-tuned **2B-parameter local reception model** (`Gemma-2-2B` / `Llama-3.2-1B`, 4-bit quantized, running on a ₹35,000 / ~$420 clinic mini-PC) inside a **100% deterministic, zero-cloud Python safety envelope**.

---

## 2. Three-Layer Human-Scale AI Execution Pipeline

```text
Incoming Patient WhatsApp Message (Tamil / Tanglish / English / Hindi)
   │
   ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: PRE-LLM DETERMINISTIC CLINICAL SAFETY GATE (< 1 ms, Zero-LLM)   │
│                                                                           │
│  1. 4-Language Opt-Out Gate (`en`, `ta`, `tanglish`, `hi`)                │
│     └─► Immediate opt-out confirmation + durable SQLite suppression       │
│  2. Indic & Tanglish Normalizer (`IndicClinicalNormalizer`)               │
│     └─► Preserves Unicode `M*` vowel signs + bilateral clause negation    │
│  3. 3-Turn Progressive Clinical Context Graph (`ClinicalContextGraph`)    │
│     └─► Risk factors + prodromal symptoms + red-flag/overdose/poison      │
│     └─► If EMERGENCY: Immediate Tamil Nadu Dial-108 + Doctor Alert        │
│         (Always breaks through active Ghost-Mute; LLM is bypassed)        │
│  4. 15-Minute Clinician Ghost-Mute Coexistence Check                      │
│     └─► If doctor replied manually within last 900s: suppress bot reply   │
│  5. Multilingual Prompt Injection Firewall (`PromptInjectionFirewall`)    │
│     └─► Executed AFTER emergency triage so emergencies are never dropped  │
└───────────────────────────────────┬───────────────────────────────────────┘
                                    │ (Only if `llm_allowed == True`)
                                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: LOCAL 2B RECEPTION LANGUAGE MODEL (On-Premises CPU / 4-bit GGUF) │
│                                                                           │
│  * Handles ONLY administrative clinic reception tasks:                    │
│    appointment slot discovery, clinic timings, address directions,        │
│    and bilingual Tamil/Tanglish reception follow-ups.                     │
└───────────────────────────────────┬───────────────────────────────────────┘
                                    │ (Draft reply string)
                                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: POST-LLM CLINICAL OUTPUT GUARD & ZERO-PII AUDIT CHAIN            │
│                                                                           │
│  1. `ClinicalOutputGuard.verify_llm_reply()`                              │
│     └─► Blocks any leaked `mg`/`ml` dosage, named OTC/antibiotic brand    │
│         (`Dolo 650`, `Amoxicillin`, `Calpol`), pregnancy/pacemaker safety │
│         verdict, or false medical reassurance.                            │
│  2. `PIIVault` & `LocalClinicSafetyStore`                                 │
│     └─► AES-256-GCM (`v1:`) at-rest phone encryption + keyed HMAC-SHA256  │
│         (`h1:`) subject hashing + SHA-256 tamper-evident audit chain      │
│     └─► 1-command India DPDP Act 2023 Right-to-Erasure (`erase_subject`)  │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Linguistic Engineering: Solving Two Major Indic Clinical NLP Defects

### Defect A — Indic Combining-Mark Stripping (`खाना` vs `खून` Collision)
Naive regex normalizers strip non-ASCII punctuation using ASCII word classes or strip Unicode Mark categories (`Mn`, `Mc`), which destroys Tamil pulli/uyir-mei signs (`U+0B80..0BFF`) and Devanagari vowel matras (`U+0900..097F`). In Hindi, stripping vowel matras causes `"खाना"` (food) and `"खून"` (blood) to collapse into the identical consonant skeleton `"खन"`. `IndicClinicalNormalizer` explicitly preserves all Unicode `L*`, `N*`, and `M*` categories after NFKC normalization and Malayalam atomic chillu folding.

### Defect B — Dravidian Clause-Final Negation (`"நெஞ்சு வலி இல்ல"`)
English clinical NLP checks for negators *before* the symptom (`"no chest pain"`). In Tamil, Romanized Tanglish, and Hindi, negators routinely appear *after* the symptom noun at the end of the clause (`"நெஞ்சு வலி இல்ல"`, `"nenju vali illa"`, `"सीने में दर्द नहीं है"`). `IndicClinicalNormalizer.keyword_hit()` splits utterances along discourse boundaries (`ஆனால்`, `aana`, `but`, punctuation) and checks a bilateral $\pm 3$-token window plus agglutinated Tamil negation suffixes (`-இல்லை`, `-illa`).

---

## 4. STRIDE & Clinical AI Threat Model

| Threat Vector | Failure Mode in Standard LLM Chatbots | Deterministic Mitigation in `helio-safety-gate` | Verification Test |
| :--- | :--- | :--- | :--- |
| **Multi-Turn Code-Mixed Escalation** | Patient describes age/diabetes on Turn 1, chest heaviness on Turn 2, and left-arm pain in Tanglish on Turn 3; single-turn classifier misses acute MI. | `ClinicalContextGraph` accumulates risk factors + prodromal symptoms across turns and triggers deterministic Dial-108 routing on Turn 3. | `test_01_three_turn_progressive_tanglish_cardiac_escalation` |
| **Dravidian Post-Negation False Alarm** | Patient says `"நெஞ்சு வலி இல்ல, சாதாரண செக்கப் வேணும்"`; naive keyword matcher triggers false Dial-108 panic. | Clause-local bilateral negation window suppresses negated clauses while preserving affirmative clauses in the same message. | `test_04_tamil_and_tanglish_post_negation_immunity` |
| **Prompt Injection + Emergency Collision** | Adversarial or garbled text triggers prompt-injection blocker before emergency triage, dropping a real cardiac/syncope call. | `PromptInjectionFirewall` is architecturally wired *after* `SEVERE_EMERGENCY_RULES` so life-safety always wins. | `test_14_emergency_takes_precedence_over_prompt_injection_firewall` |
| **Hallucinated Prescription / Dosage Leak** | Local 2B model suggests `"Take Dolo 650 twice daily"` or `"Amoxicillin 500mg"`. | `ClinicalOutputGuard` intercepts numeric dosages (`mg`, `ml`, `1-0-1`), drug brands, and false reassurance before delivery. | `test_15_output_guard_blocks_medication_dosages_and_brands` |
| **Bot Interrupting Live Doctor Chat** | Doctor replies manually to patient from phone, but bot keeps firing automated booking prompts. | `clinician_manual_reply()` activates a 15-minute (900s) Ghost-Mute while still allowing life-threat emergencies to break through. | `test_10` & `test_11` |
| **Local Database Compromise / Tampering** | Raw patient phone numbers leaked from SQLite or audit logs altered retroactively. | `PIIVault` encrypts phones with AES-256-GCM (`v1:`), hashes subjects via HMAC-SHA256 (`h1:`), and links every audit row with a SHA-256 hash chain. | `test_18`, `test_19`, `test_20` |

---

## 5. Regulatory & Open-Core IP Boundary

* **Non-Diagnostic Administrative Scope (CDSCO Alignment):** HELIO never diagnoses medical conditions or recommends treatment. Its safety gate strictly performs deterministic administrative routing (routing red-flag emergencies to Tamil Nadu Dial-108 and flagging the human clinician while restricting the LLM to appointment scheduling).
* **India DPDP Act 2023 Compliance:** Data minimization by design, AES-256-GCM field encryption at rest, zero-PII audit logs, 4-language single-message opt-out (`STOP` / `நிறுத்து` / `vendaam` / `रोकें`), and 1-call `erase_patient_subject()` Right-to-Erasure.
* **Open-Core Commons vs. Commercial Boundary:** This Apache-2.0 repository publishes the complete clinical safety gate, benchmark corpus, PIIVault, and audit chain as a public safety commons that any clinic or researcher can audit and adopt. HEONIX AI's proprietary commercial clinic CRM, multi-tenant practice management dashboard, and automated billing workflows remain separate commercial modules.
