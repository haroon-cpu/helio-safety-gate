# HELIO Human-Scale AI Architecture, Threat Model & Regulatory Boundary

**Repository:** `helio-safety-gate` (`v2.5.0-commons` — Apache-2.0 Open-Source Clinical Safety Commons)  
**Maintainer:** Mohammed Haroon J — Founder, HEONIX AI (Coimbatore, Tamil Nadu, India)

---

## 1. Why a Deterministic Safety Commons Around a Small Local Model?

Small 1-to-3-doctor outpatient clinics in Tamil Nadu manage daily patient WhatsApp inquiries in **Tamil script, Romanized Tanglish, English, and Hindi**. Relying on large foreign cloud LLMs creates three structural failure modes for community healthcare:

1. **Probabilistic Hallucination on High-Stakes Boundaries:** Any generative LLM can hallucinate medication dosages (`"Take Dolo 650 twice daily"`), miss multi-turn code-mixed cardiac escalation (`"nenju pakkam barama irukku"` → `"idadhu kai valikkudhu"`), or be manipulated by prompt injection.
2. **Cloud Cost & Data Sovereignty Failures:** When HEONIX AI's free Google Cloud credits expired during early prototyping, a **₹5,000 cloud bill arrived in a single week** (later waived by Google Support). Streaming patient phone numbers and symptom narratives to foreign servers is both unaffordable for neighborhood clinics and misaligned with India's DPDP Act Rules (taking full effect around May 2027).
3. **Automation Lockout of the Human Doctor:** During an in-person discovery visit and live demo at a Coimbatore dental clinic, requiring a separate SIM card caused a one-week deployment delay and led the dentist to revert to manual replies. Small clinicians must keep their existing number and immediate manual override control.

`helio-safety-gate` solves this by keeping **all life-safety routing, coexistence locks, opt-outs, and privacy cryptography 100% deterministic and local today** (Layers 1 & 3), while migrating administrative language parsing (Layer 2) from the current Gemini API prototype to a **1B–2B 4-bit quantized local model stack** (`Gemma 3 1B` / `Qwen2.5 1.5B` + `AI4Bharat IndicBERT-v3-1B` + MIT-licensed `IndicTrans2`) running on standard 8GB clinic PCs in Year 1.

---

## 2. Three-Layer Human-Scale AI Execution Pipeline

```text
Incoming Patient WhatsApp Message (Tamil / Tanglish / English / Hindi)
   │
   ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: PRE-LLM DETERMINISTIC CLINICAL SAFETY GATE (100% Local Today)    │
│          ~2.1 ms mean CPU latency | ~18.4 KB RAM | 0 Cloud API Calls      │
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
│ LAYER 2: BOUNDED ADMINISTRATIVE RECEPTION MODEL                           │
│          Current Prototype: Gemini API | Year-1 Target: Local 1B–2B 4-bit │
│          (Gemma 3 1B / Qwen2.5 1.5B + IndicBERT-v3-1B on 8GB Clinic PC)   │
│                                                                           │
│  * Handles ONLY administrative clinic reception tasks:                    │
│    appointment slot discovery, clinic timings, address directions,        │
│    and bilingual Tamil/Tanglish reception follow-ups from clinician FAQ.  │
└───────────────────────────────────┬───────────────────────────────────────┘
                                    │ (Draft reply string)
                                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: POST-LLM CLINICAL OUTPUT GUARD & ZERO-PII AUDIT (100% Local)     │
│                                                                           │
│  1. `ClinicalOutputGuard.verify_llm_reply()`                              │
│     └─► Blocks any leaked `mg`/`ml` dosage, named OTC/antibiotic brand    │
│         (`Dolo 650`, `Amoxicillin`, `Calpol`, `Azithromycin`), pregnancy/ │
│         pacemaker safety verdict, or false medical reassurance.           │
│  2. `PIIVault` & `LocalClinicSafetyStore`                                 │
│     └─► AES-256-GCM (`v1:`) at-rest phone encryption + keyed HMAC-SHA256  │
│         (`h1:`) subject hashing + SHA-256 tamper-evident audit chain      │
│     └─► 1-command India DPDP Act 2023 Right-to-Erasure (`erase_subject`)  │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Linguistic Engineering: Solving Two Major Indic Clinical NLP Defects

### Defect A — Indic Combining-Mark Stripping (`खाना` vs `खून` Collision)
Naive regex normalizers strip non-ASCII punctuation using ASCII word classes or strip Unicode Mark categories (`Mn`, `Mc`), destroying Tamil pulli/uyir-mei signs (`U+0B80..0BFF`) and Devanagari vowel matras (`U+0900..097F`). In Hindi, stripping vowel matras causes `"खाना"` (food) and `"खून"` (blood) to collapse into the identical consonant skeleton `"खन"`. `IndicClinicalNormalizer` explicitly preserves all Unicode `L*`, `N*`, and `M*` categories after NFKC normalization and Malayalam atomic chillu folding.

### Defect B — Dravidian Clause-Final Negation (`"நெஞ்சு வலி இல்ல"`)
English clinical NLP checks for negators *before* the symptom (`"no chest pain"`). In Tamil, Romanized Tanglish, and Hindi, negators routinely appear *after* the symptom noun at the end of the clause (`"நெஞ்சு வலி இல்ல"`, `"nenju vali illa"`, `"सीने में दर्द नहीं है"`). `IndicClinicalNormalizer.keyword_hit()` splits utterances along discourse boundaries (`ஆனால்`, `aana`, `but`, punctuation) and checks a bilateral ±3-token window plus agglutinated Tamil negation suffixes (`-இல்லை`, `-illa`).

---

## 4. STRIDE & Clinical AI Threat Model

| Threat Vector | Failure Mode in Standard LLM Chatbots | Deterministic Mitigation in `helio-safety-gate` | Verification Test |
| :--- | :--- | :--- | :--- |
| **Multi-Turn Code-Mixed Escalation** | Patient describes age/diabetes on Turn 1, chest heaviness on Turn 2, and left-arm pain in Tanglish on Turn 3; single-turn classifier misses acute MI. | `ClinicalContextGraph` accumulates risk factors + prodromal symptoms across turns and triggers deterministic Dial-108 routing on Turn 3. | `test_01` |
| **Dravidian Post-Negation & Dental False Alarms** | Patient says `"நெஞ்சு வலி இல்ல, சாதாரண செக்கப் வேணும்"` or `"Mild toothache, dental cleaning tomorrow"`; naive matcher triggers false Dial-108 panic. | Clause-local bilateral negation window suppresses negated clauses while preserving affirmative clauses in the same message. | `test_04`, `test_05`, `test_23` |
| **Prompt Injection + Emergency Collision** | Adversarial or garbled text triggers prompt-injection blocker before emergency triage, dropping a real cardiac or pediatric ingestion call. | `PromptInjectionFirewall` is architecturally wired *after* `SEVERE_EMERGENCY_RULES` so life-safety always wins. | `test_14`, `test_28` |
| **Hallucinated Prescription / False Reassurance** | Downstream model suggests `"Take Dolo 650 twice daily"` or `"It is just mild acidity and completely harmless."` | `ClinicalOutputGuard` intercepts numeric dosages (`mg`, `ml`, `1-0-1`), Indian drug brands, pacemaker/pregnancy verdicts, and false reassurance. | `test_15`, `test_16`, `test_27` |
| **Bot Interrupting Live Doctor Chat** | Doctor replies manually to patient from phone, but bot keeps firing automated booking prompts. | `clinician_manual_reply()` activates a 15-minute (900s) Ghost-Mute while still allowing acute life-threat emergencies to break through. | `test_10`, `test_11` |
| **Cross-Patient Context Bleed** | Risk factors from Patient A bleed into Patient B's triage state in a shared clinic store. | Strict keyed HMAC-SHA256 subject isolation per phone number in SQLite WAL. | `test_24` |
| **Local Database Compromise / Audit Tampering** | Raw patient phone numbers leaked from SQLite or audit logs altered retroactively. | `PIIVault` encrypts phones with AES-256-GCM (`v1:`), hashes subjects via HMAC-SHA256 (`h1:`), logs zero PII, and links every audit row with a SHA-256 hash chain. | `test_18`, `test_19`, `test_20`, `test_26` |

---

## 5. Regulatory & Open-Core IP Boundary

- **Non-Diagnostic Administrative Scope (CDSCO Alignment):** HELIO never diagnoses medical conditions or recommends treatment. Its safety gate strictly performs deterministic administrative routing (routing red-flag emergencies to Tamil Nadu Dial-108 and flagging the human clinician while restricting the LLM to appointment scheduling). Before any patient-facing pilot, HEONIX AI will obtain a formal CDSCO medical-device classification legal opinion and physician safety sign-off.
- **India DPDP Act 2023 Compliance:** Data minimization by design, AES-256-GCM field encryption at rest, zero-PII audit logs, 4-language single-message opt-out (`STOP` / `நிறுத்து` / `vendaam` / `रोकें`), and 1-call `erase_patient_subject()` Right-to-Erasure.
- **Open-Core Commons vs. Commercial Boundary:** This Apache-2.0 repository publishes the complete clinical safety gate, 100-case synthetic benchmark corpus, PIIVault, and audit chain as a permanent public safety commons. HEONIX AI's separate commercial clinic CRM, multi-tenant practice management dashboard, and billing modules remain proprietary.
