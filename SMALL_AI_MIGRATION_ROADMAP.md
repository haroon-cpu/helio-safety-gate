# Small-AI Local Migration Roadmap (Prototype → 8GB Clinic PC)

**Goal:** Eliminate 100% of frontier cloud API dependency during Year 1 of the Mozilla Human-Scale AI Incubator so small clinics in Tamil Nadu run HELIO completely offline on affordable local hardware with zero per-token cloud bills.

---

## 1. Current State (Honest Baseline — Nov 2026)

| Layer | Current Execution | Cloud API Calls | Hardware Requirement |
| :--- | :--- | :--- | :--- |
| **Layer 1: Pre-LLM Safety Gate** (`helio-safety-gate`) | **100% Local Deterministic Python** | **0** | Any CPU (~2.1 ms mean, ~18.4 KB RAM) |
| **Layer 2: Administrative Language Parsing** | **Gemini API (Prototype)** | 1 per routine turn | Cloud internet required |
| **Layer 3: Post-LLM Zero-Rx Guard, PIIVault & Audit Chain** | **100% Local Deterministic Python + SQLite** | **0** | Any CPU (< 1 ms) |

**Why we are migrating:** When our free Google Cloud credits expired during early prototyping, a **₹5,000 cloud bill hit in a single week** (waived by Google Support). Combined with uneven rural Tamil Nadu internet connectivity (TRAI March 2026: 20.36M rural vs. 48.65M urban subscriptions) and India's DPDP Act Rules (taking full effect around May 2027), cloud-dependent AI is structurally unsuitable for small independent clinics.

---

## 2. Target Year-1 Local Stack (8GB Clinic Mini-PC / Intel N100 Class)

| Component | Candidate Open-Weight Models | Quantization / Format | Target RAM Budget | Role |
| :--- | :--- | :--- | :--- | :--- |
| **Layer 1 Safety Gate** | `helio-safety-gate` (Python) | Deterministic (no weights) | < 10 MB | 108 escalation, negation, Ghost-Mute, opt-out, firewall |
| **Layer 2A Indic Normalization & Intent** | `AI4Bharat IndicBERT-v3-1B` + `IndicTrans2` (MIT) | INT8 ONNX Runtime (CPU) | ~1.2 GB | Tanglish/Tamil script normalization & administrative intent routing |
| **Layer 2B Bounded Reception Generation** | `Gemma 3 1B` or `Qwen2.5 1.5B` (benchmarked head-to-head) | 4-bit GGUF (`Q4_K_M`, `llama.cpp`) | ~1.1 – 1.5 GB | Slot booking, timings, directions strictly from clinician-approved FAQ |
| **Layer 3 Output Guard & Encrypted Store** | `ClinicalOutputGuard` + `PIIVault` + SQLite WAL | Deterministic (no weights) | < 20 MB | Zero-Rx enforcement, AES-256-GCM encryption, SHA-256 audit chain |
| **OS + Runtime Headroom** | Linux / Windows 11 + Battery UPS | — | ~3.5 GB | Keeps total footprint comfortably under **6.5 GB on an 8GB clinic PC** |

---

## 3. Phased Year-1 Execution Milestones

1. **Months 1–3 (Hardware & Model Benchmarking):** Benchmark `Gemma 3 1B`, `Qwen2.5 1.5B`, and `AI4Bharat IndicBERT-v3-1B` on real 8GB Intel N100 mini-PCs in Coimbatore. Publish open quarterly benchmarks measuring real CPU latency, RAM ceiling, Tamil/Tanglish booking accuracy, and watt-hour power draw on UPS backup.
2. **Months 4–6 (Shadow-Mode Parity & Gate 1 Clinical Review):** Run the local 1B–2B stack in **shadow mode** across 3–5 Coimbatore clinics alongside existing manual WhatsApp workflows. Zero automated patient replies go out until 2–3 practicing Coimbatore physicians sign off on Gate 1 sensitivity and specificity thresholds.
3. **Months 7–12 (Offline-First Pilot Rollout & Zero-Cloud Cutover):** Transition to 10–20 pilot clinics using the 100% local stack with deterministic fallback templates whenever the local model times out or triggers `ClinicalOutputGuard`. Retire all frontier cloud API dependencies permanently.
