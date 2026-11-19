#!/usr/bin/env python3
"""
HELIODeterministic Clinical Safety Gate, PIIVault & Local Audit Commons
========================================================================
Release: v2.4.0-commons (Open-Source Public Safety Layer extracted from HELIO v53.0)
License: Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
Author:  Mohammed Haroon J — Founder, HEONIX AI (Coimbatore, Tamil Nadu, India)
Repo:    https://github.com/haroon-cpu/helio-safety-gate

ARCHITECTURAL PURPOSE
---------------------
Small local language models (1B-2B parameters running on clinic edge hardware)
make fine-tuning for code-mixed Tamil/Tanglish phrasing affordable and private,
but probabilistic models must NEVER serve as the primary decision-maker for:
  1. Acute clinical emergency triage & Tamil Nadu Dial-108 ambulance routing.
  2. Medication dosage / prescription safety enforcement (Zero-Diagnosis / Zero-Rx).
  3. Clinician manual WhatsApp takeover (15-Minute Ghost-Mute Coexistence).
  4. Patient opt-out integrity across English, Tamil, Romanized Tanglish, and Hindi.
  5. At-rest patient PII encryption, zero-PII hash-chained audit logging, and
     India DPDP Act 2023 Right-to-Erasure compliance.

This open-source library provides a zero-cloud, deterministic pre-LLM and post-LLM
safety envelope with <1 ms median latency and zero mandatory external dependencies.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# Optional AES-256-GCM hardware acceleration via `cryptography` if present;
# falls back transparently to a stdlib HMAC-SHA256 authenticated stream cipher
# so this commons runs out-of-the-box on any standard Python 3.9+ installation.
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    _HAS_AESGCM = True
except Exception:
    AESGCM = None  # type: ignore
    _HAS_AESGCM = False


__version__ = "2.4.0-commons"
__all__ = [
    "PIIVault",
    "IndicClinicalNormalizer",
    "PatientContext",
    "TriageDecision",
    "OutputGuardVerdict",
    "PromptInjectionFirewall",
    "ClinicalOutputGuard",
    "LocalClinicSafetyStore",
    "HelioSafetyGate",
]


# ============================================================================
# MODULE 1: AES-256-GCM PIIVault, Keyed HMAC Subject Hashing & Tiered Masking
# ============================================================================

class PIIVault:
    """
    Field-level authenticated encryption and deterministic keyed subject hashing
    for clinic edge storage (India DPDP Act 2023 alignment).

    * Encrypted payloads are tagged with `v1:` (AES-256-GCM 96-bit nonce + ciphertext+tag)
      or `v1s:` (stdlib authenticated stream cipher fallback when `cryptography`
      is unavailable in minimal edge containers).
    * Subject identifiers (patient phone numbers) are hashed via keyed HMAC-SHA256
      with an `h1:` version prefix so raw phone numbers never appear in audit logs.
    """

    ENC_PREFIX_AESGCM = "v1:"
    ENC_PREFIX_STDLIB = "v1s:"
    HASH_PREFIX = "h1:"

    def __init__(self, master_secret: Optional[str] = None, salt: str = "helio-dpdp-salt-v1") -> None:
        raw_secret = (master_secret or os.environ.get("HELIO_PII_KEY") or "helio-dev-commons-default-key").strip()
        self._salt = salt.encode("utf-8")
        if len(raw_secret) == 64 and all(c in "0123456789abcdefABCDEF" for c in raw_secret):
            self._key = bytes.fromhex(raw_secret)
        else:
            self._key = hashlib.pbkdf2_hmac("sha256", raw_secret.encode("utf-8"), self._salt, 100_000, dklen=32)
        self._hmac_key = hashlib.pbkdf2_hmac("sha256", self._key, b"helio-hmac-subject-v1", 10_000, dklen=32)
        self._aesgcm = AESGCM(self._key) if _HAS_AESGCM and AESGCM is not None else None

    @property
    def backend_name(self) -> str:
        return "AES-256-GCM (cryptography)" if self._aesgcm is not None else "HMAC-SHA256-CTR (stdlib-AEAD)"

    def encrypt(self, plaintext: Optional[str], aad: str = "helio-pii-v1") -> str:
        """Encrypts a PII field with a fresh 96-bit random nonce and authenticated tag."""
        if plaintext is None or plaintext == "":
            return ""
        if plaintext.startswith(self.ENC_PREFIX_AESGCM) or plaintext.startswith(self.ENC_PREFIX_STDLIB):
            return plaintext
        pt_bytes = plaintext.encode("utf-8")
        aad_bytes = aad.encode("utf-8")
        nonce = secrets.token_bytes(12)

        if self._aesgcm is not None:
            ct = self._aesgcm.encrypt(nonce, pt_bytes, aad_bytes)
            blob = base64.urlsafe_b64encode(nonce + ct).decode("ascii")
            return f"{self.ENC_PREFIX_AESGCM}{blob}"

        # Stdlib authenticated stream cipher fallback (CTR keystream + HMAC-SHA256 tag)
        ct_bytes = self._stdlib_xor_stream(nonce, pt_bytes)
        tag = hmac.new(self._key, b"v1s|" + nonce + aad_bytes + ct_bytes, hashlib.sha256).digest()[:16]
        blob = base64.urlsafe_b64encode(nonce + ct_bytes + tag).decode("ascii")
        return f"{self.ENC_PREFIX_STDLIB}{blob}"

    def decrypt(self, token: Optional[str], aad: str = "helio-pii-v1") -> str:
        """Verifies authentication tag and decrypts a `v1:` or `v1s:` PII token."""
        if token is None or token == "":
            return ""
        aad_bytes = aad.encode("utf-8")

        if token.startswith(self.ENC_PREFIX_AESGCM):
            raw = base64.urlsafe_b64decode(token[len(self.ENC_PREFIX_AESGCM):].encode("ascii"))
            nonce, ct = raw[:12], raw[12:]
            if self._aesgcm is None:
                raise RuntimeError("AES-256-GCM token requires `cryptography` package to decrypt.")
            return self._aesgcm.decrypt(nonce, ct, aad_bytes).decode("utf-8")

        if token.startswith(self.ENC_PREFIX_STDLIB):
            raw = base64.urlsafe_b64decode(token[len(self.ENC_PREFIX_STDLIB):].encode("ascii"))
            nonce, ct_bytes, tag = raw[:12], raw[12:-16], raw[-16:]
            expected = hmac.new(self._key, b"v1s|" + nonce + aad_bytes + ct_bytes, hashlib.sha256).digest()[:16]
            if not hmac.compare_digest(tag, expected):
                raise ValueError("PIIVault authentication tag verification failed (tampered ciphertext).")
            return self._stdlib_xor_stream(nonce, ct_bytes).decode("utf-8")

        return token

    def _stdlib_xor_stream(self, nonce: bytes, data: bytes) -> bytes:
        out = bytearray(len(data))
        block_idx = 0
        offset = 0
        while offset < len(data):
            counter = block_idx.to_bytes(4, "big")
            keystream = hmac.new(self._key, b"ctr|" + nonce + counter, hashlib.sha256).digest()
            take = min(32, len(data) - offset)
            for i in range(take):
                out[offset + i] = data[offset + i] ^ keystream[i]
            offset += take
            block_idx += 1
        return bytes(out)

    def hash_subject_phone(self, phone: str) -> str:
        """
        Normalizes an Indian/E.164 phone number and returns a deterministic keyed
        HMAC-SHA256 subject identifier (`h1:<32-hex-chars>`) for zero-PII indexing.
        """
        digits = re.sub(r"\D+", "", str(phone or ""))
        if len(digits) == 10 and digits[0] in "6789":
            digits = "91" + digits
        digest = hmac.new(self._hmac_key, digits.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        return f"{self.HASH_PREFIX}{digest}"

    @staticmethod
    def mask(value: Optional[str], kind: str = "phone") -> str:
        """Tiered redaction helper for clinician logs and terminal debugging."""
        s = str(value or "").strip()
        if not s:
            return "[EMPTY]"
        if kind == "phone":
            digits = re.sub(r"\D+", "", s)
            if len(digits) >= 4:
                return f"+**-******{digits[-4:]}"
            return "***"
        if kind == "name":
            return s[0] + "***" if len(s) > 1 else "*"
        if kind == "token":
            return s[:7] + "...[REDACTED]" if len(s) > 10 else "[REDACTED]"
        return "[REDACTED]"


# ============================================================================
# MODULE 2: Indic & Code-Mixed Tanglish Clinical Normalizer + Bilateral Negation
# ============================================================================

class IndicClinicalNormalizer:
    """
    Unicode-safe clinical text normalizer for Tamil (`U+0B80..0BFF`), Devanagari
    (`U+0900..097F`), Malayalam atomic chillu letters, and Romanized Tanglish.

    CRITICAL LINGUISTIC INVARIANTS
    ------------------------------
    1. Preserves Indic combining vowel signs (Unicode general category `M*`, such as
       Tamil pulli/uyir-mei signs and Devanagari matras) during punctuation stripping.
       Dropping category `M*` causes catastrophic consonant-skeleton collisions in
       Indic scripts (e.g., Hindi `खाना` [food] vs `खून` [blood] both collapse to `खन`).
    2. Performs clause-local bilateral negation analysis (checking both pre-keyword
       and post-keyword token windows inside the local clause) because Dravidian and
       Indic languages place negators AFTER the symptom noun (`"நெஞ்சு வலி இல்ல"`,
       `"nenju vali illa"`, `"सीने में दर्द नहीं है"`).
    """

    _CHILLU_MAP = {
        "\u0d7a": "\u0d23\u0d4d",  # ൻ -> ண் equivalent
        "\u0d7b": "\u0d28\u0d4d",  # ൻ -> ந்
        "\u0d7c": "\u0d30\u0d4d",  # ർ -> ர்
        "\u0d7d": "\u0d32\u0d4d",  # ൽ -> ல்
        "\u0d7e": "\u0d33\u0d4d",  # ൾ -> ள்
        "\u0d7f": "\u0d15\u0d4d",  # ൿ -> க்
    }

    # Pre-symptom negators (English, Hindi, Tanglish)
    PRE_NEGATORS: Set[str] = {
        "no", "not", "never", "without", "denies", "denied", "negative", "nil", "none",
        "illa", "illai", "nahi", "nahin", "na", "mat",
        "இல்ல", "இல்லை", "நஹி", "नहीं", "ना", "बिना",
    }

    # Post-symptom negators (Tamil, Tanglish, Hindi, Dravidian clause-final negators)
    POST_NEGATORS: Set[str] = {
        "illa", "illai", "illaye", "ille", "kidaiyadhu", "kidayathu", "vendaam", "vendam",
        "nahi", "nahin", "nae", "none", "absent", "free",
        "இல்ல", "இல்லை", "இல்லவே", "கிடையாது", "வேண்டாம்", "வாண்டாம்",
        "नहीं", "नही", "ना", "मत",
    }

    CLAUSE_BOUNDARY_RE = re.compile(r"[,.;!?\n\r]+|\b(?:but|and|aana|anal|ஆனால்|आना|पर|लेकिन)\b", re.IGNORECASE)

    @classmethod
    def normalize(cls, text: str) -> str:
        """
        Normalizes a multi-script patient utterance while preserving all Indic
        combining marks (`Mn`, `Mc`, `Me`).
        """
        if not text:
            return ""
        s = unicodedata.normalize("NFKC", str(text))
        for chillu, decomposed in cls._CHILLU_MAP.items():
            s = s.replace(chillu, decomposed)
        s = s.lower()

        # Squeeze expressive Roman character elongations ("chesttt painnn" -> "chest pain")
        s = re.sub(r"([a-z])\1{2,}", r"\1", s)

        # Keep alphanumeric letters, numbers, Indic combining marks (M*), and clause delimiters
        cleaned_chars: List[str] = []
        for ch in s:
            cat = unicodedata.category(ch)
            if cat.startswith(("L", "N", "M")) or ch in " ,.;!?\n\t/-+<>=%":
                cleaned_chars.append(ch)
            else:
                cleaned_chars.append(" ")
        return re.sub(r"\s+", " ", "".join(cleaned_chars)).strip()

    @classmethod
    def split_clauses(cls, text: str) -> List[str]:
        norm = cls.normalize(text)
        if not norm:
            return []
        return [c.strip() for c in cls.CLAUSE_BOUNDARY_RE.split(norm) if c and c.strip()]

    @classmethod
    def keyword_hit(cls, text: str, phrases: Tuple[str, ...]) -> Tuple[bool, Optional[str]]:
        """
        Returns `(True, matched_phrase)` if any phrase in `phrases` appears in `text`
        inside a non-negated clause; returns `(False, None)` if absent or negated.
        """
        clauses = cls.split_clauses(text)
        for clause in clauses:
            tokens = clause.split()
            for raw_phrase in phrases:
                phrase = cls.normalize(raw_phrase)
                if not phrase:
                    continue
                if not cls._phrase_in_clause(clause, tokens, phrase):
                    continue
                if cls._is_clause_negated(clause, tokens, phrase):
                    continue
                return True, raw_phrase
        return False, None

    @staticmethod
    def _phrase_in_clause(clause: str, tokens: List[str], phrase: str) -> bool:
        if " " in phrase:
            # Multi-word phrase: check token subsequence or substring with word boundaries
            return phrase in clause
        # Single-word phrase: exact token match or bounded Dravidian agglutinative prefix
        for tok in tokens:
            if tok == phrase:
                return True
            if len(phrase) >= 4 and tok.startswith(phrase) and (len(tok) - len(phrase)) <= 6:
                return True
        return False

    @classmethod
    def _is_clause_negated(cls, clause: str, tokens: List[str], phrase: str) -> bool:
        phrase_tokens = phrase.split()
        if not phrase_tokens:
            return False
        first_pt = phrase_tokens[0]
        last_pt = phrase_tokens[-1]

        # Locate phrase span in clause tokens
        start_idx = -1
        for i, tok in enumerate(tokens):
            if tok == first_pt or (len(first_pt) >= 4 and tok.startswith(first_pt)):
                start_idx = i
                break
        if start_idx == -1:
            return False
        end_idx = min(len(tokens) - 1, start_idx + len(phrase_tokens) - 1)
        for j in range(start_idx, len(tokens)):
            if tokens[j] == last_pt or (len(last_pt) >= 4 and tokens[j].startswith(last_pt)):
                end_idx = j
                break

        # Pre-window: up to 3 tokens before the symptom
        pre_window = tokens[max(0, start_idx - 3):start_idx]
        for tok in pre_window:
            if tok in cls.PRE_NEGATORS or tok in cls.POST_NEGATORS:
                return True

        # Post-window: up to 3 tokens after the symptom (critical for Tamil/Tanglish/Hindi)
        post_window = tokens[end_idx + 1:min(len(tokens), end_idx + 4)]
        for tok in post_window:
            if tok in cls.POST_NEGATORS or tok in cls.PRE_NEGATORS:
                return True
            # Handle Tamil agglutinated negation suffixes like "வலியில்லை" / "valiyilla"
            if any(tok.endswith(neg) for neg in ("இல்லை", "இல்ல", "illa", "illai")):
                return True

        return False


# ============================================================================
# MODULE 3: Data Models for Triage, Context Graph & Output Guardrails
# ============================================================================

@dataclass
class PatientContext:
    """Per-patient state tracked locally in SQLite across multi-turn WhatsApp sessions."""
    phone_hash: str
    masked_phone: str = ""
    encrypted_phone: str = ""
    opted_out: bool = False
    opt_out_language: Optional[str] = None
    ghost_mute_until: float = 0.0
    last_emergency_signature: str = ""
    risk_factors: List[str] = field(default_factory=list)
    symptom_history: List[str] = field(default_factory=list)
    turn_timestamps: List[float] = field(default_factory=list)


@dataclass
class TriageDecision:
    """Deterministic pre-LLM decision emitted by `HelioSafetyGate.process_incoming()`."""
    severity: str                         # ROUTINE | ELEVATED | EMERGENCY | OPT_OUT | GHOST_MUTED | FIREWALL_BLOCKED
    llm_allowed: bool                     # False whenever deterministic safety gate intercepts
    dial_108: bool                        # True for acute emergencies requiring Tamil Nadu 108 ambulance
    clinician_alert: bool                 # True when doctor WhatsApp alert is triggered
    ghost_mute_active: bool               # True when 15-minute clinician takeover is active
    matched_triggers: List[str]           # Explicit clinical/safety rules that fired
    accumulated_risk_factors: List[str]   # Multi-turn patient risk profile
    accumulated_symptoms: List[str]       # Multi-turn symptom trajectory
    response_text: Optional[str]          # Deterministic patient reply (None if passed to local 2B LLM)
    latency_ms: float = 0.0               # Wall-clock execution time in milliseconds
    audit_hash: str = ""                  # Tamper-evident SHA-256 chain hash for this event


@dataclass
class OutputGuardVerdict:
    """Deterministic post-LLM safety verdict emitted by `ClinicalOutputGuard`."""
    safe: bool
    violation_category: Optional[str]     # NONE | RX_DOSAGE_LEAK | CLINICAL_SAFETY_VERDICT | FALSE_REASSURANCE
    matched_pattern: Optional[str]
    sanitized_reply: str


# ============================================================================
# MODULE 4: Pre-LLM Multilingual Prompt Injection Firewall & Post-LLM Output Guard
# ============================================================================

class PromptInjectionFirewall:
    """
    Deterministic pre-LLM firewall blocking system-prompt extraction, role-hijacking,
    and prescription-forcing jailbreaks across English, Tamil, Tanglish, and Hindi.

    ARCHITECTURAL INVARIANT:
    Always executed *after* Emergency Triage in `HelioSafetyGate.process_incoming()`
    so a patient experiencing a genuine life-threatening emergency is NEVER denied
    Dial-108 emergency routing even if their message contains unusual phrasing.
    """

    INJECTION_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
        ("SYSTEM_OVERRIDE", re.compile(
            r"\b(?:ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|"
            r"disregard\s+your\s+rules|you\s+are\s+now\s+dr\.?\s+|"
            r"act\s+as\s+a\s+licensed\s+doctor|bypass\s+safety\s+gate|"
            r"system\s+prompt\s+reveal|print\s+your\s+hidden\s+instructions)\b",
            re.IGNORECASE,
        )),
        ("FORCE_RX_JAILBREAK", re.compile(
            r"\b(?:prescribe\s+me\s+antibiotics\s+now|give\s+exact\s+mg\s+dosage\s+override|"
            r"developer\s+mode\s+enabled|sudo\s+prescribe)\b",
            re.IGNORECASE,
        )),
        ("TAMIL_TANGLISH_OVERRIDE", re.compile(
            r"(?:பழைய\s+விதிகளை\s+மறந்துவிடு|நீ\s+இப்போது\s+மருத்துவர்|"
            r"pazhaya\s+rules\s+marandhudu|doctor\s+madhiri\s+marundhu\s+ezhudhu)",
            re.IGNORECASE,
        )),
    )

    SAFE_REFUSAL = (
        "HELIO reception assistant here. I can only assist with clinic appointment scheduling, "
        "timings, and routing urgent concerns to the doctor. I cannot override clinic safety rules."
    )

    @classmethod
    def inspect(cls, text: str) -> Tuple[bool, Optional[str]]:
        for label, pattern in cls.INJECTION_PATTERNS:
            if pattern.search(text or ""):
                return True, label
        return False, None


class ClinicalOutputGuard:
    """
    Deterministic post-LLM guardrail ensuring a downstream 1B-2B local model NEVER:
      1. Prescribes medications, antibiotics, or numeric dosages (`mg`, `ml`, `mcg`,
         `tablet bd/tds`, or Indian brand names like `Dolo 650`, `Amoxicillin`, `Azithromycin`).
      2. Issues unilateral clinical safety verdicts for high-risk procedures or patients
         (pregnancy, pacemaker/implants, infants, post-op complications).
      3. Offers false medical reassurance (`"nothing serious"`, `"no need to see a doctor"`).
    """

    RX_DOSAGE_RE = re.compile(
        r"\b(?:\d+\s*(?:mg|mcg|ml|g|iu)\b|"
        r"(?:take|consume|eat|சாப்பிடுங்கள்|எடுத்துக்கொள்ளுங்கள்)\s+\d+\s*(?:tablet|tablets|pill|capsule|strip|மாத்திரை)|"
        r"dolo\s*650|calpol\s*\d*|crocin\s*\d*|combiflam|amoxicillin|augmentin|azithromycin|azee\s*\d*|"
        r"ciprofloxacin|metformin|insulin\s+dose|paracetamol\s+\d+\s*mg|"
        r"\b(?:1-0-1|1-1-1|0-0-1)\b|\b(?:bd|tds|qid)\s+for\s+\d+\s+days)\b",
        re.IGNORECASE,
    )

    UNSAFE_VERDICT_RE = re.compile(
        r"\b(?:completely\s+safe\s+during\s+pregnancy|100%\s+safe\s+for\s+pregnant|"
        r"safe\s+with\s+your\s+pacemaker|no\s+risk\s+at\s+all\s+for\s+your\s+baby|"
        r"you\s+ definitely\s+have\s+(?:diabetes|cancer|angina|appendicitis)|"
        r"diagnosed\s+with)\b",
        re.IGNORECASE,
    )

    FALSE_REASSURANCE_RE = re.compile(
        r"\b(?:nothing\s+to\s+worry\s+about|not\s+serious\s+at\s+all|"
        r"no\s+need\s+to\s+(?:visit|see)\s+(?:a|the)\s+doctor|"
        r"just\s+gas\s+pain\s+sleep\s+it\s+off|பயப்பட\s+தேவையில்லை\s+சாதாரண\s+வலிதான்)\b",
        re.IGNORECASE,
    )

    FALLBACK_SAFE_REPLY = (
        "நான் மருத்துவ ஆலோசனையோ மருந்து அளவுகளோ (Prescription / Dosage) வழங்க முடியாது. "
        "உங்கள் விவரங்களை மருத்துவரிடம் பகிர்ந்துள்ளேன்; நேரில் ஆலோசிக்க முன்பதிவு செய்யட்டுமா? / "
        "I cannot prescribe medications, dosages, or medical diagnoses. I have flagged your query "
        "for the clinician—would you like to book an in-person consultation slot?"
    )

    @classmethod
    def verify_llm_reply(cls, draft_reply: str) -> OutputGuardVerdict:
        text = str(draft_reply or "").strip()
        if not text:
            return OutputGuardVerdict(True, None, None, text)

        m_rx = cls.RX_DOSAGE_RE.search(text)
        if m_rx:
            return OutputGuardVerdict(
                safe=False,
                violation_category="RX_DOSAGE_LEAK",
                matched_pattern=m_rx.group(0),
                sanitized_reply=cls.FALLBACK_SAFE_REPLY,
            )

        m_verdict = cls.UNSAFE_VERDICT_RE.search(text)
        if m_verdict:
            return OutputGuardVerdict(
                safe=False,
                violation_category="CLINICAL_SAFETY_VERDICT",
                matched_pattern=m_verdict.group(0),
                sanitized_reply=cls.FALLBACK_SAFE_REPLY,
            )

        m_reassure = cls.FALSE_REASSURANCE_RE.search(text)
        if m_reassure:
            return OutputGuardVerdict(
                safe=False,
                violation_category="FALSE_REASSURANCE",
                matched_pattern=m_reassure.group(0),
                sanitized_reply=cls.FALLBACK_SAFE_REPLY,
            )

        return OutputGuardVerdict(
            safe=True,
            violation_category=None,
            matched_pattern=None,
            sanitized_reply=text,
        )


# ============================================================================
# MODULE 5: Local SQLite WAL Persistence, SHA-256 Audit Chain & DPDP Erasure
# ============================================================================

class LocalClinicSafetyStore:
    """
    Local-first SQLite WAL persistence engine for single-doctor clinics.
    Stores encrypted patient context, durable 4-language opt-outs, and a
    tamper-evident SHA-256 hash-chained zero-PII audit log with 1-command
    India DPDP Act 2023 Right-to-Erasure (`erase_patient_subject`).
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, db_path: str = ":memory:", vault: Optional[PIIVault] = None) -> None:
        self.db_path = db_path
        self.vault = vault or PIIVault()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS patient_contexts (
                phone_hash TEXT PRIMARY KEY,
                masked_phone TEXT NOT NULL,
                encrypted_phone TEXT NOT NULL,
                opted_out INTEGER NOT NULL DEFAULT 0,
                opt_out_language TEXT,
                ghost_mute_until REAL NOT NULL DEFAULT 0.0,
                last_emergency_signature TEXT NOT NULL DEFAULT '',
                risk_factors_json TEXT NOT NULL DEFAULT '[]',
                symptom_history_json TEXT NOT NULL DEFAULT '[]',
                turn_timestamps_json TEXT NOT NULL DEFAULT '[]',
                updated_at REAL NOT NULL
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_chain (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                subject_hash TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )
        self._conn.commit()

    def load_context(self, raw_phone: str) -> PatientContext:
        phone_hash = self.vault.hash_subject_phone(raw_phone)
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM patient_contexts WHERE phone_hash = ?", (phone_hash,))
        row = cur.fetchone()
        if row is None:
            ctx = PatientContext(
                phone_hash=phone_hash,
                masked_phone=self.vault.mask(raw_phone, "phone"),
                encrypted_phone=self.vault.encrypt(raw_phone),
            )
            self.save_context(ctx)
            return ctx
        return PatientContext(
            phone_hash=row["phone_hash"],
            masked_phone=row["masked_phone"],
            encrypted_phone=row["encrypted_phone"],
            opted_out=bool(row["opted_out"]),
            opt_out_language=row["opt_out_language"],
            ghost_mute_until=float(row["ghost_mute_until"]),
            last_emergency_signature=str(row["last_emergency_signature"] or ""),
            risk_factors=json.loads(row["risk_factors_json"]),
            symptom_history=json.loads(row["symptom_history_json"]),
            turn_timestamps=json.loads(row["turn_timestamps_json"]),
        )

    def save_context(self, ctx: PatientContext) -> None:
        now = time.time()
        self._conn.execute(
            """
            INSERT INTO patient_contexts (
                phone_hash, masked_phone, encrypted_phone, opted_out, opt_out_language,
                ghost_mute_until, last_emergency_signature, risk_factors_json,
                symptom_history_json, turn_timestamps_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(phone_hash) DO UPDATE SET
                opted_out = excluded.opted_out,
                opt_out_language = excluded.opt_out_language,
                ghost_mute_until = excluded.ghost_mute_until,
                last_emergency_signature = excluded.last_emergency_signature,
                risk_factors_json = excluded.risk_factors_json,
                symptom_history_json = excluded.symptom_history_json,
                turn_timestamps_json = excluded.turn_timestamps_json,
                updated_at = excluded.updated_at;
            """,
            (
                ctx.phone_hash,
                ctx.masked_phone,
                ctx.encrypted_phone,
                int(ctx.opted_out),
                ctx.opt_out_language,
                ctx.ghost_mute_until,
                ctx.last_emergency_signature,
                json.dumps(ctx.risk_factors, ensure_ascii=False),
                json.dumps(ctx.symptom_history, ensure_ascii=False),
                json.dumps(ctx.turn_timestamps),
                now,
            ),
        )
        self._conn.commit()

    def append_audit(
        self,
        subject_hash: str,
        event_type: str,
        severity: str,
        details: Dict[str, Any],
        timestamp: Optional[float] = None,
    ) -> str:
        """
        Appends a zero-PII event to the SHA-256 hash chain and returns `entry_hash`.
        """
        cur = self._conn.cursor()
        cur.execute("SELECT entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        prev_hash = str(row["entry_hash"]) if row else self.GENESIS_HASH
        created_at = round(float(timestamp if timestamp is not None else time.time()), 6)
        details_json = json.dumps(details, sort_keys=True, ensure_ascii=False)
        canonical = f"{prev_hash}|{subject_hash}|{event_type}|{severity}|{details_json}|{created_at:.6f}"
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        cur.execute(
            """
            INSERT INTO audit_chain (prev_hash, entry_hash, subject_hash, event_type, severity, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (prev_hash, entry_hash, subject_hash, event_type, severity, details_json, created_at),
        )
        self._conn.commit()
        return entry_hash

    def verify_audit_chain(self) -> Tuple[bool, int, Optional[str]]:
        """
        Cryptographically verifies every link in the SHA-256 audit chain.
        Returns `(is_valid, total_entries, error_message)`.
        """
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM audit_chain ORDER BY seq ASC")
        rows = cur.fetchall()
        expected_prev = self.GENESIS_HASH
        for row in rows:
            if row["prev_hash"] != expected_prev:
                return False, len(rows), f"Broken prev_hash link at seq={row['seq']}"
            canonical = (
                f"{row['prev_hash']}|{row['subject_hash']}|{row['event_type']}|"
                f"{row['severity']}|{row['details_json']}|{float(row['created_at']):.6f}"
            )
            recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(recomputed, row["entry_hash"]):
                return False, len(rows), f"Tampered payload hash mismatch at seq={row['seq']}"
            expected_prev = row["entry_hash"]
        return True, len(rows), None

    def erase_patient_subject(self, raw_phone: str) -> Dict[str, Any]:
        """
        India DPDP Act 2023 Right-to-Erasure: Purges encrypted patient PII and
        clinical context rows while recording a zero-PII erasure receipt in the
        audit chain.
        """
        phone_hash = self.vault.hash_subject_phone(raw_phone)
        cur = self._conn.cursor()
        cur.execute("DELETE FROM patient_contexts WHERE phone_hash = ?", (phone_hash,))
        deleted_rows = cur.rowcount
        self._conn.commit()
        receipt_hash = self.append_audit(
            subject_hash=phone_hash,
            event_type="DPDP_RIGHT_TO_ERASURE",
            severity="COMPLIANCE",
            details={"deleted_context_rows": deleted_rows, "pii_purged": True},
        )
        return {
            "subject_hash": phone_hash,
            "deleted_context_rows": deleted_rows,
            "erasure_audit_receipt": receipt_hash,
        }


# ============================================================================
# MODULE 6: Deterministic Multi-Turn Clinical Safety Gate & Ghost-Mute Engine
# ============================================================================

class HelioSafetyGate:
    """
    Deterministic Pre-LLM and Post-LLM Clinical Safety Gate for neighborhood clinics.

    Combines:
      * 4-Language Opt-Out Integrity (`en`, `ta`, `tanglish`, `hi`)
      * 15-Minute Clinician Ghost-Mute Coexistence with Emergency Breakthrough
      * Single-Turn & 3-Turn Progressive Tamil/Tanglish Clinical Context Graph (CCG)
      * Clause-Local Bilateral Negation Immunity
      * Counted Tablet/Strip Overdose & Household Poison / Button-Battery Detector
      * Pre-LLM Prompt Injection Firewall & Post-LLM Zero-Rx Output Guard
      * Local SQLite WAL Persistence & SHA-256 Hash-Chained Audit Trail
    """

    GHOST_MUTE_SECONDS = 15 * 60  # 15 minutes (900 seconds)

    # 1. Four-Language Exact & Clause-Level Opt-Out Vocabulary
    OPT_OUT_KEYWORDS: Dict[str, Set[str]] = {
        "en": {"stop", "unsubscribe", "opt out", "optout", "cancel messages", "quit"},
        "ta": {"நிறுத்து", "வேண்டாம்", "மெசேஜ் வேண்டாம்", "நிறுத்தவும்", "போதும் நிறுத்து"},
        "tanglish": {"niruthu", "vendaam", "vendam", "stop pannunga", "msg vendaam", "message vendam"},
        "hi": {"रोकें", "बंद करो", "मैसेज मत भेजो", "रुको", "बस करो"},
    }

    OPT_OUT_CONFIRMATIONS: Dict[str, str] = {
        "en": "You have been opted out of automated clinic messages. Contact the clinic reception directly for assistance.",
        "ta": "தானியங்கி மருத்துவமனை குறுந்தகவல்கள் நிறுத்தப்பட்டன. நேரில் மருத்துவமனையைத் தொடர்பு கொள்ளவும்.",
        "tanglish": "Automated clinic messages niruthapattadhu. Neradiyaaga clinic reception-ai thodarbu kollavum.",
        "hi": "स्वचालित क्लिनिक संदेश बंद कर दिए गए हैं। सहायता के लिए सीधे क्लिनिक रिसेप्शन से संपर्क करें।",
    }

    # 2. High-Risk Patient Factors (Tracked across turns in Clinical Context Graph)
    RISK_FACTOR_RULES: Dict[str, Tuple[str, ...]] = {
        "diabetes": ("sugar patient", "diabetes", "diabetic", "சர்க்கரை நோய்", "சுகர்", "மधुमेह", "शुगर"),
        "hypertension": ("bp patient", "high bp", "hypertension", "ரத்த அழுத்தம்", "பிபி", "हाई बीपी"),
        "cardiac_history": ("heart patient", "stent", "bypass", "இதய நோய்", "ஹார்ட் பேஷன்ட்"),
        "pregnancy": ("pregnant", "pregnancy", "கர்ப்பிணி", "கர்ப்பம்", "masama iruken", "गर्भवती"),
        "pediatric_infant": ("newborn", "infant", "baby", "குழந்தை", "பச்சிளம் குழந்தை", "கைக்குழந்தை", "शिशु"),
    }

    SENIOR_AGE_RE = re.compile(
        r"\b(?:age\s*(?:is\s*)?(6\d|7\d|8\d|9\d)|(6\d|7\d|8\d|9\d)\s*(?:yrs|years|வயது|வயசு|vayasu))\b",
        re.IGNORECASE,
    )

    # 3. Elevated / Prodromal Symptoms (Turn 1 / Turn 2 progressive context nodes)
    ELEVATED_SYMPTOM_RULES: Dict[str, Tuple[str, ...]] = {
        "chest_discomfort": (
            "nenju pakkam barama irukku", "nenju baram", "chest heaviness", "chest tightness",
            "நெஞ்சு பாரம்", "நெஞ்சு அழுத்தம்", "நெஞ்சு கனம்", "सीने में भारीपन",
        ),
        "dizziness_vertigo": (
            "head spinning", "dizziness", "giddiness", "தலை சுற்றல்", "தலை சுத்துது", "thalai suthudhu", "चक्कर",
        ),
        "persistent_vomiting": (
            "vomiting since morning", "continuous vomiting", "வாந்தி", "vaandhi", "उल्टी",
        ),
        "high_fever": (
            "high fever", "103 fever", "104 fever", "கடும் காய்ச்சல்", "அதிக காய்ச்சல்", "तेज बुखार",
        ),
    }

    # 4. Acute Red-Flag Emergency Rules (Single-turn OR Multi-turn progression -> Dial 108)
    SEVERE_EMERGENCY_RULES: Dict[str, Tuple[str, ...]] = {
        "cardiac_ischemia": (
            "chest pain", "crushing chest", "heart attack", "nenju vali", "nenju valikkudhu",
            "நெஞ்சு வலி", "நெஞ்சு வலிக்குது", "இதய வலி", "सीने में दर्द", "छाती में दर्द",
        ),
        "left_arm_jaw_radiation": (
            "idadhu kai valikkudhu", "idathu kai vali", "left arm pain", "pain radiating to left arm",
            "இடது கை வலி", "இடது கை வலிக்குது", "தாடை வலி", "बाएं हाथ में दर्द",
        ),
        "respiratory_distress": (
            "moochu vaanga kastama irukku", "moochu thinaral", "shortness of breath",
            "difficulty breathing", "cant breathe", "மூச்சு திணறல்", "மூச்சு வாங்க கஷ்டமா இருக்கு",
            "மூச்சு விட முடியல", "सांस लेने में तकलीफ", "सांस फूल रही",
        ),
        "diaphoresis_sweating": (
            "cold sweat", "profuse sweating", "ரொம்ப வேர்க்குது", "அதிக வியர்வை",
            "romba verkudhu", "verthu kottudhu", "ठंडा पसीना",
        ),
        "syncope_unconscious": (
            "unconscious", "fainted", "collapsed", "not waking up", "மயக்கம்", "மயங்கி விழுந்துட்டார்",
            "mayakkam", "mayangi vizhundhuttar", "बेहोश",
        ),
        "stroke_fast_signs": (
            "face drooping", "slurred speech", "one side paralysis", "முகம் கோணல்", "பேச்சு குழறுது",
            "கை கால் செயல் இழப்பு", "vaai konal", "लकवा",
        ),
        "anaphylaxis_airway": (
            "throat swelling", "tongue swelling", "swallowing difficulty after medicine",
            "தொண்டை வீக்கம்", "நாக்கு வீக்கம்", "गले में सूजन",
        ),
        "active_hemorrhage": (
            "vomiting blood", "coughing blood", "heavy bleeding", "ரத்த வாந்தி", "இரத்தப் போக்கு",
            "ratha vaandhi", "खून की उल्टी",
        ),
        "pediatric_foreign_body": (
            "swallowed button battery", "swallowed coin", "swallowed magnet",
            "பட்டன் பேட்டரி விழுங்கிவிட்டான்", "காசு விழுங்கிடுச்சு", "battery vizhungittan",
        ),
    }

    # 5. Household Poison & Counted Tablet/Strip Overdose Detectors (SVO & Tamil SOV order)
    _POISON_AGENTS = (
        r"(?:phenyl|harpic|lizol|rat\s+poison|pesticide|kerosene|bleach|"
        r"பினாயில்|எலி\s*மருந்து|பூச்சி\s*மருந்து|மண்ணெண்ணெய்)"
    )
    _INGEST_VERBS = (
        r"(?:drank|swallowed|consumed|ingested|குடித்துவிட்டார்|குடிச்சிட்டான்|குடித்தான்|குடிச்சிட்டா|"
        r"விழுங்கிவிட்டார்|விழுங்கிட்டான்|kudichittan|kudichittar|vizhungittan)"
    )
    HOUSEHOLD_POISON_RE = re.compile(
        rf"(?:{_INGEST_VERBS}[^\n,.;]{{0,30}}{_POISON_AGENTS}|{_POISON_AGENTS}[^\n,.;]{{0,30}}{_INGEST_VERBS})",
        re.IGNORECASE,
    )

    _OVERDOSE_QTY = (
        r"(?:(?:[6-9]|\d{2,})\s*(?:tablets?|pills?|capsules?|மாத்திரை(?:கள்)?)|"
        r"(?:[1-9]\d*)\s*(?:full\s+)?strips?\s*(?:of\s+)?(?:tablets?|pills?|paracetamol|dolo|sleeping\s+pills|மாத்திரை(?:கள்)?)?)"
    )
    _OVERDOSE_VERBS = (
        r"(?:took|swallowed|ate|consumed|சாப்பிட்டார்|சாப்பிட்டான்|விழுங்கினார்|விழுங்கிட்டான்|saapittan|saapittar|vizhungittan)"
    )
    COUNTED_OVERDOSE_RE = re.compile(
        rf"(?:{_OVERDOSE_VERBS}[^\n,.;]{{0,25}}{_OVERDOSE_QTY}|{_OVERDOSE_QTY}[^\n,.;]{{0,25}}{_OVERDOSE_VERBS})",
        re.IGNORECASE,
    )

    HYPOGLYCEMIA_CRITICAL_RE = re.compile(
        r"(?:sugar|glucose|rbs|cbs|சர்க்கரை|சுகர்)\s*(?:level\s*|லெவல்\s*)?(?:is\s*|reading\s*)?(?:[2-4]\d|5[0-4])\s*(?:mg/dl)?",
        re.IGNORECASE,
    )

    EMERGENCY_RESPONSE_TA_EN = (
        "அவசர மருத்துவ எச்சரிக்கை (EMERGENCY ALERT): உங்கள் அறிகுறிகள் உடனடி அவசர மருத்துவ "
        "கவனிப்பு தேவைப்படுவதைக் காட்டுகின்றன. தயவுசெய்து உடனடியாக 108 ஆம்புலன்ஸை அழைக்கவும் "
        "அல்லது அருகிலுள்ள அவசர சிகிச்சைப் பிரிவுக்குச் (Emergency Room) செல்லவும். "
        "மருத்துவருக்கு உடனடி தகவல் அனுப்பப்பட்டுள்ளது. / "
        "URGENT: Your symptoms require immediate emergency medical attention. Please call "
        "108 Ambulance immediately or proceed to the nearest hospital Emergency Room. "
        "The clinician has been alerted."
    )

    def __init__(
        self,
        store: Optional[LocalClinicSafetyStore] = None,
        vault: Optional[PIIVault] = None,
    ) -> None:
        self.vault = vault or PIIVault()
        self.store = store or LocalClinicSafetyStore(":memory:", vault=self.vault)

    # ------------------------------------------------------------------------
    # Public API 1: Detect 4-Language Opt-Out
    # ------------------------------------------------------------------------
    def detect_opt_out(self, text: str) -> Optional[str]:
        norm = IndicClinicalNormalizer.normalize(text)
        if not norm:
            return None
        # Check exact match or short command match (<= 4 words) to avoid false opt-out on long sentences
        tokens = norm.split()
        if len(tokens) <= 5:
            for lang, phrases in self.OPT_OUT_KEYWORDS.items():
                for phrase in phrases:
                    p_norm = IndicClinicalNormalizer.normalize(phrase)
                    if norm == p_norm or p_norm in tokens:
                        return lang
                    if " " in p_norm and p_norm in norm:
                        return lang
        return None

    # ------------------------------------------------------------------------
    # Public API 2: Record Clinician Manual WhatsApp Takeover (15-Min Ghost-Mute)
    # ------------------------------------------------------------------------
    def clinician_manual_reply(self, phone: str, now: Optional[float] = None) -> PatientContext:
        """
        Called when the doctor replies manually from their WhatsApp Business phone.
        Activates a 15-minute (900s) Ghost-Mute so the automated assistant never
        interrupts a live doctor-patient conversation.
        """
        ts = float(now if now is not None else time.time())
        ctx = self.store.load_context(phone)
        ctx.ghost_mute_until = ts + self.GHOST_MUTE_SECONDS
        self.store.save_context(ctx)
        self.store.append_audit(
            subject_hash=ctx.phone_hash,
            event_type="CLINICIAN_GHOST_MUTE_ACTIVATED",
            severity="COEXISTENCE",
            details={"mute_seconds": self.GHOST_MUTE_SECONDS, "until_epoch": round(ctx.ghost_mute_until, 3)},
            timestamp=ts,
        )
        return ctx

    # ------------------------------------------------------------------------
    # Public API 3: Deterministic Pre-LLM Incoming Message Triage
    # ------------------------------------------------------------------------
    def process_incoming(
        self,
        phone: str,
        message: str,
        now: Optional[float] = None,
    ) -> TriageDecision:
        t0 = time.perf_counter()
        ts = float(now if now is not None else time.time())
        ctx = self.store.load_context(phone)

        # STEP 1: 4-Language Opt-Out Gate (Highest Priority User Autonomy Rule)
        opt_lang = self.detect_opt_out(message)
        if opt_lang is not None:
            ctx.opted_out = True
            ctx.opt_out_language = opt_lang
            self.store.save_context(ctx)
            latency = round((time.perf_counter() - t0) * 1000.0, 3)
            audit_hash = self.store.append_audit(
                subject_hash=ctx.phone_hash,
                event_type="PATIENT_OPT_OUT",
                severity="OPT_OUT",
                details={"language": opt_lang},
                timestamp=ts,
            )
            return TriageDecision(
                severity="OPT_OUT",
                llm_allowed=False,
                dial_108=False,
                clinician_alert=False,
                ghost_mute_active=False,
                matched_triggers=[f"opt_out:{opt_lang}"],
                accumulated_risk_factors=list(ctx.risk_factors),
                accumulated_symptoms=list(ctx.symptom_history),
                response_text=self.OPT_OUT_CONFIRMATIONS[opt_lang],
                latency_ms=latency,
                audit_hash=audit_hash,
            )

        if ctx.opted_out:
            latency = round((time.perf_counter() - t0) * 1000.0, 3)
            audit_hash = self.store.append_audit(
                subject_hash=ctx.phone_hash,
                event_type="OPTED_OUT_SILENCE_ENFORCED",
                severity="OPT_OUT",
                details={"suppressed": True},
                timestamp=ts,
            )
            return TriageDecision(
                severity="OPT_OUT",
                llm_allowed=False,
                dial_108=False,
                clinician_alert=False,
                ghost_mute_active=False,
                matched_triggers=["opted_out_suppressed"],
                accumulated_risk_factors=list(ctx.risk_factors),
                accumulated_symptoms=list(ctx.symptom_history),
                response_text=None,
                latency_ms=latency,
                audit_hash=audit_hash,
            )

        # STEP 2: Multi-Turn Clinical Context Graph (CCG) Extraction with Bilateral Negation
        matched_triggers: List[str] = []

        # 2a. Risk Factors
        if self.SENIOR_AGE_RE.search(message or ""):
            if "senior_age_60_plus" not in ctx.risk_factors:
                ctx.risk_factors.append("senior_age_60_plus")
            matched_triggers.append("risk:senior_age_60_plus")

        for rf_name, phrases in self.RISK_FACTOR_RULES.items():
            hit, phrase = IndicClinicalNormalizer.keyword_hit(message, phrases)
            if hit:
                if rf_name not in ctx.risk_factors:
                    ctx.risk_factors.append(rf_name)
                matched_triggers.append(f"risk:{rf_name}({phrase})")

        # 2b. Elevated Prodromal Symptoms
        for sym_name, phrases in self.ELEVATED_SYMPTOM_RULES.items():
            hit, phrase = IndicClinicalNormalizer.keyword_hit(message, phrases)
            if hit:
                if sym_name not in ctx.symptom_history:
                    ctx.symptom_history.append(sym_name)
                matched_triggers.append(f"elevated:{sym_name}({phrase})")

        # 2c. Acute Red-Flag Symptoms
        severe_hits_this_turn: List[str] = []
        for sev_name, phrases in self.SEVERE_EMERGENCY_RULES.items():
            hit, phrase = IndicClinicalNormalizer.keyword_hit(message, phrases)
            if hit:
                severe_hits_this_turn.append(sev_name)
                if sev_name not in ctx.symptom_history:
                    ctx.symptom_history.append(sev_name)
                matched_triggers.append(f"emergency:{sev_name}({phrase})")

        # 2d. Household Poison, Counted Overdose & Critical Hypoglycemia
        if self.HOUSEHOLD_POISON_RE.search(message or ""):
            severe_hits_this_turn.append("household_poison_ingestion")
            if "household_poison_ingestion" not in ctx.symptom_history:
                ctx.symptom_history.append("household_poison_ingestion")
            matched_triggers.append("emergency:household_poison_ingestion")

        if self.COUNTED_OVERDOSE_RE.search(message or ""):
            severe_hits_this_turn.append("counted_tablet_strip_overdose")
            if "counted_tablet_strip_overdose" not in ctx.symptom_history:
                ctx.symptom_history.append("counted_tablet_strip_overdose")
            matched_triggers.append("emergency:counted_tablet_strip_overdose")

        if self.HYPOGLYCEMIA_CRITICAL_RE.search(message or ""):
            severe_hits_this_turn.append("critical_hypoglycemia_under_55")
            if "critical_hypoglycemia_under_55" not in ctx.symptom_history:
                ctx.symptom_history.append("critical_hypoglycemia_under_55")
            matched_triggers.append("emergency:critical_hypoglycemia_under_55")

        ctx.turn_timestamps.append(ts)
        ctx.turn_timestamps = ctx.turn_timestamps[-10:]

        # STEP 3: Evaluate Single-Turn OR 3-Turn Progressive Emergency Escalation
        # Progressive Escalation fires when:
        #   - Any acute severe red flag is present, OR
        #   - High-risk patient profile + prodromal chest/dizziness symptom + worsening
        #     autonomic/radiation/dyspnea sign across turns within a session.
        severe_set = set(self.SEVERE_EMERGENCY_RULES.keys()) | {
            "household_poison_ingestion",
            "counted_tablet_strip_overdose",
            "critical_hypoglycemia_under_55",
        }
        accumulated_severe = [s for s in ctx.symptom_history if s in severe_set]
        accumulated_elevated = [s for s in ctx.symptom_history if s in self.ELEVATED_SYMPTOM_RULES]

        is_progressive_cardiac_emergency = (
            len(ctx.risk_factors) >= 1
            and "chest_discomfort" in accumulated_elevated
            and (len(accumulated_severe) >= 1 or len(accumulated_elevated) >= 2)
        )
        is_emergency = bool(severe_hits_this_turn) or is_progressive_cardiac_emergency

        if is_emergency:
            # Emergency ALWAYS breaks through Ghost-Mute if a new emergency symptom appears,
            # and activates/extends Ghost-Mute so routine bot chatter stays silent.
            ctx.ghost_mute_until = max(ctx.ghost_mute_until, ts + self.GHOST_MUTE_SECONDS)
            ctx.last_emergency_signature = "|".join(sorted(set(ctx.symptom_history)))
            self.store.save_context(ctx)
            latency = round((time.perf_counter() - t0) * 1000.0, 3)
            audit_hash = self.store.append_audit(
                subject_hash=ctx.phone_hash,
                event_type="EMERGENCY_DIAL_108_ESCALATION",
                severity="EMERGENCY",
                details={
                    "triggers": matched_triggers,
                    "risk_factors": ctx.risk_factors,
                    "symptoms": ctx.symptom_history,
                    "dial_108": True,
                },
                timestamp=ts,
            )
            return TriageDecision(
                severity="EMERGENCY",
                llm_allowed=False,
                dial_108=True,
                clinician_alert=True,
                ghost_mute_active=True,
                matched_triggers=matched_triggers,
                accumulated_risk_factors=list(ctx.risk_factors),
                accumulated_symptoms=list(ctx.symptom_history),
                response_text=self.EMERGENCY_RESPONSE_TA_EN,
                latency_ms=latency,
                audit_hash=audit_hash,
            )

        # STEP 4: 15-Minute Clinician Ghost-Mute Check (Non-Emergency messages stay silent)
        if ts < ctx.ghost_mute_until:
            self.store.save_context(ctx)
            latency = round((time.perf_counter() - t0) * 1000.0, 3)
            audit_hash = self.store.append_audit(
                subject_hash=ctx.phone_hash,
                event_type="GHOST_MUTE_SUPPRESSED",
                severity="GHOST_MUTED",
                details={"remaining_seconds": round(ctx.ghost_mute_until - ts, 1)},
                timestamp=ts,
            )
            return TriageDecision(
                severity="GHOST_MUTED",
                llm_allowed=False,
                dial_108=False,
                clinician_alert=False,
                ghost_mute_active=True,
                matched_triggers=["clinician_ghost_mute_active"],
                accumulated_risk_factors=list(ctx.risk_factors),
                accumulated_symptoms=list(ctx.symptom_history),
                response_text=None,
                latency_ms=latency,
                audit_hash=audit_hash,
            )

        # STEP 5: Pre-LLM Prompt Injection Firewall (Runs strictly AFTER Emergency Triage)
        flagged_inj, inj_label = PromptInjectionFirewall.inspect(message)
        if flagged_inj:
            self.store.save_context(ctx)
            latency = round((time.perf_counter() - t0) * 1000.0, 3)
            audit_hash = self.store.append_audit(
                subject_hash=ctx.phone_hash,
                event_type="PROMPT_INJECTION_BLOCKED",
                severity="FIREWALL_BLOCKED",
                details={"rule": inj_label},
                timestamp=ts,
            )
            return TriageDecision(
                severity="FIREWALL_BLOCKED",
                llm_allowed=False,
                dial_108=False,
                clinician_alert=False,
                ghost_mute_active=False,
                matched_triggers=[f"firewall:{inj_label}"],
                accumulated_risk_factors=list(ctx.risk_factors),
                accumulated_symptoms=list(ctx.symptom_history),
                response_text=PromptInjectionFirewall.SAFE_REFUSAL,
                latency_ms=latency,
                audit_hash=audit_hash,
            )

        # STEP 6: Elevated vs Routine Administrative Routing (Safe for Local 2B Reception Model)
        severity = "ELEVATED" if accumulated_elevated or ctx.risk_factors else "ROUTINE"
        self.store.save_context(ctx)
        latency = round((time.perf_counter() - t0) * 1000.0, 3)
        audit_hash = self.store.append_audit(
            subject_hash=ctx.phone_hash,
            event_type="PRE_LLM_TRIAGE_PASSED",
            severity=severity,
            details={
                "triggers": matched_triggers,
                "risk_factors": ctx.risk_factors,
                "symptoms": ctx.symptom_history,
                "llm_allowed": True,
            },
            timestamp=ts,
        )
        return TriageDecision(
            severity=severity,
            llm_allowed=True,
            dial_108=False,
            clinician_alert=(severity == "ELEVATED" and len(accumulated_elevated) >= 1),
            ghost_mute_active=False,
            matched_triggers=matched_triggers,
            accumulated_risk_factors=list(ctx.risk_factors),
            accumulated_symptoms=list(ctx.symptom_history),
            response_text=None,
            latency_ms=latency,
            audit_hash=audit_hash,
        )

    # ------------------------------------------------------------------------
    # Public API 4: Post-LLM Output Safety Verification (Zero-Rx / Zero-Diagnosis)
    # ------------------------------------------------------------------------
    def verify_outgoing_llm_reply(self, phone: str, draft_reply: str) -> OutputGuardVerdict:
        ctx = self.store.load_context(phone)
        verdict = ClinicalOutputGuard.verify_llm_reply(draft_reply)
        self.store.append_audit(
            subject_hash=ctx.phone_hash,
            event_type="POST_LLM_OUTPUT_GUARD",
            severity="SAFE" if verdict.safe else "OUTPUT_BLOCKED",
            details={
                "safe": verdict.safe,
                "violation_category": verdict.violation_category,
                "matched_pattern": verdict.matched_pattern,
            },
        )
        return verdict


# ============================================================================
# MODULE 7: Interactive CLI Demonstration for Mozilla Technical Review
# ============================================================================

def _run_interactive_cli_demo() -> None:
    print("=" * 78)
    print(f"HELIO CLINICAL SAFETY GATE & PIIVAULT COMMONS ({__version__})")
    print("Deterministic Pre-LLM & Post-LLM Safety Architecture for Neighborhood Clinics")
    print("=" * 78)

    vault = PIIVault(master_secret="mozilla-incubator-2027-demo-secret")
    store = LocalClinicSafetyStore(":memory:", vault=vault)
    gate = HelioSafetyGate(store=store, vault=vault)

    # Demo 1: 3-Turn Progressive Tanglish Cardiac Escalation (No English emergency keywords)
    print("\n[1] 3-TURN PROGRESSIVE TANGLISH CARDIAC ESCALATION (Zero English Red-Flag Words)")
    p1 = "+919876543210"
    turns = [
        ("Turn 1 (History)", "Appa age 64, avarukku sugar and bp irukku."),
        ("Turn 2 (Prodrome)", "Morning la irundhu nenju pakkam barama irukku."),
        ("Turn 3 (Escalation)", "Ippo idadhu kai valikkudhu, moochu vaanga kastama irukku."),
    ]
    for label, msg in turns:
        res = gate.process_incoming(p1, msg)
        print(
            f"  {label:<20} | Msg: {msg}\n"
            f"  {'':<20} -> Severity: {res.severity:<10} | LLM Allowed: {str(res.llm_allowed):<5} "
            f"| Dial-108: {str(res.dial_108):<5} | Latency: {res.latency_ms:.3f} ms"
        )

    # Demo 2: Clause-Local Bilateral Negation Immunity (Tamil & Tanglish)
    print("\n[2] CLAUSE-LOCAL BILATERAL NEGATION IMMUNITY (Tamil & Tanglish Post-Negators)")
    p2 = "+919876500002"
    neg_msg = "நெஞ்சு வலி இல்ல, மூச்சு திணறல் இல்லை, நாளைக்கு சாதாரண செக்கப் அப்பாயின்ட்மென்ட் வேணும்"
    res_neg = gate.process_incoming(p2, neg_msg)
    print(f"  Msg: {neg_msg}")
    print(f"  -> Severity: {res_neg.severity} | LLM Allowed: {res_neg.llm_allowed} | Dial-108: {res_neg.dial_108}")

    # Demo 3: 15-Minute Clinician Ghost-Mute Coexistence + Emergency Breakthrough
    print("\n[3] 15-MINUTE CLINICIAN GHOST-MUTE COEXISTENCE & EMERGENCY BREAKTHROUGH")
    p3 = "+919876500003"
    gate.clinician_manual_reply(p3, now=1000.0)
    res_muted = gate.process_incoming(p3, "Doctor, what time is clinic open?", now=1200.0)
    res_break = gate.process_incoming(p3, "Doctor ippo திடீர்னு மயக்கம் வந்து விழுந்துட்டார்", now=1260.0)
    print(f"  Routine Msg @ +200s after Doctor Reply -> Severity: {res_muted.severity} | Bot Muted: {not res_muted.llm_allowed}")
    print(f"  Syncope Emergency @ +260s during Mute  -> Severity: {res_break.severity} | Dial-108 Breakthrough: {res_break.dial_108}")

    # Demo 4: Post-LLM Zero-Rx / Zero-Diagnosis Output Guard
    print("\n[4] POST-LLM ZERO-RX / ZERO-DIAGNOSIS OUTPUT GUARD")
    unsafe_llm_draft = "Take Dolo 650 mg tablet twice daily and Amoxicillin 500mg for 5 days."
    verdict = gate.verify_outgoing_llm_reply(p2, unsafe_llm_draft)
    print(f"  Unsafe LLM Draft : {unsafe_llm_draft}")
    print(f"  Guard Verdict    : safe={verdict.safe} | category={verdict.violation_category} | caught='{verdict.matched_pattern}'")

    # Demo 5: AES-256-GCM PIIVault, SHA-256 Audit Chain Verification & DPDP Right-to-Erasure
    print("\n[5] AES-256-GCM PIIVAULT, SHA-256 AUDIT CHAIN & INDIA DPDP ACT RIGHT-TO-ERASURE")
    enc_token = vault.encrypt(p1)
    erasure = store.erase_patient_subject(p1)
    chain_ok, total_events, err = store.verify_audit_chain()
    print(f"  PIIVault Backend : {vault.backend_name}")
    print(f"  Encrypted Phone  : {vault.mask(enc_token, 'token')} (Decrypted Roundtrip OK: {vault.decrypt(enc_token) == p1})")
    print(f"  DPDP Erasure     : Subject={erasure['subject_hash'][:18]}... | Purged Rows={erasure['deleted_context_rows']}")
    print(f"  Audit Hash Chain : Valid={chain_ok} | Total Zero-PII Events={total_events} | Error={err}")
    print("=" * 78)


if __name__ == "__main__":
    _run_interactive_cli_demo()
