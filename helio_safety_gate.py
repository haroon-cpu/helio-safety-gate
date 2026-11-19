#!/usr/bin/env python3
"""
HELIO Safety Gate (Apache-2.0 Public Safety Commons)
Deterministic Tamil / Tanglish 3-Turn Progressive Emergency Escalation,
15-Minute Clinician Ghost-Mute Coexistence Protocol, and 4-Language Opt-Out Gate.

DISCLAIMER:
- NOT a diagnostic tool or medical device.
- NOT a substitute for professional medical advice.
- Designed strictly for clinic intake coordination and deterministic red-flag escalation
  to Tamil Nadu Dial-108 emergency services and human clinicians.
"""

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


HIGH_RISK_PATIENT_RE = re.compile(
    r"\b(6\d|7\d|8\d|9\d)\s*(vayasu|yrs|years|age)?|\b(sugar|diabetes|bp|hypertension|heart\s*patient|pregnant|asthma)\b",
    re.IGNORECASE,
)

ELEVATED_SYMPTOM_RE = re.compile(
    r"(nenju\s*(pakkam|vali|barama|irukkam)|chest\s*(pain|tight|heavy|pressure)|thalai\s*suth|dizzy|faint|high\s*fever)",
    re.IGNORECASE,
)

SEVERE_SYMPTOM_RE = re.compile(
    r"(idadhu\s*kai\s*vali|left\s*arm\s*pain|moochu\s*(vaanga|thinaral|kastam)|breath|sweat|வேர்க்குது|unconscious|mayakkam|seizure|bleeding\s*heavy)",
    re.IGNORECASE,
)

OPT_OUT_RE = re.compile(r"^\s*(stop|unsubscribe|opt\s*out|vendaam|vendam|நிப்பாட்டு|बंद)\s*$", re.IGNORECASE)

OPT_OUT_MESSAGES = {
    "en": "You have been removed from automated follow-up messages. Message anytime or call the clinic directly if you need help.",
    "ta": "தானியங்கி தொடர் செய்திகளில் இருந்து உங்களை நீக்கிவிட்டோம். எப்போது வேண்டுமானாலும் கிளினிக்கைத் தொடர்பு கொள்ளலாம்.",
    "tanglish": "Ungalai follow-up messages-la irundhu remove pannitom. Eppo venalum help-ku message pannunga.",
    "hi": "Aapko automated follow-up messages se hata diya gaya hai. Madad ke liye kabhi bhi clinic se sampark karein.",
}


@dataclass
class PatientSession:
    session_id: str
    language: str = "tanglish"
    has_high_risk_history: bool = False
    has_elevated_symptom: bool = False
    opted_out: bool = False
    ghost_mute_until: float = 0.0
    history: List[str] = field(default_factory=list)


class HelioSafetyGate:
    """Zero-LLM deterministic clinical safety and coexistence layer."""

    GHOST_MUTE_SECONDS = 15 * 60  # 15-minute clinician priority override

    def __init__(self) -> None:
        self.sessions: Dict[str, PatientSession] = {}

    def get_session(self, session_id: str, language: str = "tanglish") -> PatientSession:
        if session_id not in self.sessions:
            self.sessions[session_id] = PatientSession(session_id=session_id, language=language)
        return self.sessions[session_id]

    def clinician_manual_reply(self, session_id: str, now: Optional[float] = None) -> Dict[str, object]:
        """Activates 15-minute Ghost-Mute Coexistence Protocol when a human doctor replies."""
        ts = now if now is not None else time.time()
        session = self.get_session(session_id)
        session.ghost_mute_until = ts + self.GHOST_MUTE_SECONDS
        return {
            "status": "GHOST_MUTE_ACTIVE",
            "muted_for_seconds": self.GHOST_MUTE_SECONDS,
            "human_clinician_in_control": True,
        }

    def evaluate_message(self, session_id: str, message: str, language: str = "tanglish", now: Optional[float] = None) -> Dict[str, object]:
        ts = now if now is not None else time.time()
        session = self.get_session(session_id, language=language)
        session.history.append(message)

        # 1. Opt-out integrity check (4 languages)
        if OPT_OUT_RE.match(message):
            session.opted_out = True
            return {
                "outcome": "opted_out",
                "acuity_level": "NONE",
                "llm_called": False,
                "reply": OPT_OUT_MESSAGES.get(language, OPT_OUT_MESSAGES["en"]),
            }

        if session.opted_out:
            return {
                "outcome": "opted_out_silent",
                "acuity_level": "NONE",
                "llm_called": False,
                "reply": "",
            }

        # 2. Progressive Clinical Context Graph (3-Turn Non-Keyword Escalation)
        if HIGH_RISK_PATIENT_RE.search(message):
            session.has_high_risk_history = True
        if ELEVATED_SYMPTOM_RE.search(message):
            session.has_elevated_symptom = True
        severe_now = bool(SEVERE_SYMPTOM_RE.search(message))

        # Emergency triggers IMMEDIATELY even if Ghost-Mute is active (never delay emergencies!)
        if severe_now and (session.has_high_risk_history or session.has_elevated_symptom):
            session.ghost_mute_until = ts + self.GHOST_MUTE_SECONDS
            return {
                "outcome": "emergency-escalation",
                "acuity_level": "EMERGENCY",
                "llm_called": False,
                "dial_108_recommended": True,
                "clinician_alert": "HELIO_CCG_EMERGENCY",
                "ghost_mute_activated": True,
                "reply": (
                    "URGENT SAFETY ALERT: Your symptoms may need immediate medical care. "
                    "Please call 108 (Tamil Nadu Emergency Ambulance) or go to the nearest hospital right away. "
                    "I have alerted the clinic doctor immediately and paused automated replies."
                ),
            }

        # 3. Respect 15-minute clinician coexistence mute for non-emergency messages
        if ts < session.ghost_mute_until:
            return {
                "outcome": "clinician-coexistence-muted",
                "acuity_level": "LOW",
                "llm_called": False,
                "reply": "",
            }

        if session.has_elevated_symptom:
            return {
                "outcome": "urgent-clinician-review",
                "acuity_level": "ELEVATED",
                "llm_called": False,
                "clinician_alert": "HELIO_ELEVATED_REVIEW",
                "reply": "Thank you for sharing these symptoms. I have flagged this for the doctor to review promptly. If symptoms worsen, please call 108 immediately.",
            }

        return {
            "outcome": "administrative",
            "acuity_level": "LOW",
            "llm_called": False,
            "reply": "Thank you. I can help coordinate your clinic appointment time with the doctor.",
        }


if __name__ == "__main__":
    gate = HelioSafetyGate()
    demo_turns = [
        "Enakku 62 vayasu, sugar bp irukku",
        "Nethu irundhu nenju pakkam oru mathiri barama irukku",
        "Ippo idadhu kai valikkudhu, romba வேர்க்குது, moochu vaanga kastama irukku",
    ]
    print("=== HELIO Local Safety Gate (Zero-LLM Demo) ===")
    for idx, msg in enumerate(demo_turns, 1):
        res = gate.evaluate_message("demo_patient_01", msg)
        print(f"Turn {idx}: {msg}")
        print(f"  -> Acuity: {res['acuity_level']} | Outcome: {res['outcome']} | LLM Called: {res['llm_called']}")
        if res.get("dial_108_recommended"):
            print("  -> ACTION: Dial-108 Escalation + Clinician Alert + 15-Min Ghost Mute ACTIVATED!")
