#!/usr/bin/env python3
"""Automated verification tests for HELIO Safety Gate (Apache-2.0)."""

import unittest
from helio_safety_gate import HelioSafetyGate


class TestHelioSafetyGate(unittest.TestCase):
    def setUp(self):
        self.gate = HelioSafetyGate()

    def test_01_three_turn_tanglish_emergency_escalation(self):
        r1 = self.gate.evaluate_message("p1", "Enakku 62 vayasu, sugar bp irukku", now=1000.0)
        self.assertEqual(r1["acuity_level"], "LOW")
        self.assertFalse(r1["llm_called"])

        r2 = self.gate.evaluate_message("p1", "Nethu irundhu nenju pakkam oru mathiri barama irukku", now=1010.0)
        self.assertEqual(r2["acuity_level"], "ELEVATED")
        self.assertEqual(r2["outcome"], "urgent-clinician-review")

        r3 = self.gate.evaluate_message("p1", "Ippo idadhu kai valikkudhu, romba வேர்க்குது, moochu vaanga kastama irukku", now=1020.0)
        self.assertEqual(r3["acuity_level"], "EMERGENCY")
        self.assertEqual(r3["outcome"], "emergency-escalation")
        self.assertTrue(r3["dial_108_recommended"])
        self.assertTrue(r3["ghost_mute_activated"])
        self.assertFalse(r3["llm_called"])

    def test_02_clinician_15_minute_ghost_mute_coexistence(self):
        self.gate.clinician_manual_reply("p2", now=2000.0)
        # Routine message 5 minutes later stays muted so doctor keeps control
        r_muted = self.gate.evaluate_message("p2", "Doctor evening 6pm slot irukka?", now=2300.0)
        self.assertEqual(r_muted["outcome"], "clinician-coexistence-muted")
        self.assertEqual(r_muted["reply"], "")

        # Routine message after 15 minutes resumes normal coordination
        r_resumed = self.gate.evaluate_message("p2", "Doctor evening 6pm slot irukka?", now=2950.0)
        self.assertEqual(r_resumed["outcome"], "administrative")

    def test_03_four_language_opt_out_respect(self):
        for lang in ("en", "ta", "tanglish", "hi"):
            res = self.gate.evaluate_message(f"opt_{lang}", "STOP", language=lang)
            self.assertEqual(res["outcome"], "opted_out")
            self.assertTrue(len(res["reply"]) > 10)
            follow = self.gate.evaluate_message(f"opt_{lang}", "Hello", language=lang)
            self.assertEqual(follow["outcome"], "opted_out_silent")


if __name__ == "__main__":
    unittest.main(verbosity=2)
