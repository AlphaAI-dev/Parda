import sys
import os

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(TEST_DIR)
for p in [PROJECT_DIR, os.path.dirname(PROJECT_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

import unittest
from parda_core.checksums import validate_luhn, generate_luhn, validate_verhoeff, generate_verhoeff
from parda_core.detectors import PardaDetector
from parda_core.masker import PardaMasker
from parda_core.vault import PardaSession


class TestParda(unittest.TestCase):
    def setUp(self):
        self.detector = PardaDetector()
        self.masker = PardaMasker(self.detector)

    def test_luhn_credit_card(self):
        valid_card = generate_luhn("453201501234567")
        self.assertTrue(validate_luhn(valid_card))
        corrupted = valid_card[:-1] + ("0" if valid_card[-1] != "0" else "1")
        self.assertFalse(validate_luhn(corrupted))

    def test_verhoeff_aadhaar(self):
        valid = generate_verhoeff("54328901234")
        self.assertTrue(validate_verhoeff(valid))
        corrupted = valid[:-1] + ("0" if valid[-1] != "0" else "1")
        self.assertFalse(validate_verhoeff(corrupted))

    def test_global_entities_detection(self):
        text = "Contact alice@cyberdyne.io with AWS key AKIAIOSFODNN7EXAMPLE and IP 192.168.1.1."
        matches = self.detector.detect_all(text, scope="GLOBAL")
        types = {m.entity_type for m in matches}
        self.assertIn("EMAIL_ADDRESS", types)
        self.assertIn("API_SECRET_KEY", types)
        self.assertIn("IP_ADDRESS", types)

    def test_regional_entities_detection(self):
        text = "User Rahul with PAN ABCPS1234F, UPI rahul@okaxis, and IFSC SBIN0001234."
        matches = self.detector.detect_all(text, scope="REGIONAL")
        types = {m.entity_type for m in matches}
        self.assertIn("PAN_CARD", types)
        self.assertIn("UPI_ID", types)
        self.assertIn("BANK_IFSC", types)

    def test_two_way_vault_session(self):
        session = PardaSession(strategy="TOKEN")
        valid_card = generate_luhn("453201501234567")
        original = f"Please process refund for Visa {valid_card} and PAN ABCPS1234F."
        sanitized = session.sanitize(original)
        safe_prompt = sanitized["sanitized_text"]

        # Ensure cloud never sees real card or PAN
        self.assertNotIn(valid_card, safe_prompt)
        self.assertNotIn("ABCPS1234F", safe_prompt)

        # Mock LLM response
        mock_reply = "Refund scheduled for card <CREDIT_CARD_1> registered to PAN <PAN_CARD_1>."
        restored = session.de_anonymize(mock_reply)

        self.assertIn(valid_card, restored)
        self.assertIn("ABCPS1234F", restored)
        self.assertNotIn("<CREDIT_CARD_1>", restored)


if __name__ == "__main__":
    unittest.main()
