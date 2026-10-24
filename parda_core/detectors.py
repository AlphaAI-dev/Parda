"""
Parda Intelligent Detection Engine.
Detects both Global (Credit Cards, API Keys, Emails, SSN, IBAN, IP) and
Regional (Aadhaar, PAN, UPI, IFSC, Bank Accounts) privacy identifiers.
"""

import re
from typing import List, Dict, Any
from .checksums import validate_luhn, validate_verhoeff


class EntityMatch:
    def __init__(
        self,
        entity_type: str,
        value: str,
        start: int,
        end: int,
        confidence: float,
        scope: str = "GLOBAL",
        metadata: Dict[str, Any] = None,
    ):
        self.entity_type = entity_type
        self.value = value
        self.start = start
        self.end = end
        self.confidence = confidence
        self.scope = scope  # "GLOBAL" or "REGIONAL"
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "scope": self.scope,
            "metadata": self.metadata,
        }


class PardaDetector:
    def __init__(self):
        # --- GLOBAL PATTERNS ---
        self.email_regex = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
        )
        self.ip_regex = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        )
        # Credit Card candidates (13-19 digits with spaces/hyphens)
        self.credit_card_regex = re.compile(
            r"\b(?:\d[ -]*?){13,19}\b"
        )
        self.api_key_regex = re.compile(
            r"\b(?:AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|sk-[a-zA-Z0-9]{32,64}|eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+)\b"
        )
        self.us_ssn_regex = re.compile(
            r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"
        )
        self.iban_regex = re.compile(
            r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b"
        )
        self.global_phone_regex = re.compile(
            r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        )

        # --- REGIONAL (INDIAN) PATTERNS ---
        self.pan_regex = re.compile(r"\b([A-Z]{5}[0-9]{4}[A-Z])\b", re.IGNORECASE)
        self.aadhaar_regex = re.compile(r"\b([2-9][0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})\b")
        self.upi_regex = re.compile(
            r"\b([a-zA-Z0-9._\-]{2,50}@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|ibl|upi|axl|apl|barodampay|federal|kotak|gpay|[a-zA-Z]{2,15}))\b",
            re.IGNORECASE,
        )
        self.ifsc_regex = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b", re.IGNORECASE)
        self.bank_acc_regex = re.compile(
            r"(?:(?:a/c|account(?:\s*no)?|acc(?:\s*num|\s*no)?|खाता(?:\s*संख्या)?)\s*[:#\-]?\s*)([0-9]{9,18})\b",
            re.IGNORECASE,
        )
        self.indian_phone_regex = re.compile(
            r"(?:(?:\+91|91|0)[\s\-]?)?(\b[6-9][0-9]{9}\b)"
        )
        self.name_context_regex = re.compile(
            r"(?:(?:name(?:\s*is)?|s/o|d/o|w/o|shri|smt|mr\.|mrs\.|dr\.|श्री|श्रीमती)\s*[:\-]?\s*)([A-Za-z\u0900-\u097F]+(?:\s+[A-Za-z\u0900-\u097F]+){1,3})",
            re.IGNORECASE,
        )

    def detect_all(self, text: str, scope: str = "ALL") -> List[EntityMatch]:
        """
        Detects entities based on scope: 'ALL', 'GLOBAL', or 'REGIONAL'.
        """
        matches: List[EntityMatch] = []

        # --- GLOBAL DETECTIONS ---
        if scope in ("ALL", "GLOBAL"):
            # 1. API Keys & Secrets
            for m in self.api_key_regex.finditer(text):
                matches.append(
                    EntityMatch("API_SECRET_KEY", m.group(0), m.start(), m.end(), 0.99, "GLOBAL", {"category": "Secrets"})
                )

            # 2. Email
            for m in self.email_regex.finditer(text):
                matches.append(
                    EntityMatch("EMAIL_ADDRESS", m.group(0), m.start(), m.end(), 0.98, "GLOBAL", {"category": "Contact"})
                )

            # 3. Credit Cards (with Luhn check)
            for m in self.credit_card_regex.finditer(text):
                raw = m.group(0)
                clean = re.sub(r"\D", "", raw)
                if 13 <= len(clean) <= 19 and validate_luhn(clean):
                    matches.append(
                        EntityMatch("CREDIT_CARD", raw, m.start(), m.end(), 0.97, "GLOBAL", {"category": "Financial", "luhn_valid": True})
                    )

            # 4. US SSN
            for m in self.us_ssn_regex.finditer(text):
                matches.append(
                    EntityMatch("US_SSN", m.group(0), m.start(), m.end(), 0.95, "GLOBAL", {"category": "National ID"})
                )

            # 5. IP Address
            for m in self.ip_regex.finditer(text):
                matches.append(
                    EntityMatch("IP_ADDRESS", m.group(0), m.start(), m.end(), 0.90, "GLOBAL", {"category": "Network"})
                )

        # --- REGIONAL DETECTIONS ---
        if scope in ("ALL", "REGIONAL"):
            # 1. PAN Card
            for m in self.pan_regex.finditer(text):
                val = m.group(1).upper()
                entity_desc = "Individual" if len(val) >= 4 and val[3] == "P" else "Entity"
                matches.append(
                    EntityMatch("PAN_CARD", m.group(1), m.start(1), m.end(1), 0.98, "REGIONAL", {"category": "Tax ID", "entity": entity_desc})
                )

            # 2. Aadhaar Card (with Verhoeff checksum)
            for m in self.aadhaar_regex.finditer(text):
                raw = m.group(1)
                clean = re.sub(r"[\s\-]", "", raw)
                is_valid = len(clean) == 12 and validate_verhoeff(clean)
                matches.append(
                    EntityMatch(
                        "AADHAAR_CARD",
                        raw,
                        m.start(1),
                        m.end(1),
                        0.99 if is_valid else 0.75,
                        "REGIONAL",
                        {"category": "National ID", "verhoeff_valid": is_valid},
                    )
                )

            # 3. UPI ID
            for m in self.upi_regex.finditer(text):
                matches.append(
                    EntityMatch("UPI_ID", m.group(1), m.start(1), m.end(1), 0.96, "REGIONAL", {"category": "Payments"})
                )

            # 4. IFSC Code
            for m in self.ifsc_regex.finditer(text):
                matches.append(
                    EntityMatch("BANK_IFSC", m.group(1).upper(), m.start(1), m.end(1), 0.95, "REGIONAL", {"category": "Banking", "bank": m.group(1)[:4].upper()})
                )

            # 5. Bank Account
            for m in self.bank_acc_regex.finditer(text):
                matches.append(
                    EntityMatch("BANK_ACCOUNT", m.group(1), m.start(1), m.end(1), 0.92, "REGIONAL", {"category": "Banking"})
                )

            # 6. Indian Phone
            for m in self.indian_phone_regex.finditer(text):
                matches.append(
                    EntityMatch("PHONE_NUMBER", m.group(0).strip(), m.start(0), m.end(0), 0.90, "REGIONAL", {"category": "Contact"})
                )

        # Contextual Names
        for m in self.name_context_regex.finditer(text):
            matches.append(
                EntityMatch("PERSON_NAME", m.group(1).strip(), m.start(1), m.end(1), 0.85, "GLOBAL", {"category": "Personal Info"})
            )

        return self._resolve_overlaps(matches)

    def _resolve_overlaps(self, matches: List[EntityMatch]) -> List[EntityMatch]:
        if not matches:
            return []
        sorted_m = sorted(matches, key=lambda x: (x.start, -(x.end - x.start), -x.confidence))
        resolved = []
        last_end = -1
        for m in sorted_m:
            if m.start >= last_end:
                resolved.append(m)
                last_end = m.end
            else:
                prev = resolved[-1]
                if m.confidence > prev.confidence and (m.end - m.start) >= (prev.end - prev.start):
                    resolved[-1] = m
                    last_end = m.end
        return resolved
