"""
Parda Masking & Anonymization Engine.
"""

from typing import List, Dict, Tuple
from .detectors import EntityMatch, PardaDetector


class PardaMasker:
    def __init__(self, detector: PardaDetector = None):
        self.detector = detector or PardaDetector()

    def mask(
        self,
        text: str,
        strategy: str = "TOKEN",
        scope: str = "ALL",
        matches: List[EntityMatch] = None,
    ) -> Tuple[str, Dict[str, str], List[Dict]]:
        if matches is None:
            matches = self.detector.detect_all(text, scope=scope)

        token_vault: Dict[str, str] = {}
        entity_counters: Dict[str, int] = {}
        entities_found = [m.to_dict() for m in matches]

        parts = []
        last_idx = 0

        for match in matches:
            parts.append(text[last_idx : match.start])
            e_type = match.entity_type
            entity_counters[e_type] = entity_counters.get(e_type, 0) + 1
            idx = entity_counters[e_type]

            if strategy == "TOKEN":
                token = f"<{e_type}_{idx}>"
                token_vault[token] = match.value
                replacement = token
            elif strategy == "BLACKOUT":
                replacement = "█" * max(len(match.value), 4)
            elif strategy == "SYNTHETIC":
                token = f"<{e_type}_{idx}>"
                token_vault[token] = match.value
                replacement = f"[REDACTED_{e_type}]"
            else:
                replacement = f"[{e_type}]"

            parts.append(replacement)
            last_idx = match.end

        parts.append(text[last_idx:])
        return "".join(parts), token_vault, entities_found

    def unmask(self, text: str, token_vault: Dict[str, str]) -> str:
        restored = text
        for token, orig in token_vault.items():
            restored = restored.replace(token, orig)
        return restored
