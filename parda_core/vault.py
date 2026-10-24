"""
Parda Session Vault & Privacy Proxy.
"""

from typing import Dict, Any
from .detectors import PardaDetector
from .masker import PardaMasker


class PardaSession:
    def __init__(self, strategy: str = "TOKEN", scope: str = "ALL"):
        self.strategy = strategy
        self.scope = scope
        self.detector = PardaDetector()
        self.masker = PardaMasker(self.detector)
        self.vault: Dict[str, str] = {}

    def sanitize(self, raw_input: str) -> Dict[str, Any]:
        masked, session_vault, entities = self.masker.mask(
            raw_input, strategy=self.strategy, scope=self.scope
        )
        self.vault.update(session_vault)
        return {
            "sanitized_text": masked,
            "entities_detected": len(entities),
            "entities": entities,
            "vault_keys": list(session_vault.keys()),
        }

    def de_anonymize(self, llm_response: str) -> str:
        return self.masker.unmask(llm_response, self.vault)

    def clear(self):
        self.vault.clear()
