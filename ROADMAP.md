# Parda AI Project Roadmap 🗺️

Tracking key development milestones for **Parda** ([github.com/AlphaAI-dev/Parda](https://github.com/AlphaAI-dev/Parda)).

---

## 🎯 Phase 1: Client-Side Core & Interactive Web (Current)
- [x] Dual Scope Engine: Global (Cards, API Keys, Passwords, Emails, SSN) & Regional (Aadhaar, PAN, UPI, IFSC).
- [x] Mathematical Checksum Validation: Luhn Mod-10 & Dihedral $D_5$ Verhoeff algorithms.
- [x] Three Masking Strategies: Tokenized Reversible, Full Blackout, and Synthetic Replacement.
- [x] Two-Way Session Vault for local client-side de-anonymization.
- [x] Zero-dependency Interactive Web Version with Live Cloud LLM Gateway Simulator.

---

## 🔮 Phase 2: Chrome Extension & Browser Integration (Next Release)
- [ ] Manifest V3 Chrome Extension targeting `chatgpt.com`, `gemini.google.com`, and `claude.ai`.
- [ ] Auto-detection of pasted files (PDF, TXT, images) inside browser input containers.
- [ ] Zero-latency in-browser NER using Transformers.js and WebGPU.

---

## 🌐 Phase 3: Developer Middleware & Integrations (GSoC 2026)
- [ ] Drop-in Proxy middleware for LiteLLM, LangChain, and OpenAI SDK.
- [ ] Multi-platform CLI with terminal streaming and Git pre-commit hooks.
- [ ] Benchmarks across real-world legal, financial, and healthcare datasets.
