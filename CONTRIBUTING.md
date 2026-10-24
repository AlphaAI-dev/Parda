# 🤝 Contributing to Parda AI

Welcome to **Parda**! We are building an open-source, client-side privacy standard for Cloud LLMs (Gemini, Claude, ChatGPT).

We actively encourage and welcome contributions from developers, privacy researchers, and students participating in **GSoC (Google Summer of Code)**, Hacktoberfest, and open-source fellowships.

Repository: **[github.com/AlphaAI-dev/Parda](https://github.com/AlphaAI-dev/Parda)**

---

## 🌟 Contributor Spaces & Where to Start

If you are looking to contribute, check our curated issue labels:
- **`good-first-issue`**: Great starting tasks for first-time open-source contributors (e.g. adding single regex detectors, documentation updates, test cases).
- **`gsoc-candidate`**: Substantial feature proposals suitable for Google Summer of Code milestones.
- **`help-wanted`**: Issues where community expertise is specifically requested.
- **`detector`**: Proposing or building new regional or international ID validators.

---

## 🛠️ Local Development Setup

Parda core is designed to be **lightweight and zero-dependency** (using Python standard library).

```bash
# 1. Clone your fork
git clone https://github.com/AlphaAI-dev/Parda.git
cd Parda

# 2. Run unit tests to verify your environment
python3 parda/tests/test_parda.py

# 3. Launch the local interactive web interface
python3 parda/cli.py web --port 8080
```

---

## 🚀 Adding a New Identifier Detector

1. Add your detection pattern and metadata logic to `parda/parda_core/detectors.py`.
2. If the identifier uses a mathematical checksum (e.g. Luhn, Verhoeff, Mod-97), implement the check in `parda/parda_core/checksums.py`.
3. Add positive and negative unit test cases in `parda/tests/test_parda.py`.
4. Update the detector capability table in `parda/README.md`.

---

## 📋 Pull Request (PR) Guidelines

1. **Create a descriptive feature branch**:
   ```bash
   git checkout -b feat/add-german-tax-id
   ```
2. **Keep commits atomic and meaningful** following Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`).
3. **Ensure 100% test coverage**:
   All PRs run automated tests via GitHub Actions CI.
4. **Zero-Leakage Assurance**:
   Ensure no telemetry or network transmissions are introduced into the client-side core.
