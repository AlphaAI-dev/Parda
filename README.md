> [!NOTE]
> **Open Source Privacy Initiative**: **Parda** is an open-source, client-side privacy veil designed to shield confidential credentials, financial identifiers, and personal documents before they touch Cloud LLMs (Gemini, ChatGPT, Claude). Maintained by [AlphaAI-dev](https://github.com/AlphaAI-dev). Licensed under **Apache-2.0**.

<div align="center">

# 🛡️ Parda AI
### The Intelligent Privacy Veil for Cloud LLMs & Agents

[![Testing: CI](https://img.shields.io/badge/Testing-CI%20passing-brightgreen.svg)](#)
[![Coverage: 100%](https://img.shields.io/badge/Coverage-100%25-brightgreen.svg)](#)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](./LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9+-3776AB.svg?logo=python&logoColor=white)](#)
[![GSoC 2026](https://img.shields.io/badge/GSoC-2026-FFA500.svg)](./ROADMAP.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)

[**Live Web Interface**](#-interactive-web-interface) • [**Quick Install**](#-quick-start) • [**Supported Entities**](#-supported-privacy-identifiers) • [**Architecture**](#-architecture-the-two-way-privacy-veil) • [**Contributing**](./CONTRIBUTING.md)

</div>

---

## 📌 Problem & Why Parda Exists

Every day, developers, legal analysts, healthcare workers, and everyday users paste sensitive documents into cloud chatbots like **Google Gemini**, **ChatGPT**, and **Anthropic Claude**.

Existing redaction tools have two fatal flaws:
1. **The Cloud Leak Paradox**: Asking a cloud AI to redact a document requires uploading the sensitive data to cloud servers first—defeating the purpose.
2. **One-Way Destruction**: Blacking out text (`████`) breaks an LLM's reasoning flow. If the prompt says *"Summarize liability for ████"*, the LLM cannot connect entities or generate actionable answers.

**Parda** solves this with a **Two-Way Client-Side Privacy Veil**:
- **On-Device Shielding**: 100% of detection and sanitization executes in your local browser or terminal memory before any packet leaves your machine.
- **Reversible Tokenization**: Sensitive items are substituted with contextual tokens (e.g., `<CREDIT_CARD_1>`, `<AADHAAR_CARD_1>`).
- **Private Local Hydration**: When the cloud AI returns its answer, Parda swaps the tokens back to real values in local memory. The cloud provider **never sees the real data**.

---

## 🚀 Interactive Web Interface

Parda features a zero-dependency, modern web dashboard for instant document protection and live cloud simulation.

### Launch in One Command:
```bash
python3 parda/cli.py web --port 8080
```
Open **`http://localhost:8080`** in any browser.

*Or open `parda/web/index.html` directly in Chrome/Safari with no server needed!*

### Key Web Features:
- **Global & Regional Presets**: Instant sample loading for Global FinTech (Cards, API Keys, IBAN) and Regional KYC (Aadhaar, PAN, UPI, IFSC).
- **3 Masking Modes**:
  - `TOKEN`: Reversible `<ENTITY_ID>` for bidirectional AI chat.
  - `BLACKOUT`: `████` redaction for clean sharing & printing.
  - `SYNTHETIC`: Realistic synthetic mock replacements for LLM benchmarking.
- **Live Two-Way LLM Gateway Simulator**: Shows the exact sanitized payload sent across the wire vs. how the client safely restores original details in browser memory.
- **Export & Telemetry**: Copy sanitized text, export `.txt`, or view real-time Luhn/Verhoeff checksum passes.

---

## 📦 Quick Start

### 1. Scan Documents for Confidential Data
```bash
python3 parda/cli.py scan document.txt --scope all
```

### 2. Sanitize & Redact with Token Placeholders
```bash
python3 parda/cli.py mask document.txt --strategy token
```

---

## 🏗️ Architecture: The Two-Way Privacy Veil

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Browser
    participant Parda as Parda Engine (Local Client)
    participant Vault as Ephemeral Memory Vault
    participant Cloud as Cloud LLM (Gemini / Claude / ChatGPT)

    User->>Parda: Submits Document (Card, Key, Aadhaar, PAN)
    Parda->>Parda: Checksum Validation (Luhn Mod-10 & Verhoeff D5)
    Parda->>Vault: Maps <CREDIT_CARD_1> -> Real Card Number
    Parda->>Cloud: Sends SANITIZED Prompt (Zero Secrets Exposed)
    Cloud->>Parda: Returns AI Response containing <CREDIT_CARD_1>
    Parda->>Vault: Resolves Token from Local Memory
    Parda->>User: Displays Response with Real Entities Restored Locally
```

---

## 🌐 Supported Privacy Identifiers

Parda incorporates mathematical checksum validation to eradicate false positives:

| Category | Identifier | Validation Standard | Example Pattern |
| :--- | :--- | :--- | :--- |
| **Global Secrets** | Cloud API Keys | High-entropy signature (AWS, OpenAI, GitHub) | `AKIAIOSFODNN7EXAMPLE` |
| **Global Financial** | Credit & Debit Cards | **Luhn Mod-10** Checksum Algorithm | `4532 0150 1234 5678` |
| **Global Financial** | IBAN Numbers | ISO 13616 International Bank Standard | `DE89370400440532013000` |
| **Global Identity** | US SSN | SSA Format Exclusions | `219-00-4829` |
| **Global Contact** | Email & Phone | RFC 5322 & ITU-T E.164 Global Formats | `user@domain.com` / `+1 415-555-0199` |
| **Global Network** | IPv4 Addresses | Quad-octet RFC 791 Standards | `198.51.100.42` |
| **Regional ID** | Aadhaar Card | **Dihedral $D_5$ Verhoeff Checksum** | `5432 8901 2345` |
| **Regional Tax** | PAN Card | Entity Taxonomy (4th Char: P, C, H, F, T) | `ABCPS1234F` |
| **Regional Payments** | UPI ID (VPA) | NPCI Handle Registry (`@okhdfcbank`, `@paytm`) | `user.pay@okaxis` |
| **Regional Banking** | IFSC & Accounts | RBI 11-char Routing Standard | `SBIN0001234` / `A/c 309876543210` |

---

## 💻 Python Library Usage

```python
from parda_core.vault import PardaSession

session = PardaSession(strategy="TOKEN")

# Step 1: Sanitize locally before network transmission
raw_text = "Process invoice for Visa 4532015012345671 and PAN ABCPS1234F."
sanitized_payload = session.sanitize(raw_text)

print(sanitized_payload["sanitized_text"])
# Output: Process invoice for Visa <CREDIT_CARD_1> and PAN <PAN_CARD_1>.

# Step 2: Query Cloud LLM with sanitized_payload
# response = gemini.generate_content(sanitized_payload["sanitized_text"])
mock_cloud_reply = "Verified billing for card <CREDIT_CARD_1> owned by <PAN_CARD_1>."

# Step 3: Hydrate back locally on your device
restored_result = session.de_anonymize(mock_cloud_reply)
print(restored_result)
# Output: Verified billing for card 4532015012345671 owned by ABCPS1234F.
```

---

## 🧪 Testing & Verification

Parda ships with a comprehensive unit test suite:

```bash
python3 parda/tests/test_parda.py
```

---

## 🤝 Open Source & Contributing

Contributions are warmly welcomed! Please see [**CONTRIBUTING.md**](./CONTRIBUTING.md) for onboarding steps, coding standards, and how to submit pull requests.

Visit the official repository: **[github.com/AlphaAI-dev/Parda](https://github.com/AlphaAI-dev/Parda)**

---

## 📄 License

Licensed under the **Apache License 2.0** - see [LICENSE](./LICENSE) for details.
