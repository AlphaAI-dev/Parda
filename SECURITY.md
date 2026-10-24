# Security Policy 🛡️

## Privacy Architecture
Parda is strictly designed with a **Zero-Cloud Leakage** guarantee:
- All regex pattern matching and checksum algorithms run **locally on the client machine**.
- The token vault is ephemeral and held in memory during the session—it is never sent over any network socket.
- No telemetry, analytics, or document payloads are collected or stored.

## Vulnerability Disclosure
If you find a security bypass, please report it privately via GitHub Security Advisories or email `security@alphaai.dev`.
