# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** via email to:
**cibi-dev@users.noreply.github.com**

Do NOT open public GitHub issues for security vulnerabilities or secret leaks.

### Response SLA
- **Acknowledgement:** Within 48 hours.
- **Triage & Remediation Plan:** Within 7 business days.
- **Patch Release:** Prioritized based on CVSS severity (HIGH/CRITICAL within 7 days).

---

## Security Hardening Applied

This project adheres to the strict **cibi-dev DevSecOps & Security Standard**:

| Security Control | Reference / Standard | Verification |
|---|---|:---:|
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI |
| Path Traversal Defense | CWE-22 (`commonpath`) | Pytest suite |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Safe Subprocess Execution | CWE-78 (`shell=False`, argument list) | Code review & Bandit |
| Constant-Time Crypto Comparisons | CWE-208 (`hmac.compare_digest`) | Unit tests |
| Bounded Memory & Resource Quotas | CWE-400 (Anti-DoS) | Timeout & Stream limits |
| Safe Deserialization | CWE-502 (`yaml.safe_load`, Pydantic v2) | Strict schema validation |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
