# 🛡️ Security Policy — V1

Security is a core design requirement of HTTP Header Analyzer. This policy explains which release lines receive security fixes and how to report vulnerabilities responsibly.

> **Current stable release:** `v1.0.0` (**V1**)

---

## 🔒 Supported Versions

Security fixes are delivered to the latest supported V1 release line. Upgrade to the newest available V1 patch release before reporting a vulnerability where possible.

| Version | Supported | Status |
| --- | :---: | --- |
| **v1.0.x** | ✅ | Supported V1 release line |
| **v0.x** | ❌ | Legacy; no longer supported |

Only the latest supported release line is eligible for security fixes. A later V1 patch release may supersede an earlier patch release.

---

## 🚨 Reporting a Vulnerability

Please report suspected vulnerabilities **privately**. Do not publish exploit details before maintainers have had a reasonable opportunity to assess and address the issue.

### Responsible Disclosure Guidelines

- **Do not** open a public issue, pull request, or discussion for an unpatched vulnerability.
- **Do not** exploit the issue against systems you do not own or have permission to test.
- **Do not** disclose technical exploit details publicly before a fix or coordinated disclosure agreement.
- Provide clear reproduction steps and limit proof-of-concept activity to systems you control.

### 📧 Contact

Report security findings directly to:

**[wanheda.work@gmail.com](mailto:wanheda.work@gmail.com)**

Please include, where applicable:

- Affected version or commit (V1 release: `v1.0.0`)
- Proof of Concept (PoC) or reproducible steps
- Impact and realistic attack scenarios
- Logs, requests, or sanitized evidence
- Suggested remediation, if known

Do not include real users' private data, credentials, or other secrets in a report.

---

## ⏱️ Response Expectations

We aim to follow this initial response timeline:

1. **Acknowledgment:** within **48 hours** of receipt.
2. **Initial assessment:** within **72 hours**, including an initial view of impact and next steps.

These are response targets, not a guarantee that a fix will be released within that window. Timelines may depend on severity, reproducibility, and release complexity.

---

## 🧱 Security Scope and Deployment Notes

HTTP Header Analyzer makes outbound requests to URLs supplied by a caller. Its protections include URL and destination validation, DNS-address checks, validated redirect handling, bounded request sizes, concurrency limits, per-client rate limiting, and scan deadlines.

These controls reduce risk but do not replace deployment-level safeguards. Operators should:

- Restrict network egress to the destinations appropriate for their environment.
- Place public instances behind authentication or trusted-network controls when anonymous scanning is not intended.
- Add edge-level rate limiting for multi-instance deployments because the built-in limiter is process-local.
- Keep the application and dependencies updated to the latest supported V1 release.
- Scan only targets for which they have authorization.

See the [README](README.md) for setup and operational details, and the [CHANGELOG](CHANGELOG.md) for V1 release history.

---

*Thank you for helping keep HTTP Header Analyzer safer for everyone.*
