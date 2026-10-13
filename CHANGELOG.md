# 📜 HTTP Header Analyzer — Changelog

All notable changes to **HTTP Header Analyzer** are documented here.

This changelog follows semantic versioning. The current stable release is **V1 · `v1.0.0`**. Historical `0.x` entries are retained as a record of earlier milestones.

> **Current stable version:** `v1.0.0`  
> **Release line:** V1  
> **Release date:** 2026-10-13  
> **Status:** ✅ Stable

---

## [Unreleased]

> Changes listed here are planned for a future release and are not part of `v1.0.0` unless noted elsewhere.

No unreleased changes have been recorded yet.

---

## [1.0.0] — V1 Stable Release (2026-10-13)

> 🎉 **First stable V1 release.** This milestone consolidates the security analyzer, reporting dashboard, API safeguards, CLI automation, and automated verification into a production-oriented release.

### 🛡️ Security and Correctness

- Hardened URL validation against localhost, local and reserved hostnames, private and special-use IPv4/IPv6 ranges, legacy numeric IP formats, unusual ports, and unsafe destinations.
- Validated DNS results at connection time and rejected mixed public/private address answers.
- Disabled environment-proxy routing for target scans and validated each redirect destination before following it.
- Changed HTTP-method discovery to use `OPTIONS` and the `Allow` response header instead of sending state-changing probe methods.
- Improved security scoring so not-applicable and unknown checks do not distort the denominator; missing required controls and weak policies are represented distinctly.
- Added structured Content Security Policy analysis, including risky directives, unsafe script sources, wildcard sources, and missing policy controls.
- Expanded HSTS policy-strength assessment, including disabled and short `max-age` values.
- Integrated TLS certificate-chain and hostname observations, validity dates, key strength, and weak-signature signals.
- Expanded cookie-level findings, redirect metadata, CORS and method observations, `security.txt`, robots.txt, technology detection, and information-disclosure reporting.

### 📊 Dashboard and Reports

- Added an executive summary with score/rating, scan metadata, status counters, and passed/failed check counts.
- Added finding search, severity filtering, sorting, expandable remediation guidance, responsive layout, accessible theme controls, progress feedback, and scan cancellation.
- Added bounded batch scanning in the dashboard and API, with validation before work starts and capped parallelism.
- Added browser-local scan history and comparisons that identify new, resolved, and unchanged findings for repeated scans of the same hostname.
- Added CSV export with spreadsheet-formula-injection mitigation.
- Updated print/save-to-PDF reporting to use the current result instead of unexpectedly running the target scan again.
- Retained JSON export for machine-readable reporting.

### ⚡ API and Operational Safeguards

- Added a bounded batch endpoint for 1–10 targets per request, with limited batch workers and a process-wide scan concurrency cap.
- Added per-client API rate limiting, strict JSON decoding, request-body bounds, scan deadlines, and safer error handling.
- Added a health endpoint and hardened HTTP response behavior.
- Documented production deployment limitations: process-local rate limits do not coordinate across replicas, and deployments should add authentication or trusted-network controls when public anonymous scanning is not intended.

### 💻 CLI, Testing, and Engineering

- Standardized the Go module/import path.
- Added CLI scanning, JSON output and file export, a version command, configurable timeout, minimum-score gates, and severity gates for automation.
- Expanded URL-validation, SSRF, analyzer, CSP, HSTS, cookie, API, and integration regression tests.
- Added a Playwright Chromium dashboard smoke suite.
- Expanded Go CI with formatting/build/static checks, race tests, module verification, and vulnerability scanning.
- Updated project documentation to describe V1 features, responsible scanning, development, and reporting workflows.

---

# 🕰️ Previous Version History

## [0.7.0] — Previous Development Milestone

> **Release milestone:** Advanced analysis, professional reporting, major security hardening, and production-oriented CLI tooling.

### 🧠 Advanced Security Analysis
- Added HSTS analysis.
- Added `security.txt` detection and analysis.
- Added technology detection.
- Added information-disclosure analysis.
- Added HTTP method analysis.
- Added CORS analysis.
- Extended scan results with advanced security data.
- Integrated advanced analyzers into the main scan pipeline.

### 📊 Professional Reporting
- Added professional security assessment reports.
- Added dedicated security report API endpoint.
- Expanded result models for advanced security findings.
- Added richer security assessment output for dashboard and API consumers.

### 🔐 Security Hardening
- Hardened target URL validation against SSRF.
- Added protection against localhost and private/reserved destinations.
- Added protection for loopback, link-local, multicast, and unspecified addresses.
- Tightened redirect and outbound-request handling.
- Added safe target validation to report generation.
- Added request-context propagation.

### 💻 CLI & Automation
- Added CLI scanning.
- Added JSON scan output.
- Added JSON report-file output.
- Added configurable scan timeout.
- Added `version` command.
- Added `--min-score` quality gates.
- Added `--fail-on` severity gates.
- Added combined quality-gate support for CI/CD workflows.
- Added deterministic CLI tests for output, gates, and failure handling.

### 🧪 Engineering & CI
- Added Go test and vet workflow.
- Added CLI compilation to CI.
- Expanded security-rule tests.
- Expanded URL-validation and SSRF tests.
- Added cookie and safe-target test coverage.
- Hardened API input handling and request limits.
- Added graceful server shutdown and server hardening.

### 📚 Documentation
- Major README documentation refresh.
- Added CLI and JSON usage documentation.
- Added quality-gate examples.
- Added versioned project changelog.

---

## [0.6.0] — Advanced Security & Reporting

> 🛡️ Expanded the scanner from header inspection into a broader security assessment platform.

### ✨ Added
- Advanced security analysis framework.
- HSTS analyzer.
- `security.txt` analyzer.
- Technology analyzer.
- Information-disclosure analyzer.
- HTTP-method analyzer.
- CORS analyzer.
- Professional security assessment report generation.
- Security report API endpoint.
- Advanced security result models.

### 📊 Dashboard
- Added dedicated sections for advanced security findings.
- Added richer visualization of scan results.
- Integrated advanced analyzer results into the UI.

### 🔧 Improved
- Expanded analysis pipeline.
- Improved result structure for API and dashboard consumers.
- Improved security reporting workflow.

---

## [0.5.0] — Cyberpunk UI & Project Presentation

> 🎨 Major visual and user-experience evolution of the project.

### 🎨 UI / UX
- Major dashboard overhaul.
- Introduced the cyberpunk-inspired visual identity.
- Improved scan-result presentation.
- Improved analysis states and result visualization.
- Improved responsive behavior and overall UX.

### 📚 Documentation
- Expanded README documentation.
- Added project screenshots and preview material.
- Improved feature descriptions.
- Improved project structure documentation.
- Added clearer project presentation for users and contributors.

### 🤝 Community
- Added contribution documentation.
- Added Code of Conduct.
- Added security documentation.
- Added issue templates and bug-report workflow.

---

## [0.4.0] — Security Hardening Foundation

> 🔐 Focused heavily on making outbound scanning safer and the codebase more resilient.

### 🛡️ SSRF Protection
- Hardened target URL validation.
- Restricted unsupported URL schemes.
- Rejected malformed and unsafe targets.
- Added protection against localhost targets.
- Added protection against private IPv4/IPv6 ranges.
- Added protection against loopback addresses.
- Added protection against link-local addresses.
- Added protection against multicast and unspecified addresses.
- Hardened redirect destination validation.

### 🔒 Analyzer Hardening
- Improved HTTP client configuration.
- Added request timeouts.
- Added redirect limits.
- Added bounded response-body processing.
- Improved outbound connection handling.
- Hardened TLS/request behavior.

### 🌐 API Hardening
- Added request-body limits.
- Added strict JSON decoding.
- Added request validation.
- Added safer error handling.
- Added security-focused HTTP response headers.
- Added graceful server shutdown.
- Added server timeouts.

### 🧪 Testing
- Added URL-validation tests.
- Added SSRF guard tests.
- Added security-header rule tests.
- Added security-rating tests.
- Added safe-target and cookie-rule tests.

### ⚙️ CI
- Added automated Go testing.
- Added `go vet` checks.
- Added build verification.

---

## [0.3.0] — Security Analysis Expansion

> 🔎 Expanded the original analyzer into a more complete HTTP security scanner.

### 🛡️ Security Headers
- Added security-header analysis.
- Added CSP analysis.
- Added HSTS analysis foundation.
- Added `X-Frame-Options` checks.
- Added `X-Content-Type-Options` validation.
- Added Referrer Policy analysis.
- Added Permissions Policy analysis.

### 🍪 Cookie Security
- Added cookie security analysis.
- Added `Secure` flag checks.
- Added `HttpOnly` flag checks.
- Added `SameSite` analysis.

### 🔐 TLS
- Added TLS protocol information.
- Added cipher-suite reporting.
- Added certificate inspection.
- Added certificate subject and issuer information.
- Added certificate expiration information.

### 🔀 Redirects
- Added redirect-chain analysis.
- Added final-destination tracking.
- Added redirect limits.
- Added safe redirect handling.

### 📊 Scoring
- Added security scoring from 0–100.
- Added letter-based security ratings.
- Added actionable remediation guidance.

---

## [0.2.0] — Analyzer & API Foundation

> ⚙️ Established the core scanning engine, API layer, and web application structure.

### 🧠 Analyzer Core
- Built the main HTTP analysis pipeline.
- Added HTTP request/response inspection.
- Added response-header processing.
- Added security finding generation.
- Added structured analysis results.

### ⚡ API
- Added REST API target analysis.
- Added health-check endpoint.
- Added JSON request/response handling.
- Added API routing and server structure.

### 🌐 Web Interface
- Added browser-based analysis dashboard.
- Added target scanning workflow.
- Added scan result rendering.
- Added responsive interface foundations.

### 🧰 Project Structure
- Organized the Go application into modular packages.
- Separated analyzer, API, model, validation, and command responsibilities.
- Established a maintainable project layout.

---

## [0.1.0] — Initial Release

> 🧪 The starting point of HTTP Header Analyzer.

### ✨ Added
- Initial Go implementation.
- Basic HTTP target analysis.
- Initial security-header inspection.
- Initial result models.
- Initial command/server structure.
- Initial web interface foundation.

### 📚 Documentation
- Initial README.
- Basic project description.
- Initial project structure documentation.

### 🧱 Foundation
- Established the project as an open-source HTTP security analysis tool.
- Created the initial repository and development workflow.

---

# 📌 Version Overview

| Version | Status | Major Milestone |
| --- | --- | --- |
| **v1.0.0 (V1)** | ✅ Current stable | First stable release: security analysis, safer scanning, dashboard history, reports, bounded API, CLI, and CI |
| **v0.7.0** | 📚 Historical | Advanced analysis, CLI tooling, security hardening, and automation |
| **v0.6.0** | 📚 Historical | Advanced security analysis and reporting |
| **v0.5.0** | 📚 Historical | Cyberpunk UI, UX, and project presentation |
| **v0.4.0** | 📚 Historical | SSRF protection and security hardening |
| **v0.3.0** | 📚 Historical | Security analysis expansion |
| **v0.2.0** | 📚 Historical | Analyzer, API, and web foundation |
| **v0.1.0** | 📚 Historical | Initial project foundation |

---

# 🗂️ Change Categories

| Category | Meaning |
|----------|---------|
| ✨ **Added** | New features or capabilities |
| 🔧 **Changed** | Changes to existing behavior |
| 🛡️ **Security** | Security fixes and hardening |
| 🐛 **Fixed** | Bug fixes |
| ⚡ **Performance** | Performance improvements |
| 🧹 **Removed** | Removed or deprecated functionality |
| 🧪 **Testing** | Tests and CI improvements |
| 📚 **Documentation** | Documentation and project presentation |

---

# 🔗 Links

- **Repository:** https://github.com/ItsWanheda/http-header-analyzer
- **Issues:** https://github.com/ItsWanheda/http-header-analyzer/issues
- **Discussions:** https://github.com/ItsWanheda/http-header-analyzer/discussions
- **Security:** [SECURITY.md](SECURITY.md)

---

<div align="center">

**Analyze. Understand. Secure.**

Made with ❤️ and Go by **ItsWanheda**

</div>
