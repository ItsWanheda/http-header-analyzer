# 📜 Changelog

All notable changes to **HTTP Header Analyzer** are documented here.

This changelog tracks the project's evolution from its initial implementation through the current **v0.7.0** development line. It is organized by version and grouped by major areas of change.

> **Current version:** `0.7.0`  
> **Status:** ✅ Active Development

---

## [Unreleased]

> 🚧 Changes currently being prepared for the next version.

### 🔧 Planned / In Progress
- Continued analyzer hardening and reliability improvements.
- Additional CLI and automation improvements.
- Further test coverage and documentation refinement.

---

# 🚀 Version History

## [0.7.0] — Active Development

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
|---------|--------|-----------------|
| **Unreleased** | 🚧 Development | Next improvements |
| **0.7.0** | ✅ Active | Advanced analysis, CLI, hardening & automation |
| **0.6.0** | 📊 Development | Advanced security analysis & reporting |
| **0.5.0** | 🎨 Development | Cyberpunk UI, UX & project presentation |
| **0.4.0** | 🔐 Development | SSRF protection & security hardening |
| **0.3.0** | 🔎 Development | Security analysis expansion |
| **0.2.0** | ⚙️ Development | Analyzer, API & web foundation |
| **0.1.0** | 🧪 Initial | Initial project foundation |

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
