# 📜 Changelog

All notable changes to **HTTP Header Analyzer** are documented here.

This changelog follows a human-readable format inspired by **Keep a Changelog** and uses **Semantic Versioning** where applicable.

---

## [Unreleased]

> 🚧 Changes in development and not yet included in a release.

### ✨ Added

- CLI quality gates with `--min-score` and `--fail-on`.
- Deterministic CLI tests for JSON output, quality gates, and analyzer failures.
- Expanded CI coverage for CLI compilation and testing.
- Versioned project changelog.

### 🔧 Improved

- CLI documentation and examples in the README.
- Machine-readable JSON output for automation and CI/CD workflows.
- Security-focused URL validation and outbound request handling.

### 🧪 Testing

- Added coverage for minimum score enforcement.
- Added coverage for severity-based failure thresholds.
- Added coverage for combined quality gates.
- Added coverage for JSON CLI output.
- Added coverage for invalid quality-gate configuration.
- Added coverage for analyzer failure propagation.

---

## [0.1.0] — Initial Development Release

> 🧪 First public development version of HTTP Header Analyzer.

### ✨ Added

#### 🛡️ Security Analysis

- HTTP security-header analysis.
- Content Security Policy (CSP) checks.
- HTTP Strict Transport Security (HSTS) checks.
- `X-Frame-Options` analysis.
- `X-Content-Type-Options` validation.
- Referrer Policy and Permissions Policy checks.
- Cookie security analysis for `Secure`, `HttpOnly`, and `SameSite`.

#### 🔐 TLS Inspection

- TLS protocol detection.
- Cipher-suite reporting.
- Certificate validity inspection.
- Certificate subject and issuer information.
- Certificate expiration reporting.

#### 🔀 Network & Redirect Analysis

- Redirect-chain analysis.
- Final destination tracking.
- Safe outbound request handling.
- SSRF-aware URL validation.
- Protection against localhost, private, loopback, link-local, multicast, and unspecified targets.
- HTTP request timeouts and redirect limits.
- Bounded response-body processing.

#### 🔎 Extended Analysis

- Technology detection.
- CORS configuration analysis.
- HTTP method analysis.
- `security.txt` detection.
- Information-disclosure checks.
- Security scoring from 0–100.
- Letter-based security ratings.
- Actionable remediation guidance.

#### ⚡ API & Web Interface

- REST API for target analysis.
- Health-check endpoint.
- JSON request and response handling.
- Cyberpunk-inspired web dashboard.
- Responsive interface with analysis states and result visualization.

#### 💻 CLI

- Command-line target scanning.
- Human-readable scan results.
- JSON output.
- JSON report file output.
- Configurable scan timeout.
- `version` command.

#### 🧰 Engineering & Security

- Request-body size limits.
- Strict JSON decoding.
- Security-focused server response headers.
- Graceful HTTP server shutdown.
- Go CI workflow with:
  - `go test ./...`
  - `go vet ./...`
  - `go build ./...`

---

## 📌 Versioning

| Version | Status | Notes |
| --- | --- | --- |
| **Unreleased** | 🚧 Development | Changes currently being prepared |
| **0.1.0** | 🧪 Development | Initial public development release |

---

## 🗂️ Change Categories

| Category | Meaning |
| --- | --- |
| ✨ **Added** | New features or capabilities |
| 🔧 **Changed** | Changes to existing behavior |
| 🛡️ **Security** | Security fixes or hardening |
| 🐛 **Fixed** | Bug fixes |
| ⚡ **Performance** | Performance improvements |
| 🧹 **Removed** | Removed features or deprecated behavior |
| 🧪 **Testing** | Test and CI improvements |
| 📚 **Documentation** | Documentation changes |

---

## 🔗 Links

- **Repository:** https://github.com/ItsWanheda/http-header-analyzer
- **Issues:** https://github.com/ItsWanheda/http-header-analyzer/issues
- **Discussions:** https://github.com/ItsWanheda/http-header-analyzer/discussions
- **Security:** See [SECURITY.md](SECURITY.md)

---

<div align="center">

**Analyze. Understand. Secure.**

Made with ❤️ and Go by **ItsWanheda**

</div>
