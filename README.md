# 🔒 HTTP Header Analyzer

[![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)](https://github.com/ItsWanheda/http-header-analyzer)

> A security-focused HTTP header, TLS, cookie, redirect, and configuration analyzer built with Go.

HTTP Header Analyzer inspects the externally observable security posture of a website and turns its findings into an actionable report. It combines HTTP security-header checks, cookie analysis, TLS inspection, redirect tracking, SSRF-aware URL validation, and a cyberpunk-inspired web interface.

Built for developers, security researchers, penetration testers, system administrators, and security enthusiasts.

> **Responsible use:** Only scan systems that you own or have explicit permission to test.

---

## ✨ Features

| Area | What it does |
| --- | --- |
| 🛡️ Security headers | Checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and related controls |
| 🍪 Cookie security | Reviews `Secure`, `HttpOnly`, and `SameSite` protections |
| 🔐 TLS inspection | Reports protocol, cipher, certificate, issuer, subject, and expiration details |
| 🔀 Redirect analysis | Tracks redirect behavior and the final destination |
| 📊 Security scoring | Produces a normalized score from 0–100 with a letter rating |
| 🧠 Remediation | Provides explanations and practical recommendations for findings |
| 🛑 SSRF defenses | Rejects localhost, private, loopback, link-local, multicast, and unspecified IP targets |
| 🔎 Extended analysis | Detects technologies, CORS settings, HTTP methods, `security.txt`, and information disclosure signals |
| ⚡ REST API | Supports JSON analysis requests and a health-check endpoint |
| 🎨 Web dashboard | Responsive dark/light interface with loading states, notifications, exports, and clipboard tools |

## 📸 Screenshots

| Dashboard | Analysis | Findings |
| --- | --- | --- |
| ![Main dashboard](assets/main-page.png) | ![Analysis results](assets/result-page.png) | ![Detailed findings](assets/result2-page.png) |

![Additional analysis](assets/result3-page.png)

---

## 🧭 How it works

```text
Target URL
    │
    ▼
Validate URL and apply SSRF protections
    │
    ▼
Fetch response and inspect headers, cookies, TLS, and redirects
    │
    ▼
Run extended checks and collect evidence
    │
    ▼
Calculate score and generate remediation guidance
    │
    ▼
Display results in the dashboard or return JSON
```

## 📊 Security rating

The analyzer reports a score between 0 and 100 and maps it to the following rating bands:

| Score | Rating |
| ---: | :---: |
| 97–100 | A+ |
| 93–96 | A |
| 90–92 | A- |
| 87–89 | B+ |
| 83–86 | B |
| 80–82 | B- |
| 77–79 | C+ |
| 73–76 | C |
| 70–72 | C- |
| 60–69 | D |
| 0–59 | F |

---

## ⚡ Quick start

### Requirements

- Go 1.21 or newer
- Git

### Install

```bash
git clone https://github.com/ItsWanheda/http-header-analyzer.git
cd http-header-analyzer
go mod download
```

### Run the web application

```bash
go run ./cmd/server
```

Then open <http://localhost:8080>.

### Use the CLI

Build the scanner CLI:

```bash
go build -o http-header-analyzer ./cmd/http-header-analyzer
```

Scan a target with human-readable output:

```bash
./http-header-analyzer scan https://example.com
```

Return the complete analysis as machine-readable JSON:

```bash
./http-header-analyzer scan https://example.com --json
```

Save JSON directly to a file:

```bash
./http-header-analyzer scan https://example.com --json --output report.json
```

Control the maximum scan duration:

```bash
./http-header-analyzer scan --json --timeout 30s https://example.com
```

Use quality gates in CI/CD:

```bash
# Fail when the score is below 80
./http-header-analyzer scan --min-score 80 https://example.com

# Fail when a High-or-worse issue exists
./http-header-analyzer scan --fail-on high https://example.com

# Combine both checks
./http-header-analyzer scan --json --min-score 80 --fail-on high https://example.com
```

The CLI exits with a non-zero status when a scan cannot be completed, making it suitable for scripts and CI pipelines.

### Build a production binary

```bash
go build -o http-header-analyzer ./cmd/server
./http-header-analyzer
```

On Windows:

```powershell
go build -o http-header-analyzer.exe ./cmd/server
.\http-header-analyzer.exe
```

---

## ⚙️ REST API

### Analyze a target

```http
POST /api/analyze
Content-Type: application/json
```

Request:

```json
{
  "url": "https://example.com"
}
```

Example response shape:

```json
{
  "url": "https://example.com",
  "score": 95,
  "rating": "A",
  "issues": [
    {
      "header": "Strict-Transport-Security",
      "status": "fail",
      "severity": "High",
      "explanation": "HSTS helps prevent protocol downgrade attacks.",
      "remediation": "Add Strict-Transport-Security with an appropriate max-age."
    }
  ]
}
```

### Health check

```http
GET /api/health
```

```json
{
  "status": "healthy"
}
```

---

## 🛡️ Security considerations

Because the application makes outbound requests to user-supplied URLs, URL validation is a core security boundary. The validation layer:

- Accepts only `http` and `https` URLs.
- Rejects embedded credentials and URL fragments.
- Rejects localhost and local hostnames.
- Rejects private, loopback, link-local, multicast, and unspecified IP literals.
- Restricts explicit ports to `80` and `443`.
- Limits request-body sizes and validates JSON API input.

These controls reduce risk but do not replace network-level egress controls, authentication, authorization, or responsible operation. Deploy the service behind appropriate infrastructure controls in production.

See [SECURITY.md](SECURITY.md) for reporting security issues.

---

## 🏗️ Project structure

```text
http-header-analyzer/
├── cmd/
│   └── server/
│       └── main.go              # HTTP server and route registration
├── internal/
│   ├── analyzer/                # Header, TLS, redirect, and extended analysis
│   ├── api/                     # HTTP handlers and JSON responses
│   ├── models/                  # Analysis result types
│   └── validation/              # URL and SSRF-aware validation
├── web/
│   ├── templates/               # HTML templates
│   └── static/                  # JavaScript and CSS assets
├── assets/                      # Screenshots and project media
├── go.mod
├── go.sum
└── README.md
```

## 🧪 Development

Format the Go code:

```bash
gofmt -w cmd internal
```

Run the test suite:

```bash
go test ./...
```

Run tests with verbose output:

```bash
go test -v ./...
```

Run static analysis and build all packages:

```bash
go vet ./...
go build ./...
```

---

## 🤝 Contributing

Contributions, bug reports, documentation improvements, and security enhancements are welcome.

1. Fork the repository.
2. Create a focused branch:
   ```bash
   git checkout -b feature/my-improvement
   ```
3. Make your changes and add tests where appropriate.
4. Run `gofmt`, `go test ./...`, `go vet ./...`, and `go build ./...`.
5. Commit using a clear Conventional Commit message.
6. Push your branch and open a pull request.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

## 🗺️ Roadmap

- [x] JSON analysis reports
- [x] CSV and PDF report support
- [x] CSP visualization
- [x] TLS, cookie, redirect, CORS, and `security.txt` checks
- [ ] Historical scan tracking
- [ ] Result comparison and regression detection
- [ ] Batch URL scanning
- [ ] Subdomain analysis
- [ ] Expanded CSP policy analysis

## 📄 License

This project is distributed under the [MIT License](LICENSE).

## 👤 Author

Created and maintained by [ItsWanheda](https://github.com/ItsWanheda).

If you find the project useful, consider giving it a ⭐ and sharing feedback through [issues](https://github.com/ItsWanheda/http-header-analyzer/issues) or [discussions](https://github.com/ItsWanheda/http-header-analyzer/discussions).

---

<div align="center">

**Analyze. Understand. Secure.**

Made with ❤️ and Go by [ItsWanheda](https://github.com/ItsWanheda)

</div>
