# 🔒 HTTP Header Analyzer

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

> **A security-focused HTTP header, TLS, cookie, and redirect analysis tool built with Go.**

HTTP Header Analyzer is a lightweight security auditing application designed to inspect websites and identify common HTTP security misconfigurations. It analyzes security headers, cookies, TLS configuration, certificates, and redirect behavior, then turns the findings into an easy-to-understand security score with actionable remediation guidance.

Built for **developers, security researchers, penetration testers, system administrators, and security enthusiasts**.

**Developed by [ItsWanheda](https://github.com/ItsWanheda).**

---

## 📸 Screenshots

### Main Dashboard

![HTTP Header Analyzer Main Dashboard](assets/main-page.png)

### Security Analysis Results

![HTTP Header Analyzer Results](assets/result-page.png)

### Detailed Security Findings

![HTTP Header Analyzer Detailed Results](assets/result2-page.png)

### Additional Analysis

![HTTP Header Analyzer Additional Results](assets/result3-page.png)

---

## ✨ Overview

Modern web applications rely on a combination of HTTP headers, secure cookies, TLS configuration, and redirect policies to protect users and applications.

HTTP Header Analyzer brings these checks together into a single interface.

Enter a target URL and the analyzer evaluates its externally observable security configuration, identifies potential weaknesses, assigns severity levels, and provides recommendations for improving the target's security posture.

```text
Target URL
    │
    ▼
┌─────────────────────┐
│ HTTP Request        │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Header Analysis     │
│ Cookie Analysis     │
│ TLS/SSL Inspection  │
│ Redirect Tracking   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Security Evaluation │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Score + Findings    │
│ Severity + Fixes    │
└─────────────────────┘
```

---

## 🚀 Highlights

| Capability           | Description                                                   |
| -------------------- | ------------------------------------------------------------- |
| 🛡️ Security Headers | Analyze important HTTP security headers and policies          |
| 🍪 Cookie Security   | Inspect `Secure`, `HttpOnly`, and `SameSite` attributes       |
| 🔐 TLS Inspection    | Examine TLS versions, cipher suites, and certificate metadata |
| 🔀 Redirect Analysis | Track the complete HTTP redirect chain                        |
| 📊 Security Score    | Generate a 0–100 security score with letter grading           |
| 🧠 Remediation       | Provide actionable recommendations for detected issues        |
| 🛑 SSRF Protection   | Block localhost, private IP ranges, and internal targets      |
| 🎨 Modern Interface  | Security-focused responsive dashboard                         |
| 🌓 Theme Support     | Switch between dark and light modes                           |
| 📋 Clipboard Tools   | Quickly copy analysis data                                    |
| ⚡ REST API           | Programmatically perform security analysis                    |
| ❤️ Health Check      | Monitor API/application availability                          |

---

## 🛡️ Security Analysis
### HTTP Security Headers
The analyzer evaluates commonly used security controls, including:
* `Content-Security-Policy`
* `Strict-Transport-Security`
* `X-Frame-Options`
* `X-Content-Type-Options`
* `Referrer-Policy`
* `Permissions-Policy`

Detected configurations are evaluated and presented with their associated security impact and remediation guidance.

---

## 🍪 Cookie Security
Cookies are inspected for important security attributes:
| Attribute  | Purpose                                                  |
| ---------- | -------------------------------------------------------- |
| `Secure`   | Restricts cookie transmission to HTTPS                   |
| `HttpOnly` | Helps prevent client-side scripts from accessing cookies |
| `SameSite` | Helps mitigate cross-site request attacks                |

The analyzer identifies missing or weak cookie protections and provides recommendations where applicable.

---

## 🔐 TLS / SSL Inspection
HTTP Header Analyzer examines TLS-related information including:
* TLS protocol versions
* Cipher suite information
* Certificate metadata
* Certificate expiration status
* HTTPS configuration

This helps identify outdated or potentially insecure TLS configurations.

---

## 🔀 Redirect Chain Tracking
Redirects can introduce unexpected behavior and security concerns.

The analyzer tracks the path from the initial URL through intermediate responses until the final destination.
```text
https://example.com
        │
        ▼
   HTTP 301
        │
        ▼
https://www.example.com
        │
        ▼
   HTTP 302
        │
        ▼
https://www.example.com/login
```

---

## 📊 Security Scoring
Results are converted into an overall security score from 0–100.

The interface also provides letter-based grading to make security results easier to understand at a glance.

|  Score | Grade |
| -----: | :---: |
| 95–100 |   A+  |
|  90–94 |   A   |
|  80–89 |   B   |
|  70–79 |   C   |
|  60–69 |   D   |
|   0–59 |   F   |

---

## 🧠 Remediation Engine
Finding a security issue is only part of the process.

HTTP Header Analyzer provides actionable remediation guidance alongside detected weaknesses.

Each finding can include:
* Security header or configuration
* Current status
* Severity
* Security explanation
* Recommended remediation
* Suggested configuration

Example:
```text
Finding:
Strict-Transport-Security

Status:
Missing

Severity:
High

Recommendation:
Add a Strict-Transport-Security header with an appropriate
max-age value and includeSubDomains where applicable.
```

This makes the tool useful not only for identifying problems, but also for helping developers understand how to address them.

---

## 🛑 SSRF Protection
Because the analyzer performs requests against user-provided URLs, protecting the application against Server-Side Request Forgery (SSRF) is an important security requirement.

The application includes protections designed to prevent requests to internal or restricted destinations, including:
* Localhost addresses
* Private IPv4 ranges
* Internal network targets
* Restricted destinations
* Potentially dangerous URL targets

The validation layer helps prevent attackers from abusing the analyzer as a proxy into protected infrastructure.

---

## 🎨 User Experience
HTTP Header Analyzer uses a security-focused interface designed around fast analysis and clear results.

## 🌑 Cybersecurity-Inspired Design

The interface uses a dark, high-contrast visual style inspired by modern security tooling.

## 🌓 Dark & Light Mode

Switch between dark and light themes depending on your environment and preference.

## 📱 Responsive Layout

The interface is designed to work across:

* Desktop
* Laptop
* Tablet
* Mobile
## ⚡ Interactive Feedback

The application provides visual feedback during operations, including:

* Skeleton loading states
* Toast notifications
* Clipboard actions
* Theme transitions
* Analysis status indicators

---

## ⚙️ REST API
HTTP Header Analyzer provides a JSON-based REST API for integrating analysis functionality into other applications and workflows.

Analyze Target
```http
POST /api/analyze
```

Request
```json
{
  "url": "https://example.com"
}
```

Example Response
```json
{
  "url": "https://example.com",
  "score": 95,
  "rating": "A",
  "issues": [
    {
      "header": "Strict-Transport-Security",
      "status": "pass",
      "severity": "High",
      "explanation": "HSTS prevents SSL stripping...",
      "remediation": "Add 'Strict-Transport-Security' header with 'max-age=63072000; includeSubDomains'."
    }
  ]
}
```

---

## ❤️ Health Check
The application provides a simple health-check endpoint for monitoring availability.

Endpoint
```http
GET /api/health
```

Response
```json
{
  "status": "healthy"
}
```

---

## 🗺️ Roadmap
Planned Features
* [x] JSON reports
* [x] CSV reports
* [x] PDF reports
* [x] CSP Visualizer
* Historical Tracking
* Compare scan results over time
* Detect security regressions
* Track score changes
* Batch Scanner
* Analyze multiple URLs
* Analyze subdomains
* Process URL lists
* Visualize CSP directives
* Identify policy weaknesses
* Present CSP attack surface information
* Export Options

---

## 🚀 Quick Start
Prerequisites

Make sure the following are installed:

* Go 1.21+
* Git

Verify your Go installation:
```bash
go version
```

Verify Git:
```bash
git --version
```

---

## 📥 Installation
Clone the Repository
```bash
git clone https://github.com/itswanheda/http-header-analyzer.git
```

Navigate into the project:
```bash
cd http-header-analyzer
```

Install Dependencies
```bash
go mod tidy
```

---

## ▶️ Running the Application
Start the development server:
```bash
go run cmd/server/main.go
```
The application should become available at:
```bash
http://localhost:8080
```
Open the address in your browser and enter a URL to begin an analysis.

---

## 🏗️ Build the Application
Create a production binary:
```bash
go build -o http-header-analyzer cmd/server/main.go
```
Run the compiled application:
```bash
./http-header-analyzer
```
On Windows:
```bash
.\http-header-analyzer.exe
```

---

## 📂 Project Structure
```text
http-header-analyzer/
│
├── cmd/
│   └── server/
│       └── main.go
│
├── internal/
│   │
│   ├── analyzer/
│   │   ├── analyzer.go
│   │   ├── security.go
│   │   ├── tls.go
│   │   ├── rules.go
│   │   └── redirects.go
│   │
│   ├── api/
│   │   └── handlers.go
│   │
│   ├── models/
│   │   ├── security.go
│   │   └── result.go
│   │
│   └── validation/
│       └── url.go
│
├── web/
│   ├── templates/
│   │   └── index.html
│   │
│   └── static/
│       ├── style.css
│       └── app.js
│
├── assets/
│   ├── main-page.png
│   ├── result-page.png
│   ├── result2-page.png
│   └── result3-page.png
│
├── go.mod
├── go.sum
├── LICENSE
└── README.md
```

---

## 🧩 Architecture
The application is organized into separate layers to keep analysis logic, API handling, validation, and presentation concerns isolated.

```text
┌──────────────────────────────────┐
│            Web UI                │
│        HTML / CSS / JS           │
└────────────────┬─────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐
│             API                  │
│       HTTP Request Handlers      │
└────────────────┬─────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐
│        URL Validation            │
│         SSRF Protection          │
└────────────────┬─────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐
│          Analyzer                │
│                                  │
│  Headers │ Cookies │ TLS │ URLs  │
└────────────────┬─────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐
│       Security Results           │
│   Score │ Grade │ Findings       │
│        │ Remediation │           │
└──────────────────────────────────┘
```

---

## 🔍 Example Analysis Workflow
```text
1. Enter target URL
        ↓
2. Validate URL
        ↓
3. Apply SSRF protections
        ↓
4. Establish HTTP/TLS connection
        ↓
5. Inspect response headers
        ↓
6. Analyze cookies
        ↓
7. Inspect TLS configuration
        ↓
8. Track redirects
        ↓
9. Evaluate security rules
        ↓
10. Calculate security score
        ↓
11. Generate findings
        ↓
12. Display remediation guidance
```

---

## 🛠️ Development
Run the application directly from the source:
```bash
go run cmd/server/main.go
```

Format the Go source code:
```bash
gofmt -w .
```

Run tests:
```bash
go test ./...
```

Run tests with verbose output:
```bash
go test -v ./...
```

Build the project:
```bash
go build ./...
```

---

## 🤝 Contributing
Contributions, bug reports, security improvements, issues, and feature requests are welcome.

1. Fork the Repository

Create your own fork of the project on GitHub.

2. Clone Your Fork
```bash
git clone https://github.com/your-username/http-header-analyzer.git
cd http-header-analyzer
```

3. Create a Feature Branch
```bash
git checkout -b feature/my-feature
```

4. Make Your Changes

Implement your feature or fix while keeping the existing project structure and conventions.

5. Run Tests
```bash
go test ./...
```

6. Commit Your Changes
```bash
git add .
git commit -m "feat: add my feature"
```

7. Push Your Branch
```bash
git push origin feature/my-feature
```

8. Open a Pull Request

Create a Pull Request and describe the changes you made.

---

## 🔐 Responsible Use
HTTP Header Analyzer is intended for legitimate security testing, development, auditing, and educational purposes.

Only analyze systems and URLs that you own or have explicit permission to test.

Do not use the application to:

* Attack systems without authorization
* Bypass access controls
* Probe private infrastructure
* Circumvent security controls
* Conduct unauthorized security assessments

The built-in SSRF protections are intended to reduce abuse of the application, but responsible usage remains the responsibility of the operator.

---

## 📄 License
HTTP Header Analyzer is distributed under the MIT License.

See the [LICENSE](./LICENSE) file for the complete license text.

---

## 🙏 Acknowledgments
HTTP Header Analyzer is built with and inspired by the broader open-source security ecosystem.

Special thanks to:
* [Go](https://go.dev/)
* [Gorilla Mux](https://github.com/gorilla/mux)
* The open-source security community
* Web security researchers and standards communities

---

## ⭐ Support the Project
If you find HTTP Header Analyzer useful, consider giving the repository a ⭐ on GitHub.

Your support helps the project gain visibility, attract contributors, and continue evolving.

```text
⭐ Star the project
🐛 Report bugs
💡 Suggest features
🔧 Submit improvements
📖 Improve documentation
```

---

## 👤 Author
**ItsWanheda**

**GitHub**:

[ItsWanheda](https://github.com/ItsWanheda)

Repository:

[http-header-analyzer](https://github.com/itswanheda/http-header-analyzer)

---

## 📌 Project Status

Status: Active Development

Current Release: v0.7.x

Supported Versions:
| Version | Support       |
| ------- | ------------- |
| `0.7.x` | ✅ Supported   |
| `0.4.x` | ✅ Supported   |
| `0.3.x` | ❌ Unsupported |
| `0.1.x` | ❌ Unsupported |

---

<div align="center">
🔒 HTTP Header Analyzer

Analyze. Understand. Secure.

Made with ❤️ and Go by ItsWanheda

⭐ Star the project if you find it useful.

</div>