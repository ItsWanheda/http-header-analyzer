# 🔒 HTTP Header Analyzer

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge\&logo=go)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

A security-focused HTTP header analysis tool built with **Go (Golang)**. It inspects HTTP response headers, TLS configurations, and redirect chains to help identify common web security issues and misconfigurations.

Developed by **ItsWanheda**.

---

## ✨ Features

### 🛡️ Security & Analysis Core

**Cookie Security Analysis**: Automated audit of Secure, HttpOnly, and SameSite flags.
**Remediation Engine**: Provides specific, actionable recommendations for every missing or weak security configuration.
* **Security Header Analysis**: Deep inspection of CSP, HSTS, X-Frame, X-Content-Type, Referrer, and Permissions policies.
* **TLS/SSL Inspection**: Detects TLS versions, cipher suites, certificate metadata, and expiration status.
* **Redirect Chain Tracking**: Full path visualization from initial request to final destination.
* **Security Scoring**: Automated 0–100 scoring system with letter grades (A+ to F).
* **Built-in SSRF Protection**: Hardened against blind/non-blind SSRF by blocking localhost, private IP ranges, and internal network targets.

### 🎨 User Experience (UX)
* **Cyberpunk/Hacker Aesthetic**: Dark-themed, high-contrast UI designed for security enthusiasts.
* **Dark/Light Mode**: Smooth theme toggling for comfort during late-night analysis.
* **Responsive Design**: Fluid layout optimized for desktops, tablets, and mobile devices.
* **Interactive Feedback**: 
    * **One-Click Clipboard**: Instant JSON response copying.
    * **Pulsing Skeleton Loaders**: Smooth, professional loading states.
    * **Toast Notifications**: Non-intrusive status updates for alerts and operations.

### ⚙️ Integration
* **REST API**: JSON-based analysis endpoints and system health-check utilities.

---

## 🗺️ Roadmap (Upcoming Features)
* [ ] **Historical Tracking**: Compare scan results over time to detect security regressions.
* [ ] **Batch Scanner**: Analyze multiple subdomains or lists of URLs.
* [ ] **CSP Visualizer**: Graphical breakdown of CSP directives and attack surface.
* [ ] **Export Options**: Download comprehensive reports in JSON, CSV, or PDF formats.

---

## 🚀 Quick Start

### Prerequisites

* Go 1.21+
* Git

### Clone the Repository

```bash
git clone https://github.com/itswanheda/http-header-analyzer.git
cd http-header-analyzer
```

### Install Dependencies

```bash
go mod tidy
```

### Run the Application

```bash
go run cmd/server/main.go
```

### Open in Browser

```text
http://localhost:8080
```

---

## 📂 Project Structure

```text
http-header-analyzer/
├── cmd/
│   └── server/
│       └── main.go
│
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go
│   │   ├── security.go
│   │   ├── tls.go
│   │   ├── rules.goo  # Added
│   │   └── redirects.go
│   │    
│   │
│   ├── api/
│   │   └── handlers.go
│   │
│   ├── models/
│   │   ├── security.go # Added
│   │   └── result.go
│   │
│   │
│   └── validation/
│       └── url.go
│
├── web/
│   ├── templates/
│   │   └── index.html #updated
│   │
│   └── static/
│       ├── style.css #updated
│       └── app.js    #updated
│
├── go.mod
├── go.sum
└── README.md
```

---

## 🛠 API Documentation

### Analyze Target

**Endpoint**

```http
POST /api/analyze
```

### Request Body

```json
{
  "url": "https://example.com"
}
```

### Example Response

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

### Health Check

**Endpoint**

```http
GET /api/health
```

### Response

```json
{
  "status": "healthy"
}
```

---

## 📸 Screenshots

### Main Interface

![Main Interface](assets/main-page.png)

### Analysis Results

![Analysis Results](assets/result-page.png)

![Analysis Results](assets/result2-page.png)

![Analysis Results](assets/result3-page.png)

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome.

### Steps

1. Fork the repository
2. Create a feature branch

```bash
git checkout -b feature/my-feature
```

3. Commit your changes

```bash
git commit -m "Add my feature"
```

4. Push to your branch

```bash
git push origin feature/my-feature
```

5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License.

See the `LICENSE` file for more information.

---

## 🙏 Acknowledgments

* Go Standard Library
* Gorilla Mux
* Open-source security community

---

## ⭐ Support

If you find this project useful, consider giving it a star on GitHub. It helps the project grow and reach more developers.
