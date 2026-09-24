# 🤝 Contributing to HTTP Header Analyzer

Thank you for contributing to **HTTP Header Analyzer**. This project is security-focused, so correctness, safe networking, and regression testing are especially important.

## 🚀 Before You Start

1. Fork the repository and create a branch from `main`.
2. Keep each change focused on one feature, fix, or improvement.
3. Follow **Conventional Commits**.
4. Do not commit secrets, credentials, private URLs, or sensitive scan data.
5. Read [SECURITY.md](SECURITY.md) before reporting security-sensitive issues.

## 🐛 Reporting Bugs

Before opening an issue, check the existing [Issues](https://github.com/ItsWanheda/http-header-analyzer/issues).

Include:

- Clear description of the problem
- Steps to reproduce
- Expected behavior
- Actual behavior
- Operating system
- Go version
- HTTP Header Analyzer version or commit
- Relevant logs or command output

> ⚠️ Do not publicly disclose exploitable vulnerability details. Use the private security reporting process in [SECURITY.md](SECURITY.md).

## ✨ Feature Requests

Use the feature-request template and explain:

- The problem you are trying to solve
- Why the feature is useful
- Your proposed behavior
- Any alternatives you considered

Security-sensitive features should include their threat model and expected security impact where relevant.

## 🔧 Development Setup

### Requirements

- Go 1.21 or compatible supported version
- Git

### Clone

```bash
git clone https://github.com/ItsWanheda/http-header-analyzer.git
cd http-header-analyzer
```

### Install Dependencies

```bash
go mod download
```

### Run Tests

```bash
go test ./...
```

### Run Static Checks

```bash
go vet ./...
```

### Build

```bash
go build ./...
```

### Run the Server

```bash
go run ./cmd/server
```

## 🧪 Testing Expectations

Changes should include tests when they affect:

- URL validation or SSRF protections
- Security-header rules
- TLS analysis
- Redirect handling
- API validation
- CLI behavior
- Security scoring
- Analyzer behavior

For security-sensitive changes, tests should cover both the intended behavior and relevant unsafe inputs.

## 🔐 Security First

Never:

- Commit credentials or API keys
- Test against systems without authorization
- Weaken SSRF protections without a documented security reason
- Bypass validation to make a test pass
- Include real secrets or sensitive target data in fixtures

## 📝 Pull Requests

A good PR should:

- Explain **what** changed and **why**
- Keep the diff focused
- Include tests for behavioral changes
- Update documentation when user-facing behavior changes
- Update `CHANGELOG.md` when appropriate
- Pass the repository CI checks

Before submitting:

```bash
go test ./...
go vet ./...
go build ./...
```

## 💬 Questions & Discussions

For questions, ideas, and general project discussion, use [GitHub Discussions](https://github.com/ItsWanheda/http-header-analyzer/discussions).

For bugs, use [Issues](https://github.com/ItsWanheda/http-header-analyzer/issues).

For vulnerabilities, follow [SECURITY.md](SECURITY.md).

---

**Analyze. Understand. Secure.**
