# Contributing to HTTP Analyzer

First off, thanks for taking the time to contribute! Contributions are what make this project a powerful security asset.

## How to Contribute
### Reporting Bugs
* Check the [Issues](https://github.com/ItsWanheda/HTTP-Analyzer/issues) page to see if the bug has already been reported.
* If not, open a new issue. Please include:
    * **Environment info** (OS, Python version, etc.)
    * **Steps to reproduce**
    * **Logs or error messages**

### Pull Requests (PRs)
1. **Fork the repo** and create your branch from `main`.
2. **Commit style**: Please follow [Conventional Commits](https://www.conventionalcommits.org/). (e.g., `feat: add TLS 1.3 check`, `fix: resolve SSRF parsing error`).
3. **Keep it focused**: One feature or bug fix per PR.
4. **Test it**: If you add a new security check, add a test case in `/tests`. We want to ensure no regressions in our scoring engine.
5. **Documentation**: If your change adds a new parameter or functionality, please update the `README.md`.

## Development Setup
1. **Clone your fork**: `git clone ...`
2. **Install dependencies**: `go mod tidy`
3. **Run the local server**: [go run cmd/server/main.go and to access open http://localhost:8080]
4. **Coding Style**: Please keep the code clean and comment on complex logic—especially when dealing with regex or binary parsing for headers.

## Security First
* **Never** hardcode any sensitive credentials (API keys, test tokens) in your PRs.
* All new security modules must be designed with **ethical use** in mind.

## Questions?
If you're stuck, reach out in the [Discussions](https://github.com/ItsWanheda/HTTP-Analyzer/discussions) section or open an issue!
