package analyzer

import (
	"strings"

	"github.com/ItsWanheda/http-header-analyzer/internal/models"
)

var RuleRegistry = []models.SecurityRule{
	{
		Name: "Strict-Transport-Security", HeaderName: "Strict-Transport-Security",
		Severity: models.SeverityCritical, Required: true,
		Explanation: "HSTS ensures browsers only connect via HTTPS.",
		Remediation: "Add Strict-Transport-Security with a long max-age and includeSubDomains.",
		CheckLogic: func(v string) (bool, string) {
			lower := strings.ToLower(v)
			if !strings.Contains(lower, "max-age=") { return false, "Missing max-age directive" }
			if !strings.Contains(lower, "includesubdomains") { return false, "Missing includeSubDomains directive" }
			return true, ""
		},
	},
	{
		Name: "Content-Security-Policy", HeaderName: "Content-Security-Policy",
		Severity: models.SeverityHigh, Required: true,
		Explanation: "CSP reduces the impact of XSS and content injection attacks.",
		Remediation: "Implement a restrictive Content-Security-Policy appropriate for the application.",
		CheckLogic: func(v string) (bool, string) {
			assessment := analyzeCSP(v)
			if assessment.Status == "fail" {
				return false, strings.Join(assessment.Warnings, "; ")
			}
			return true, ""
		},
	},
	{
		Name: "X-Content-Type-Options", HeaderName: "X-Content-Type-Options",
		Severity: models.SeverityMedium, Required: true,
		Explanation: "Prevents MIME-type sniffing.",
		Remediation: "Set X-Content-Type-Options: nosniff.",
		CheckLogic: func(v string) (bool, string) {
			if !strings.EqualFold(strings.TrimSpace(v), "nosniff") { return false, "Value should be nosniff" }
			return true, ""
		},
	},
	{
		Name: "X-Frame-Options", HeaderName: "X-Frame-Options",
		Severity: models.SeverityMedium, Required: true,
		Explanation: "Helps prevent clickjacking.",
		Remediation: "Set X-Frame-Options to DENY or SAMEORIGIN.",
		CheckLogic: func(v string) (bool, string) {
			value := strings.ToUpper(strings.TrimSpace(v))
			if value != "DENY" && value != "SAMEORIGIN" { return false, "Value should be DENY or SAMEORIGIN" }
			return true, ""
		},
	},
	{
		Name: "Referrer-Policy", HeaderName: "Referrer-Policy",
		Severity: models.SeverityMedium, Required: true,
		Explanation: "Controls how much referrer information is sent to other origins.",
		Remediation: "Prefer strict-origin-when-cross-origin or a more restrictive policy suitable for the application.",
		CheckLogic: func(v string) (bool, string) {
			value := strings.ToLower(strings.TrimSpace(v))
			allowed := map[string]bool{"no-referrer": true, "no-referrer-when-downgrade": true, "origin": true, "origin-when-cross-origin": true, "same-origin": true, "strict-origin": true, "strict-origin-when-cross-origin": true, "unsafe-url": true}
			if !allowed[value] { return false, "Unknown or invalid Referrer-Policy value" }
			if value == "unsafe-url" { return false, "unsafe-url may disclose full URL paths and query strings cross-origin" }
			return true, ""
		},
	},
	{
		Name: "Permissions-Policy", HeaderName: "Permissions-Policy",
		Severity: models.SeverityLow, Required: false,
		Explanation: "Restricts browser features such as camera, microphone, and geolocation.",
		Remediation: "Define an application-appropriate Permissions-Policy and disable features that are not needed.",
		CheckLogic: func(v string) (bool, string) {
			if strings.TrimSpace(v) == "" { return false, "Permissions-Policy is empty" }
			return true, ""
		},
	},
	{
		Name: "Cross-Origin-Opener-Policy", HeaderName: "Cross-Origin-Opener-Policy",
		Severity: models.SeverityLow, Required: false,
		Explanation: "Can isolate the top-level browsing context from cross-origin documents.",
		Remediation: "Consider same-origin where compatible with the application's cross-origin integration requirements.",
		CheckLogic: func(v string) (bool, string) {
			value := strings.ToLower(strings.TrimSpace(v))
			if value != "same-origin" && value != "same-origin-allow-popups" && value != "unsafe-none" { return false, "Unrecognized Cross-Origin-Opener-Policy value" }
			if value == "unsafe-none" { return false, "unsafe-none does not provide opener isolation" }
			return true, ""
		},
	},
	{
		Name: "Cookie Security", HeaderName: "Set-Cookie",
		Severity: models.SeverityHigh, Required: false,
		Explanation: "Cookies should use Secure, HttpOnly, and SameSite attributes where appropriate.",
		Remediation: "Add Secure, HttpOnly, and SameSite to sensitive cookies.",
		CheckLogic: CheckCookieSecurity,
	},
}

func CheckCookieSecurity(cookieString string) (bool, string) {
	parts := strings.Split(cookieString, ";")
	if len(parts) == 0 || !strings.Contains(parts[0], "=") {
		return false, "Invalid Set-Cookie value"
	}

	hasSecure, hasHTTPOnly, hasSameSite := false, false, false
	for _, part := range parts[1:] {
		attr := strings.TrimSpace(part)
		lower := strings.ToLower(attr)
		switch {
		case lower == "secure":
			hasSecure = true
		case lower == "httponly":
			hasHTTPOnly = true
		case strings.HasPrefix(lower, "samesite="):
			value := strings.TrimSpace(strings.TrimPrefix(lower, "samesite="))
			if value == "strict" || value == "lax" || value == "none" {
				hasSameSite = true
			}
		}
	}

	switch {
	case !hasSecure:
		return false, "Cookie missing Secure flag"
	case !hasHTTPOnly:
		return false, "Cookie missing HttpOnly flag"
	case !hasSameSite:
		return false, "Cookie missing a valid SameSite attribute"
	default:
		return true, ""
	}
}
