package analyzer

import (
    "strings"
    "github.com/zharfatech/http-header-analyzer/internal/models"
)

// RuleRegistry holds all defined security rules
var RuleRegistry = []models.SecurityRule{
    // HSTS
    {
        Name:         "Strict-Transport-Security",
        HeaderName:   "Strict-Transport-Security",
        Severity:     models.SeverityCritical,
        Required:     true,
        Explanation:  "HSTS ensures browsers only connect via HTTPS.",
        Remediation:  "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        CheckLogic: func(v string) (bool, string) {
            if !strings.Contains(v, "max-age=") {
                return false, "Missing max-age directive"
            }
            if !strings.Contains(v, "includeSubDomains") {
                return false, "Missing includeSubDomains directive"
            }
            return true, ""
        },
    },
    // CSP
    {
        Name:         "Content-Security-Policy",
        HeaderName:   "Content-Security-Policy",
        Severity:     models.SeverityHigh,
        Required:     true,
        Explanation:  "CSP prevents XSS and data injection attacks.",
        Remediation:  "Implement a strict CSP with 'default-src 'self''.",
        CheckLogic: func(v string) (bool, string) {
            if !strings.Contains(v, "default-src") {
                return false, "Missing default-src directive"
            }
            if strings.Contains(v, "'unsafe-inline'") {
                return false, "Contains unsafe-inline which is a security risk"
            }
            return true, ""
        },
    },
    // X-Content-Type-Options
    {
        Name:         "X-Content-Type-Options",
        HeaderName:   "X-Content-Type-Options",
        Severity:     models.SeverityMedium,
        Required:     true,
        Explanation:  "Prevents MIME-type sniffing.",
        Remediation:  "Set 'X-Content-Type-Options: nosniff'.",
        CheckLogic: func(v string) (bool, string) {
            if !strings.EqualFold(v, "nosniff") {
                return false, "Value should be 'nosniff'"
            }
            return true, ""
        },
    },
    // X-Frame-Options
    {
        Name:         "X-Frame-Options",
        HeaderName:   "X-Frame-Options",
        Severity:     models.SeverityMedium,
        Required:     true,
        Explanation:  "Prevents Clickjacking attacks.",
        Remediation:  "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
        CheckLogic: func(v string) (bool, string) {
            if !strings.EqualFold(v, "DENY") && !strings.EqualFold(v, "SAMEORIGIN") {
                return false, "Value should be 'DENY' or 'SAMEORIGIN'"
            }
            return true, ""
        },
    },
    // Cookie Analysis (Special Case)
    {
        Name:         "Cookie Security",
        HeaderName:   "Set-Cookie", // We will parse all Set-Cookie headers
        Severity:     models.SeverityHigh,
        Required:     false, // Only applies if cookies are set
        Explanation:  "Cookies should be Secure, HttpOnly, and SameSite.",
        Remediation:  "Ensure cookies have Secure, HttpOnly, and SameSite=Strict/Lax flags.",
        CheckLogic:  CheckCookieSecurity,
    },
}

// CheckCookieSecurity parses Set-Cookie headers and validates flags
func CheckCookieSecurity(cookieString string) (bool, string) {
    // Note: In a real multi-header scenario, you might need to iterate over headers.Values()
    // Here we assume the input is the raw Set-Cookie value or concatenated values.
    
    // Split by comma if multiple cookies are sent in one header (rare but possible)
    // Usually, Set-Cookie headers are separate. We'll treat the input as one cookie string for this example.
    
    // Check for Secure
    if !strings.Contains(strings.ToLower(cookieString), "secure") {
        return false, "Cookie missing 'Secure' flag"
    }
    
    // Check for HttpOnly
    if !strings.Contains(strings.ToLower(cookieString), "httponly") {
        return false, "Cookie missing 'HttpOnly' flag"
    }
    
    // Check for SameSite
    if !strings.Contains(strings.ToLower(cookieString), "samesite") {
        return false, "Cookie missing 'SameSite' flag"
    }
    
    return true, ""
}