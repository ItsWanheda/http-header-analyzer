package analyzer

import (
    "net/http"
    "strings"

    "github.com/zharfatech/http-header-analyzer/internal/models"
)

// expectedHeaders defines the security headers we check for
var expectedHeaders = map[string]struct {
    Required bool
    Checks   []func(string) string
}{
    "Strict-Transport-Security": {
        Required: true,
        Checks: []func(string) string{
            func(v string) string {
                if !strings.Contains(v, "max-age=") {
                    return "Missing max-age directive"
                }
                return ""
            },
            func(v string) string {
                if !strings.Contains(v, "includeSubDomains") {
                    return "Missing includeSubDomains directive"
                }
                return ""
            },
        },
    },
    "Content-Security-Policy": {
        Required: true,
        Checks: []func(string) string{
            func(v string) string {
                if !strings.Contains(v, "default-src") {
                    return "Missing default-src directive"
                }
                return ""
            },
            func(v string) string {
                if strings.Contains(v, "'unsafe-inline'") {
                    return "Contains unsafe-inline which is a security risk"
                }
                return ""
            },
        },
    },
    "X-Content-Type-Options": {
        Required: true,
        Checks: []func(string) string{
            func(v string) string {
                if !strings.EqualFold(v, "nosniff") {
                    return "Value should be 'nosniff'"
                }
                return ""
            },
        },
    },
    "X-Frame-Options": {
        Required: true,
        Checks: []func(string) string{
            func(v string) string {
                if !strings.EqualFold(v, "DENY") && !strings.EqualFold(v, "SAMEORIGIN") {
                    return "Value should be 'DENY' or 'SAMEORIGIN'"
                }
                return ""
            },
        },
    },
    "X-XSS-Protection": {
        Required: false,
        Checks: []func(string) string{
            func(v string) string {
                if !strings.Contains(v, "1") {
                    return "Should be set to '1; mode=block'"
                }
                return ""
            },
        },
    },
    "Referrer-Policy": {
        Required: true,
        Checks: []func(string) string{
            func(v string) string {
                validPolicies := []string{"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
                for _, p := range validPolicies {
                    if strings.EqualFold(v, p) {
                        return ""
                    }
                }
                return "Invalid or missing referrer policy"
            },
        },
    },
    "Permissions-Policy": {
        Required: false,
        Checks: []func(string) string{
            func(v string) string {
                if v == "" {
                    return "Missing permissions policy"
                }
                return ""
            },
        },
    },
    "Cache-Control": {
        Required: false,
        Checks: []func(string) string{
            func(v string) string {
                if strings.Contains(v, "no-store") {
                    return ""
                }
                return "Consider adding no-store for sensitive data"
            },
        },
    },
}

// analyzeSecurityHeaders analyzes the security headers in the response
func analyzeSecurityHeaders(headers http.Header) []models.SecurityHeader {
    var results []models.SecurityHeader

    for headerName, config := range expectedHeaders {
        value := headers.Get(headerName)
        present := value != ""

        status := "pass"
        message := ""

        if !present {
            if config.Required {
                status = "fail"
                message = "Required header is missing"
            } else {
                status = "warn"
                message = "Optional header is missing"
            }
        } else {
            // Run all checks
            for _, check := range config.Checks {
                if msg := check(value); msg != "" {
                    status = "warn"
                    message = msg
                    break
                }
            }
        }

        results = append(results, models.SecurityHeader{
            Name:    headerName,
            Value:   value,
            Present: present,
            Status:  status,
            Message: message,
        })
    }

    return results
}

// calculateScore calculates the overall security score
func calculateScore(headers []models.SecurityHeader, tls models.TLSInfo, redirects []models.RedirectInfo) int {
    score := 0
    maxScore := 0

    // Security headers scoring (60 points total)
    for _, h := range headers {
        if !h.Present {
            continue
        }
        maxScore += 10
        switch h.Status {
        case "pass":
            score += 10
        case "warn":
            score += 5
        case "fail":
            // 0 points
        }
    }

    // TLS scoring (30 points)
    maxScore += 30
    if tls.Valid {
        score += 15
    }
    if tls.Version != "" && (strings.Contains(tls.Version, "TLSv1.2") || strings.Contains(tls.Version, "TLSv1.3")) {
        score += 10
    }
    if !strings.Contains(strings.ToLower(tls.CipherSuite), "rc4") &&
        !strings.Contains(strings.ToLower(tls.CipherSuite), "des") &&
        !strings.Contains(strings.ToLower(tls.CipherSuite), "null") {
        score += 5
    }

    // Redirect scoring (10 points)
    maxScore += 10
    if len(redirects) == 0 {
        score += 10
    } else {
        score += 5
    }

    // Normalize to 0-100
    if maxScore > 0 {
        score = (score * 100) / maxScore
    }

    return score
}

// calculateRating converts a score to a letter grade
func calculateRating(score int) string {
    switch {
    case score >= 95:
        return "A+"
    case score >= 85:
        return "A"
    case score >= 70:
        return "B"
    case score >= 55:
        return "C"
    case score >= 40:
        return "D"
    default:
        return "F"
    }
}