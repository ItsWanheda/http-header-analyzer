package models

import (
    "time"
)

// Severity levels for security issues
type Severity string

const (
    SeverityCritical Severity = "Critical"
    SeverityHigh     Severity = "High"
    SeverityMedium   Severity = "Medium"
    SeverityLow      Severity = "Low"
)

// SecurityHeader represents a single security header analysis
type SecurityHeader struct {
    Name    string `json:"name"`
    Value   string `json:"value"`
    Present bool   `json:"present"`
    Status  string `json:"status"` // "pass", "warn", "fail"
    Message string `json:"message"`
}

// TLSInfo holds TLS configuration details
type TLSInfo struct {
    Version     string `json:"version"`
    CipherSuite string `json:"cipher_suite"`
    Certificate string `json:"certificate"`
    Valid       bool   `json:"valid"`
    ExpiresAt   string `json:"expires_at"`
    Subject     string `json:"subject"`
    Issuer      string `json:"issuer"`
}

// RedirectInfo holds redirect chain information
type RedirectInfo struct {
    StatusCode int    `json:"status_code"`
    Location   string `json:"location"`
    IsRedirect bool   `json:"is_redirect"`
}

// Issue represents a specific finding in the analysis
type Issue struct {
    Header      string     `json:"header"`
    Status      string     `json:"status"` // "pass", "fail", "warn"
    Severity    Severity   `json:"severity"`
    Explanation string     `json:"explanation"`
    Remediation string     `json:"remediation"`
}

// AnalysisResult is the complete analysis output
type AnalysisResult struct {
    URL             string             `json:"url"`
    Timestamp       time.Time          `json:"timestamp"`
    SecurityHeaders []SecurityHeader   `json:"security_headers"`
    TLS             TLSInfo            `json:"tls"`
    Redirects       []RedirectInfo     `json:"redirects"`
    Score           int                `json:"score"` // 0-100
    Rating          string             `json:"rating"` // "A+", "A", "B", etc.
    Issues          []Issue            `json:"issues"`
}