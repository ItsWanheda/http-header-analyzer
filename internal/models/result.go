package models

import "time"

// Severity levels for security issues.
type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
)

type SecurityHeader struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Present bool   `json:"present"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type TLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	Certificate string `json:"certificate"`
	Valid       bool   `json:"valid"`
	ExpiresAt   string `json:"expires_at"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
}

type CertificateInfo struct {
	Present        bool     `json:"present"`
	Valid          bool     `json:"valid"`
	Subject        string   `json:"subject"`
	Issuer         string   `json:"issuer"`
	SerialNumber   string   `json:"serial_number"`
	NotBefore      string   `json:"not_before"`
	NotAfter       string   `json:"not_after"`
	DaysRemaining  int      `json:"days_remaining"`
	Signature      string   `json:"signature_algorithm"`
	PublicKey      string   `json:"public_key"`
	DNSNames       []string `json:"dns_names"`
	Wildcard       bool     `json:"wildcard"`
	MatchesTarget  bool     `json:"matches_target"`
}

type RobotsInfo struct {
	Found          bool     `json:"found"`
	URL            string   `json:"url"`
	StatusCode     int      `json:"status_code"`
	UserAgents     []string `json:"user_agents"`
	Disallowed     []string `json:"disallowed"`
	Allowed        []string `json:"allowed"`
	Sitemaps       []string `json:"sitemaps"`
	LineCount      int      `json:"line_count"`
	SensitivePaths []string `json:"sensitive_paths"`
}

type RedirectInfo struct {
	StatusCode int    `json:"status_code"`
	Location   string `json:"location"`
	IsRedirect bool   `json:"is_redirect"`
}

type Issue struct {
	Header      string   `json:"header"`
	Status      string   `json:"status"`
	Severity    Severity `json:"severity"`
	Explanation string   `json:"explanation"`
	Remediation string   `json:"remediation"`
}

type AnalysisResult struct {
	URL             string           `json:"url"`
	Timestamp       time.Time        `json:"timestamp"`
	SecurityHeaders []SecurityHeader `json:"security_headers"`
	TLS             TLSInfo          `json:"tls"`
	Certificate     CertificateInfo  `json:"certificate"`
	Robots          RobotsInfo       `json:"robots"`
	Redirects       []RedirectInfo   `json:"redirects"`
	Score           int              `json:"score"`
	Rating          string           `json:"rating"`
	Issues          []Issue          `json:"issues"`
}