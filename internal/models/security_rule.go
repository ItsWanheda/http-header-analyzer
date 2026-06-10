package models

// SecurityRule defines a single checkable security header or policy
type SecurityRule struct {
    Name         string          `json:"name"`
    HeaderName   string          `json:"header_name"` // The actual HTTP header to check
    Severity     Severity        `json:"severity"`
    Required     bool            `json:"required"`
    Explanation  string          `json:"explanation"`
    Remediation  string          `json:"remediation"`
    CheckLogic   func(value string) (bool, string) // Returns (isPass, messageIfFail)
}