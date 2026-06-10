package analyzer

import (
    "net/http"
    "github.com/zharfatech/http-header-analyzer/internal/models"
)

// analyzeSecurityHeaders analyzes the security headers in the response
// Note: This function is now largely replaced by analyzeSecurityHeadersWithRules in analyzer.go
// We keep this for backward compatibility or if you want to use the old map-based approach elsewhere.
// However, for this refactor, we will primarily use the Rule Engine.
func analyzeSecurityHeaders(headers http.Header) []models.SecurityHeader {
    var results []models.SecurityHeader
    // This function is kept for reference but the main logic is in analyzer.go
    // If you still want to use this, ensure it doesn't conflict with the new engine.
    // For now, let's just return an empty slice or call the new engine.
    // To avoid confusion, let's remove the old logic and rely on the new engine.
    return results
}