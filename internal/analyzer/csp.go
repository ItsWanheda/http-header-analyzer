package analyzer

import (
	"strings"

	"github.com/ItsWanheda/http-header-analyzer/internal/models"
)

// analyzeCSP parses a policy and reports conservative configuration risks.
// It performs no requests and never treats a missing policy as a successful check.
func analyzeCSP(policy string) models.CSPAnalysis {
	result := models.CSPAnalysis{Present: strings.TrimSpace(policy) != "", Status: "not_applicable"}
	if !result.Present {
		result.Message = "Content-Security-Policy is not present"
		return result
	}
	result.Status = "pass"
	directives := make(map[string][]string)
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 { continue }
		name := strings.ToLower(fields[0])
		if _, exists := directives[name]; exists {
			result.DuplicateDirectives = append(result.DuplicateDirectives, name)
			result.Warnings = append(result.Warnings, "Duplicate directive: "+name+" (later duplicates are ignored by browsers)")
			continue
		}
		values := make([]string, 0, len(fields)-1)
		for _, value := range fields[1:] { values = append(values, strings.ToLower(value)) }
		directives[name] = values
	}
	result.DirectiveCount = len(directives)
	sourceValues := append([]string{}, directives["script-src"]...)
	if len(sourceValues) == 0 { sourceValues = append(sourceValues, directives["default-src"]...) }
	for _, value := range sourceValues {
		if value == "'unsafe-inline'" { result.UnsafeInline = true }
		if value == "'unsafe-eval'" { result.UnsafeEval = true }
		if value == "*" { result.WildcardSource = true }
		if strings.HasPrefix(value, "http:") || strings.HasPrefix(value, "http://") { result.InsecureHTTPSource = true }
	}
	// Also catch wildcard and insecure schemes in other high-impact source lists.
	for _, name := range []string{"default-src", "script-src", "connect-src", "object-src"} {
		for _, value := range directives[name] {
			if value == "*" { result.WildcardSource = true }
			if strings.HasPrefix(value, "http:") || strings.HasPrefix(value, "http://") { result.InsecureHTTPSource = true }
		}
	}
	result.ObjectSrcRestricted = len(directives["object-src"]) == 1 && directives["object-src"][0] == "'none'"
	result.BaseURIConfigured = len(directives["base-uri"]) > 0
	result.FrameAncestorsConfigured = len(directives["frame-ancestors"]) > 0
	if _, ok := directives["default-src"]; !ok {
		result.Warnings = append(result.Warnings, "No default-src directive is configured")
	}
	if result.UnsafeInline { result.Warnings = append(result.Warnings, "script-src permits 'unsafe-inline' or inherits it from default-src") }
	if result.UnsafeEval { result.Warnings = append(result.Warnings, "script-src permits 'unsafe-eval' or inherits it from default-src") }
	if result.WildcardSource { result.Warnings = append(result.Warnings, "A wildcard source is allowed in a high-impact source directive") }
	if result.InsecureHTTPSource { result.Warnings = append(result.Warnings, "A source directive allows insecure HTTP resources") }
	if !result.ObjectSrcRestricted { result.Warnings = append(result.Warnings, "Set object-src 'none' unless legacy plugin content is explicitly required") }
	if !result.BaseURIConfigured { result.Warnings = append(result.Warnings, "Consider defining base-uri to reduce base-element injection risk") }
	if !result.FrameAncestorsConfigured { result.Warnings = append(result.Warnings, "Consider defining frame-ancestors to control embedding and clickjacking") }
	if result.UnsafeEval || result.WildcardSource {
		result.Status = "fail"
	} else if len(result.Warnings) > 0 {
		result.Status = "warn"
	}
	if len(result.Warnings) == 0 {
		result.Message = "No common high-risk CSP patterns detected"
	} else {
		result.Message = result.Warnings[0]
	}
	return result
}
