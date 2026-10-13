package analyzer

import (
	"net/http"
	"strings"
	"testing"
)

func TestAnalyzeCSPIdentifiesRiskyDirectives(t *testing.T) {
	got := analyzeCSP("default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' http:; object-src 'self'")
	if got.Status != "fail" { t.Fatalf("status = %q, want fail", got.Status) }
	if !got.UnsafeInline || !got.UnsafeEval || !got.WildcardSource || !got.InsecureHTTPSource {
		t.Fatalf("expected risky CSP features, got %+v", got)
	}
	if got.ObjectSrcRestricted || got.BaseURIConfigured || got.FrameAncestorsConfigured {
		t.Fatalf("expected missing/restrictive directives to be reported, got %+v", got)
	}
	if len(got.Warnings) < 5 { t.Fatalf("warnings = %v, want several configuration warnings", got.Warnings) }
}

func TestAnalyzeCSPAcceptsExplicitRestrictivePolicy(t *testing.T) {
	got := analyzeCSP("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
	if got.Status != "pass" || len(got.Warnings) != 0 {
		t.Fatalf("secure CSP status = %q, warnings = %v", got.Status, got.Warnings)
	}
	if got.DirectiveCount != 5 || !got.ObjectSrcRestricted || !got.BaseURIConfigured || !got.FrameAncestorsConfigured {
		t.Fatalf("unexpected CSP metrics: %+v", got)
	}
}

func TestAnalyzeCSPMissingPolicyIsNotApplicable(t *testing.T) {
	got := analyzeCSP("")
	if got.Present || got.Status != "not_applicable" { t.Fatalf("unexpected missing policy status: %+v", got) }
}

func TestCSPWarningIsNotCollapsedIntoHardFailure(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Content-Security-Policy", "default-src 'self'")
	results, issues := analyzeSecurityHeadersWithRules(headers)
	var found bool
	for _, result := range results {
		if result.Name == "Content-Security-Policy" {
			found = true
			if result.Status != "warn" {
				t.Fatalf("CSP status = %q, want warn", result.Status)
			}
			if result.Message == "" {
				t.Fatal("CSP warning should include an explanation")
			}
		}
	}
	if !found { t.Fatal("CSP row not found") }
	var cspIssue bool
	for _, issue := range issues {
		if issue.Header == "Content-Security-Policy" {
			cspIssue = true
			if issue.Status != "warn" { t.Fatalf("CSP issue status = %q, want warn", issue.Status) }
			if !strings.Contains(issue.Explanation, "Consider defining object-src") && !strings.Contains(issue.Explanation, "object-src") {
				t.Fatalf("CSP issue lacks evidence: %q", issue.Explanation)
			}
		}
	}
	if !cspIssue { t.Fatal("expected a CSP issue for a policy missing recommended directives") }
}

func TestNotApplicableOptionalHeadersDoNotCreateFindings(t *testing.T) {
	results, issues := analyzeSecurityHeadersWithRules(make(http.Header))
	for _, result := range results {
		if result.Status == "not_applicable" && result.Name == "Permissions-Policy" {
			for _, issue := range issues {
				if issue.Header == result.Name {
					t.Fatalf("not-applicable control unexpectedly emitted issue: %+v", issue)
				}
			}
			return
		}
	}
	t.Fatal("Permissions-Policy should be represented as not applicable when absent")
}
