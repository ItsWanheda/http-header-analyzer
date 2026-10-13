package analyzer

import "testing"

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
