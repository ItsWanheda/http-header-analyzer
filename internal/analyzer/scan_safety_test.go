package analyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ItsWanheda/http-header-analyzer/internal/models"
)

func TestAnalyzeHTTPMethodsOnlySendsOptions(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method)
		mu.Unlock()
		w.Header().Set("Allow", "GET, HEAD, OPTIONS, PUT, TRACE")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	a := &Analyzer{client: client}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got := a.analyzeHTTPMethods(ctx, server.URL)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != http.MethodOptions {
		t.Fatalf("probed methods = %v; want only OPTIONS", seen)
	}
	if !got.TraceEnabled || !got.PutEnabled {
		t.Fatalf("Allow header methods not reported: %+v", got)
	}
	if len(got.Dangerous) != 2 {
		t.Fatalf("dangerous advertised methods = %v; want PUT and TRACE", got.Dangerous)
	}
}

func TestCookieFindingsAreReportedIndividually(t *testing.T) {
	headers := make(http.Header)
	headers.Add("Set-Cookie", "session=good; Secure; HttpOnly; SameSite=Lax")
	headers.Add("Set-Cookie", "preference=weak; SameSite=Lax")

	results, issues := analyzeSecurityHeadersWithRules(headers)
	if len(results) != len(RuleRegistry)+1 {
		t.Fatalf("got %d header rows, want %d for two cookies", len(results), len(RuleRegistry)+1)
	}
	var cookieIssues []models.Issue
	for _, issue := range issues {
		if strings.HasPrefix(issue.Header, "Set-Cookie (") {
			cookieIssues = append(cookieIssues, issue)
		}
	}
	if len(cookieIssues) != 1 {
		t.Fatalf("got %d cookie-specific findings among %d total findings, want 1 cookie finding", len(cookieIssues), len(issues))
	}
	if cookieIssues[0].Header != "Set-Cookie (preference)" {
		t.Fatalf("finding header = %q, want cookie-specific name", cookieIssues[0].Header)
	}
}

func TestScoreTreatsMissingControlsAsFailuresAndNAChecksAsExcluded(t *testing.T) {
	emptyHeaders, _ := analyzeSecurityHeadersWithRules(make(http.Header))
	secure := make(http.Header)
	secure.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	secure.Set("Content-Security-Policy", "default-src 'self'; object-src 'none'")
	secure.Set("X-Content-Type-Options", "nosniff")
	secure.Set("X-Frame-Options", "DENY")
	secure.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	secure.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	secure.Add("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Lax")
	secureHeaders, _ := analyzeSecurityHeadersWithRules(secure)
	tls := models.TLSInfo{Evaluated: true, Valid: true, Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256"}

	gotEmpty := calculateScore(emptyHeaders, tls, true)
	gotSecure := calculateScore(secureHeaders, tls, true)
	if gotSecure <= gotEmpty {
		t.Fatalf("secure score %d should exceed missing-controls score %d", gotSecure, gotEmpty)
	}
	if got := calculateScore([]models.SecurityHeader{{Name:"Cookie Security", Status:"not_applicable"}}, models.TLSInfo{}, false); got != -1 {
		t.Fatalf("score without evaluated evidence = %d, want -1", got)
	}
	if got := calculateRating(-1); got != "N/A" {
		t.Fatalf("calculateRating(-1) = %q, want N/A", got)
	}
}
