package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zharfatech/http-header-analyzer/internal/models"
 )

func testResult(score int, severities ...models.Severity) *models.AnalysisResult {
	issues := make([]models.Issue, 0, len(severities))
	for _, severity := range severities {
		issues = append(issues, models.Issue{Severity: severity, Header: "test", Explanation: "test issue"})
	}
	return &models.AnalysisResult{URL: "https://example.com", Timestamp: time.Unix(0, 0).UTC(), Score: score, Rating: "B", TLS: models.TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_AES_256_GCM_SHA384", Certificate: "valid", Valid: true}, Issues: issues}
}

func withTestAnalyzer(result *models.AnalysisResult, err error) func() {
	original := analyzeTarget
	analyzeTarget = func(context.Context, string) (*models.AnalysisResult, error) { return result, err }
	return func() { analyzeTarget = original }
}

func TestParseFailOn(t *testing.T) {
	tests := []struct { input string; want models.Severity; ok bool }{
		{"", "", true}, {"critical", models.SeverityCritical, true}, {"HIGH", models.SeverityHigh, true}, {"medium", models.SeverityMedium, true}, {" low ", models.SeverityLow, true}, {"info", "", false},
	}
	for _, tt := range tests { got, err := parseFailOn(tt.input); if (err == nil) != tt.ok || got != tt.want { t.Fatalf("parseFailOn(%q) = %q, err=%v; want %q, ok=%v", tt.input, got, err, tt.want, tt.ok) } }
}

func TestHasIssueAtOrAbove(t *testing.T) {
	issues := []models.Issue{{Severity: models.SeverityHigh}, {Severity: models.SeverityLow}}
	if hasIssueAtOrAbove(issues, models.SeverityCritical) { t.Fatal("unexpected critical match") }
	if !hasIssueAtOrAbove(issues, models.SeverityHigh) { t.Fatal("high severity should match") }
	if !hasIssueAtOrAbove(issues, models.SeverityMedium) { t.Fatal("high severity should satisfy medium threshold") }
}

func TestCLIQualityGates(t *testing.T) {
	tests := []struct { name string; args []string; result *models.AnalysisResult; wantErr bool }{
		{"minimum score passes", []string{"scan", "https://example.com", "--min-score", "80"}, testResult(85), false},
		{"minimum score fails", []string{"scan", "https://example.com", "--min-score", "90"}, testResult(85), true},
		{"fail-on passes", []string{"scan", "https://example.com", "--fail-on", "high"}, testResult(90, models.SeverityMedium), false},
		{"fail-on fails", []string{"scan", "--fail-on", "high", "https://example.com"}, testResult(90, models.SeverityHigh), true},
		{"both gates pass", []string{"scan", "https://example.com", "--min-score", "80", "--fail-on", "critical"}, testResult(90, models.SeverityHigh), false},
		{"both gates fail", []string{"scan", "https://example.com", "--min-score", "95", "--fail-on", "high"}, testResult(90, models.SeverityHigh), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := withTestAnalyzer(tt.result, nil); defer restore()
			var stdout, stderr bytes.Buffer
			err := run(tt.args, &stdout, &stderr)
			if (err != nil) != tt.wantErr { t.Fatalf("run() error=%v, wantErr=%v; stderr=%q", err, tt.wantErr, stderr.String()) }
			if !strings.Contains(stdout.String(), "Score:") { t.Fatalf("expected scan output, got %q", stdout.String()) }
		})
	}
}

func TestCLIFailsOnAnalyzerError(t *testing.T) {
	restore := withTestAnalyzer(nil, errors.New("scan failed")); defer restore()
	var stdout, stderr bytes.Buffer
	err := run([]string{"scan", "https://example.com"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "scan failed") { t.Fatalf("run() error = %v, want scan failure", err) }
}

func TestCLIJSONOutput(t *testing.T) {
	restore := withTestAnalyzer(testResult(88, models.SeverityLow), nil); defer restore()
	var stdout, stderr bytes.Buffer
	err := run([]string{"scan", "https://example.com", "--json"}, &stdout, &stderr)
	if err != nil { t.Fatalf("run() error = %v", err) }
	if !strings.Contains(stdout.String(), `"score": 88`) { t.Fatalf("expected JSON score, got %q", stdout.String()) }
	if !strings.Contains(stdout.String(), `"issues"`) { t.Fatalf("expected JSON issues, got %q", stdout.String()) }
}

func TestCLIRejectsInvalidQualityGate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"scan", "https://example.com", "--min-score", "101"}, &stdout, &stderr); err == nil { t.Fatal("expected invalid min-score error") }
	if err := run([]string{"scan", "https://example.com", "--fail-on", "info"}, &stdout, &stderr); err == nil { t.Fatal("expected invalid fail-on error") }
}
