package analyzer

import (
	"net/http"
	"testing"
)

func TestAnalyzeSecurityHeadersWithRules(t *testing.T) {
	headers := http.Header{}
	headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	headers.Set("Content-Security-Policy", "default-src 'self'")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Add("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Lax")

	results, issues := analyzeSecurityHeadersWithRules(headers)

	if len(results) != len(RuleRegistry) {
		t.Fatalf("got %d security header results, want %d", len(results), len(RuleRegistry))
	}
	if len(issues) != 0 {
		t.Fatalf("got %d issues for secure headers, want 0", len(issues))
	}

	for _, result := range results {
		if result.Status != "pass" {
			t.Errorf("%s status = %q, want pass", result.Name, result.Status)
		}
	}
}

func TestCalculateRating(t *testing.T) {
	tests := map[int]string{
		100: "A+",
		95:  "A",
		90:  "A-",
		85:  "B",
		75:  "C",
		65:  "D",
		40:  "F",
	}

	for score, want := range tests {
		if got := calculateRating(score); got != want {
			t.Errorf("calculateRating(%d) = %q, want %q", score, got, want)
		}
	}
}
