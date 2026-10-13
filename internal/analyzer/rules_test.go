package analyzer

import (
	"net/http"
	"testing"
)

func TestAnalyzeSecurityHeadersWithRules(t *testing.T) {
	headers := http.Header{}
	headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	headers.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	headers.Add("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Lax")

	results, issues := analyzeSecurityHeadersWithRules(headers)

	if len(results) != len(RuleRegistry) {
		t.Fatalf("got %d security header results, want %d", len(results), len(RuleRegistry))
	}
	if len(issues) != 0 {
		t.Fatalf("got %d issues for secure headers, want 0", len(issues))
	}

	for _, result := range results {
		if result.Status != "pass" && result.Status != "not_applicable" {
			t.Errorf("%s status = %q, want pass or not_applicable", result.Name, result.Status)
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

func TestHSTSScoringDistinguishesDisabledAndWeakMaxAge(t *testing.T) {
	tests := []struct {
		name, value, want string
	}{
		{name: "disabled", value: "max-age=0; includeSubDomains", want: "fail"},
		{name: "short", value: "max-age=604800; includeSubDomains", want: "warn"},
		{name: "strong", value: "max-age=31536000; includeSubDomains", want: "pass"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set("Strict-Transport-Security", tt.value)
			results, _ := analyzeSecurityHeadersWithRules(headers)
			for _, result := range results {
				if result.Name == "Strict-Transport-Security" {
					if result.Status != tt.want { t.Fatalf("HSTS status = %q, want %q", result.Status, tt.want) }
					return
				}
			}
			t.Fatal("HSTS security header row not found")
		})
	}
}
