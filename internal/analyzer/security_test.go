package analyzer

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCheckCookieSecurity(t *testing.T) {
	tests := []struct {
		name string
		cookie string
		want bool
	}{
		{"secure cookie", "session=abc; Secure; HttpOnly; SameSite=Lax", true},
		{"insecure value is not Secure flag", "session=insecure; HttpOnly; SameSite=Lax", false},
		{"missing httponly", "session=abc; Secure; SameSite=Lax", false},
		{"missing samesite", "session=abc; Secure; HttpOnly", false},
		{"invalid samesite", "session=abc; Secure; HttpOnly; SameSite=invalid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := CheckCookieSecurity(tt.cookie)
			if got != tt.want {
				t.Fatalf("CheckCookieSecurity(%q) = %v, want %v", tt.cookie, got, tt.want)
			}
		})
	}
}

func TestAnalyzeSecurityHeadersMissingRequired(t *testing.T) {
	headers := make(http.Header)
	results, issues := analyzeSecurityHeadersWithRules(headers)

	if len(results) != len(RuleRegistry) {
		t.Fatalf("got %d results, want %d", len(results), len(RuleRegistry))
	}
	if len(issues) < 4 {
		t.Fatalf("got %d issues, want at least 4", len(issues))
	}
}

func TestIsSafeRemoteURL(t *testing.T) {
	tests := map[string]bool{
		"https://example.com": true,
		"http://127.0.0.1": false,
		"http://[::1]": false,
		"http://192.168.1.1": false,
		"http://localhost": false,
		"ftp://example.com": false,
	}
	for raw, want := range tests {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		if got := isSafeRemoteURL(u); got != want {
			t.Errorf("isSafeRemoteURL(%q) = %v, want %v", raw, got, want)
		}
	}
}
