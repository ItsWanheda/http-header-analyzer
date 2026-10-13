package analyzer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"crypto/x509/pkix"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestAnalyzeWithContextWiresAllAssessmentResultsAndUsesSafeMethods(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "example.com"},
		Issuer: pkix.Name{CommonName: "Example Test CA"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24*time.Hour),
		DNSNames: []string{"example.com"},
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		methods = append(methods, req.Method)
		mu.Unlock()
		headers := make(http.Header)
		headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		headers.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		headers.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		headers.Add("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Lax")
		status, body := http.StatusOK, "<!doctype html><html><title>Example</title></html>"
		switch {
		case req.URL.Path == "/robots.txt":
			body = "User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml\n"
			headers.Set("Content-Type", "text/plain")
		case strings.HasSuffix(req.URL.Path, "/.well-known/security.txt"):
			status, body = http.StatusNotFound, ""
		case req.Method == http.MethodHead:
			body = ""
		case req.Method == http.MethodOptions:
			status, body = http.StatusNoContent, ""
			headers.Set("Allow", "GET, HEAD, OPTIONS")
			if origin := req.Header.Get("Origin"); origin != "" {
				headers.Set("Access-Control-Allow-Origin", origin)
				headers.Set("Access-Control-Allow-Credentials", "true")
				headers.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
				headers.Set("Vary", "Origin")
			}
		}
		response := &http.Response{
			StatusCode: status, Status: http.StatusText(status), Header: headers,
			Body: io.NopCloser(strings.NewReader(body)), Request: req,
			TLS: &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}},
		}
		return response, nil
	})}
	a := &Analyzer{client: client}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := a.AnalyzeWithContext(ctx, "https://example.com")
	if err != nil { t.Fatalf("AnalyzeWithContext returned error: %v", err) }

	if result.HTTPStatus != http.StatusOK { t.Fatalf("HTTP status = %d, want 200", result.HTTPStatus) }
	if result.DurationMS < 0 { t.Fatalf("duration should be non-negative, got %d", result.DurationMS) }
	if !result.Certificate.Present || !result.Certificate.MatchesTarget || !result.Certificate.ChainVerified || !result.Certificate.Valid { t.Fatalf("certificate analysis was not wired: %+v", result.Certificate) }
	if !result.Robots.Found || len(result.Robots.SensitivePaths) != 1 { t.Fatalf("robots analysis was not wired: %+v", result.Robots) }
	if !result.CSP.Present || result.CSP.Status != "pass" { t.Fatalf("CSP assessment was not wired: %+v", result.CSP) }
	if result.Score < 80 { t.Fatalf("secure fixture score = %d, want at least 80", result.Score) }
	if !result.CORS.Dangerous { t.Fatalf("origin reflection probe should be flagged: %+v", result.CORS) }

	mu.Lock()
	defer mu.Unlock()
	for _, method := range methods {
		if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
			t.Errorf("unsafe probe method %q was sent", method)
		}
	}
}
