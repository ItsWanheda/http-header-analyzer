package analyzer

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/zharfatech/http-header-analyzer/internal/models"
)

const (
    defaultTimeout = 10 * time.Second
    maxRedirects   = 5
)

// Analyzer performs HTTP header analysis
type Analyzer struct {
    client *http.Client
}

// NewAnalyzer creates a new Analyzer instance
func NewAnalyzer() *Analyzer {
    return &Analyzer{
        client: &http.Client{
            Timeout:   defaultTimeout,
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                if len(via) >= maxRedirects {
                    return fmt.Errorf("too many redirects (%d)", maxRedirects)
                }
                return nil
            },
        },
    }
}

// Analyze performs a full analysis of the given URL
func (a *Analyzer) Analyze(targetURL string) (*models.AnalysisResult, error) {
    result := &models.AnalysisResult{
        URL:       targetURL,
        Timestamp: time.Now(),
    }

    // Perform the HTTP request
    resp, err := a.client.Get(targetURL)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch URL: %w", err)
    }
    defer resp.Body.Close()

    // Analyze security headers
    result.SecurityHeaders = analyzeSecurityHeaders(resp.Header)

    // Analyze TLS information
    result.TLS = analyzeTLS(resp)

    // Analyze redirects
    result.Redirects = a.analyzeRedirects(targetURL)

    // Calculate score and rating
    result.Score = calculateScore(result.SecurityHeaders, result.TLS, result.Redirects)
    result.Rating = calculateRating(result.Score)

    return result, nil
}

// AnalyzeWithContext performs analysis with a custom context
func (a *Analyzer) AnalyzeWithContext(ctx context.Context, targetURL string) (*models.AnalysisResult, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    resp, err := a.client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch URL: %w", err)
    }
    defer resp.Body.Close()

    result := &models.AnalysisResult{
        URL:       targetURL,
        Timestamp: time.Now(),
    }

    result.SecurityHeaders = analyzeSecurityHeaders(resp.Header)
    result.TLS = analyzeTLS(resp)
    result.Redirects = a.analyzeRedirects(targetURL)
    result.Score = calculateScore(result.SecurityHeaders, result.TLS, result.Redirects)
    result.Rating = calculateRating(result.Score)

    return result, nil
}