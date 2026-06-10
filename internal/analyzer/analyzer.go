package analyzer

import (
    "context"
    "fmt"
    "net/http"
    "strings"
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
    return a.AnalyzeWithContext(context.Background(), targetURL)
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

    // 1. Analyze Security Headers using Rule Engine
    result.SecurityHeaders, result.Issues = analyzeSecurityHeadersWithRules(resp.Header)

    // 2. Analyze TLS information
    result.TLS = analyzeTLS(resp)

    // 3. Analyze redirects
    result.Redirects = a.analyzeRedirects(targetURL)

    // 4. Calculate score and rating
    result.Score = calculateScore(result.SecurityHeaders, result.TLS, result.Redirects)
    result.Rating = calculateRating(result.Score)

    return result, nil
}

// analyzeSecurityHeadersWithRules iterates through the RuleRegistry and applies checks
func analyzeSecurityHeadersWithRules(headers http.Header) ([]models.SecurityHeader, []models.Issue) {
    var securityHeaders []models.SecurityHeader
    var issues []models.Issue

    for _, rule := range RuleRegistry {
        // Get header value. For Set-Cookie, we might have multiple, so we join them or take the first relevant one.
        // For simplicity in this engine, we take the first value or join if needed.
        value := headers.Get(rule.HeaderName)
        
        // Special handling for Set-Cookie: check all of them
        if rule.HeaderName == "Set-Cookie" {
            cookies := headers.Values("Set-Cookie")
            // We will check each cookie individually or combine them. 
            // For this implementation, let's check the first one as a representative, 
            // or iterate if you want strictness. Let's iterate for thoroughness.
            allCookiesPass := true
            var failMsg string
            
            for _, cookie := range cookies {
                pass, msg := rule.CheckLogic(cookie)
                if !pass {
                    allCookiesPass = false
                    failMsg = msg
                    break // Fail on first bad cookie for simplicity
                }
            }
            
            // If no cookies found, it's not a fail for optional rules, but maybe a warn?
            // Let's treat missing cookies as a pass for the rule itself if it's optional, 
            // or just skip if no cookies are present.
            if len(cookies) == 0 {
                // No cookies set, rule doesn't apply or passes
                securityHeaders = append(securityHeaders, models.SecurityHeader{
                    Name:    rule.Name,
                    Value:   "N/A",
                    Present: false,
                    Status:  "pass", // Or "warn" if you want to flag lack of cookies
                    Message: "No cookies set",
                })
                continue
            }

            status := "pass"
            message := ""
            if !allCookiesPass {
                status = "fail"
                message = failMsg
            }

            securityHeaders = append(securityHeaders, models.SecurityHeader{
                Name:    rule.Name,
                Value:   cookies[0], // Show first cookie for display
                Present: true,
                Status:  status,
                Message: message,
            })

            // Add to issues if fail or warn
            if status != "pass" {
                issues = append(issues, models.Issue{
                    Header:      rule.HeaderName,
                    Status:      status,
                    Severity:    rule.Severity,
                    Explanation: rule.Explanation,
                    Remediation: rule.Remediation,
                })
            }
            continue
        }

        // Standard Header Check
        present := value != ""
        status := "pass"
        message := ""

        if !present {
            if rule.Required {
                status = "fail"
                message = "Required header is missing"
            } else {
                status = "warn"
                message = "Optional header is missing"
            }
        } else {
            // Run the rule's check logic
            pass, checkMsg := rule.CheckLogic(value)
            if !pass {
                status = "warn" // Or "fail" depending on severity
                message = checkMsg
            }
        }

        securityHeaders = append(securityHeaders, models.SecurityHeader{
            Name:    rule.Name,
            Value:   value,
            Present: present,
            Status:  status,
            Message: message,
        })

        // Add to issues if not pass
        if status != "pass" {
            issues = append(issues, models.Issue{
                Header:      rule.HeaderName,
                Status:      status,
                Severity:    rule.Severity,
                Explanation: rule.Explanation,
                Remediation: rule.Remediation,
            })
        }
    }

    return securityHeaders, issues
}

// calculateScore calculates the overall security score
func calculateScore(headers []models.SecurityHeader, tls models.TLSInfo, redirects []models.RedirectInfo) int {
    score := 0
    maxScore := 0

    // Security headers scoring (60 points total)
    for _, h := range headers {
        if !h.Present && h.Status == "warn" {
            // Optional headers missing don't deduct, but don't add
            continue
        }
        if !h.Present {
            continue
        }
        maxScore += 10
        switch h.Status {
        case "pass":
            score += 10
        case "warn":
            score += 5
        case "fail":
            // 0 points
        }
    }

    // TLS scoring (30 points)
    maxScore += 30
    if tls.Valid {
        score += 15
    }
    if tls.Version != "" && (strings.Contains(tls.Version, "TLSv1.2") || strings.Contains(tls.Version, "TLSv1.3")) {
        score += 10
    }
    if !strings.Contains(strings.ToLower(tls.CipherSuite), "rc4") &&
        !strings.Contains(strings.ToLower(tls.CipherSuite), "des") &&
        !strings.Contains(strings.ToLower(tls.CipherSuite), "null") {
        score += 5
    }

    // Redirect scoring (10 points)
    maxScore += 10
    if len(redirects) == 0 {
        score += 10
    } else {
        score += 5
    }

    // Normalize to 0-100
    if maxScore > 0 {
        score = (score * 100) / maxScore
    }
    return score
}

// calculateRating converts a score to a letter grade
func calculateRating(score int) string {
    switch {
    case score >= 95:
        return "A+"
    case score >= 85:
        return "A"
    case score >= 70:
        return "B"
    case score >= 55:
        return "C"
    case score >= 40:
        return "D"
    default:
        return "F"
    }
}