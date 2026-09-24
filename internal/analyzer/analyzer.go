package analyzer

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zharfatech/http-header-analyzer/internal/models"
)

const (
	defaultTimeout = 10 * time.Second
	maxRedirects   = 5
	maxBodySize    = 2 * 1024 * 1024
	userAgent      = "HTTP-Header-Analyzer/1.1"
)

type Analyzer struct {
	client *http.Client
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		client: newSafeHTTPClient(),
	}
}

func newSafeHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:            safeDialContext(dialer),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   defaultTimeout,
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("too many redirects (maximum %d)", maxRedirects)
		}
		if req.URL == nil || !isSafeRemoteURL(req.URL) {
			return fmt.Errorf("redirect target is not allowed")
		}
		return nil
	}

	return client
}

func safeDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid target address: %w", err)
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed: %w", err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("host has no IP addresses")
		}

		for _, ip := range ips {
			if !isPublicIP(ip.IP) {
				continue
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		}

		return nil, fmt.Errorf("target resolves only to private or reserved addresses")
	}
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsUnspecified() &&
		!ip.IsMulticast()
}

func isSafeRemoteURL(u *url.URL) bool {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return false
	}
	host := strings.Trim(u.Hostname(), "[]")
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return isPublicIP(ip)
	}
	return true
}

func (a *Analyzer) Analyze(targetURL string) (*models.AnalysisResult, error) {
	return a.AnalyzeWithContext(context.Background(), targetURL)
}

func (a *Analyzer) AnalyzeWithContext(ctx context.Context, targetURL string) (*models.AnalysisResult, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil || !isSafeRemoteURL(parsed) {
		return nil, fmt.Errorf("invalid or unsafe target URL")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	result := &models.AnalysisResult{
		URL:       targetURL,
		Timestamp: time.Now().UTC(),
	}

	result.SecurityHeaders, result.Issues = analyzeSecurityHeadersWithRules(resp.Header)
	result.TLS = analyzeTLS(resp)
	result.Redirects = a.analyzeRedirects(targetURL)
	result.HSTS = analyzeHSTS(resp.Header)
	result.SecurityTxt = a.analyzeSecurityTxt(ctx, targetURL)
	result.Technologies = detectTechnologies(resp.Header, string(bodyBytes))
	result.InformationLeaks = analyzeInformationDisclosure(resp.Header, string(bodyBytes))
	result.HTTPMethods = a.analyzeHTTPMethods(ctx, targetURL)
	result.CORS = analyzeCORS(resp.Header)

	result.Score = calculateScore(result.SecurityHeaders, result.TLS, result.Redirects)
	result.Rating = calculateRating(result.Score)

	return result, nil
}

func analyzeSecurityHeadersWithRules(headers http.Header) ([]models.SecurityHeader, []models.Issue) {
	results := make([]models.SecurityHeader, 0, len(RuleRegistry))
	issues := make([]models.Issue, 0)

	for _, rule := range RuleRegistry {
		if rule.HeaderName == "Set-Cookie" {
			cookies := headers.Values("Set-Cookie")
			if len(cookies) == 0 {
				results = append(results, models.SecurityHeader{
					Name: rule.Name, Value: "N/A", Present: false, Status: "pass",
					Message: "No cookies set",
				})
				continue
			}

			status, message := "pass", ""
			for _, cookie := range cookies {
				if ok, msg := rule.CheckLogic(cookie); !ok {
					status, message = "fail", msg
					break
				}
			}

			results = append(results, models.SecurityHeader{
				Name: rule.Name, Value: cookies[0], Present: true, Status: status, Message: message,
			})
			if status != "pass" {
				issues = append(issues, models.Issue{
					Header: rule.HeaderName, Status: status, Severity: rule.Severity,
					Explanation: rule.Explanation, Remediation: rule.Remediation,
				})
			}
			continue
		}

		value := headers.Get(rule.HeaderName)
		present := value != ""
		status, message := "pass", ""

		if !present {
			if rule.Required {
				status, message = "fail", "Required header is missing"
			} else {
				status, message = "warn", "Optional header is missing"
			}
		} else if ok, msg := rule.CheckLogic(value); !ok {
			status, message = "warn", msg
		}

		results = append(results, models.SecurityHeader{
			Name: rule.Name, Value: value, Present: present, Status: status, Message: message,
		})
		if status != "pass" {
			issues = append(issues, models.Issue{
				Header: rule.HeaderName, Status: status, Severity: rule.Severity,
				Explanation: rule.Explanation, Remediation: rule.Remediation,
			})
		}
	}

	return results, issues
}

func calculateScore(headers []models.SecurityHeader, tlsInfo models.TLSInfo, redirects []models.RedirectInfo) int {
	score, maxScore := 0, 0

	for _, h := range headers {
		if !h.Present {
			continue
		}
		maxScore += 10
		switch h.Status {
		case "pass":
			score += 10
		case "warn":
			score += 5
		}
	}

	maxScore += 30
	if tlsInfo.Valid {
		score += 15
	}
	if tlsInfo.Version == "TLS 1.2" || tlsInfo.Version == "TLS 1.3" {
		score += 10
	}
	if !isWeakCipher(tlsInfo.CipherSuite) {
		score += 5
	}

	maxScore += 10
	if len(redirects) == 0 {
		score += 10
	} else {
		score += 5
	}

	if maxScore == 0 {
		return 0
	}
	score = score * 100 / maxScore
	if score > 100 {
		return 100
	}
	return score
}

func calculateRating(score int) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 73:
		return "C"
	case score >= 70:
		return "C-"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}
