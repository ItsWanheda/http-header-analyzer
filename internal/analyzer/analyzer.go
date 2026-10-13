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

	"github.com/ItsWanheda/http-header-analyzer/internal/models"
	"github.com/ItsWanheda/http-header-analyzer/internal/validation"
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
		Proxy:                 nil, // Do not delegate DNS or destination validation to an environment proxy.
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
		// Reject mixed public/private DNS answers rather than selecting only
		// the public answer; this makes rebinding and split-answer tricks fail closed.
		for _, candidate := range ips {
			if !validation.IsPublicIP(candidate.IP) {
				return nil, fmt.Errorf("target resolves to a private or reserved address")
			}
		}
		var lastErr error
		for _, candidate := range ips {
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr != nil {
			return nil, fmt.Errorf("could not connect to any public address: %w", lastErr)
		}
		return nil, fmt.Errorf("host has no usable IP addresses")
	}
}

func isPublicIP(ip net.IP) bool {
	return validation.IsPublicIP(ip)
}

func isSafeRemoteURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	_, err := validation.ValidateURL(u.String())
	return err == nil
}

func (a *Analyzer) Analyze(targetURL string) (*models.AnalysisResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return a.AnalyzeWithContext(ctx, targetURL)
}

func (a *Analyzer) AnalyzeWithContext(ctx context.Context, targetURL string) (*models.AnalysisResult, error) {
	startedAt := time.Now()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	validURL, err := validation.ValidateURL(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid or unsafe target URL: %w", err)
	}
	parsed, err := url.Parse(validURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL")
	}
	targetURL = parsed.String()

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

	finalURL := targetURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	result := &models.AnalysisResult{
		URL:        targetURL,
		FinalURL:   finalURL,
		Timestamp:  time.Now().UTC(),
		HTTPStatus: resp.StatusCode,
	}

	result.SecurityHeaders, result.Issues = analyzeSecurityHeadersWithRules(resp.Header)
	result.TLS = analyzeTLS(resp)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		result.Certificate = analyzeCertificate(finalURL, resp.TLS.PeerCertificates[0], len(resp.TLS.VerifiedChains) > 0)
	}
	result.Robots = analyzeRobots(ctx, a.client, targetURL)
	result.Redirects = a.analyzeRedirects(ctx, targetURL)
	result.CSP = analyzeCSP(resp.Header.Get("Content-Security-Policy"))
	result.HSTS = analyzeHSTS(resp.Header)
	result.SecurityTxt = a.analyzeSecurityTxt(ctx, targetURL)
	result.Technologies = detectTechnologies(resp.Header, string(bodyBytes))
	result.InformationLeaks = analyzeInformationDisclosure(resp.Header, string(bodyBytes))
	result.HTTPMethods = a.analyzeHTTPMethods(ctx, targetURL)
	result.CORS = a.analyzeCORSWithContext(ctx, targetURL, resp.Header)

	result.Score = calculateScore(result.SecurityHeaders, result.TLS, parsed.Scheme == "https")
	result.Rating = calculateRating(result.Score)
	result.DurationMS = time.Since(startedAt).Milliseconds()

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
					Name: rule.Name, Value: "N/A", Present: false, Status: "not_applicable",
					Message: "No cookies were set by this response",
				})
				continue
			}

			for _, cookie := range cookies {
				cookieName := strings.TrimSpace(strings.SplitN(cookie, "=", 2)[0])
				ok, message := rule.CheckLogic(cookie)
				status := "pass"
				if !ok {
					status = "fail"
				}
				rowName := "Cookie: " + cookieName
				results = append(results, models.SecurityHeader{
					Name: rowName, Value: cookie, Present: true, Status: status, Message: message,
				})
				if !ok {
					issues = append(issues, models.Issue{
						Header: "Set-Cookie (" + cookieName + ")", Status: status, Severity: rule.Severity,
						Explanation: rule.Explanation + " " + message, Remediation: rule.Remediation,
					})
				}
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
				status, message = "not_applicable", "Optional header is not set; applicability depends on the application"
			}
		} else if rule.HeaderName == "Content-Security-Policy" {
			assessment := analyzeCSP(value)
			switch assessment.Status {
			case "fail":
				status = "fail"
			case "warn":
				status = "warn"
			default:
				status = "pass"
			}
			message = assessment.Message
			if len(assessment.Warnings) > 0 {
				message = strings.Join(assessment.Warnings, "; ")
			}
		} else if ok, msg := rule.CheckLogic(value); !ok {
			status, message = "fail", msg
		}

		results = append(results, models.SecurityHeader{
			Name: rule.Name, Value: value, Present: present, Status: status, Message: message,
		})
		if status == "fail" || status == "warn" {
			issues = append(issues, models.Issue{
				Header: rule.HeaderName, Status: status, Severity: rule.Severity,
				Explanation: strings.TrimSpace(rule.Explanation + " " + message), Remediation: rule.Remediation,
			})
		}
	}

	return results, issues
}

func calculateScore(headers []models.SecurityHeader, tlsInfo models.TLSInfo, isHTTPS bool) int {
	var earned, possible int
	weightFor := func(name string) int {
		if strings.HasPrefix(name, "Cookie: ") {
			return 15
		}
		for _, rule := range RuleRegistry {
			if name == rule.Name {
				switch rule.Severity {
				case models.SeverityCritical:
					return 20
				case models.SeverityHigh:
					return 15
				case models.SeverityMedium:
					return 10
				default:
					return 5
				}
			}
		}
		return 10
	}
	for _, header := range headers {
		switch header.Status {
		case "pass", "warn", "fail":
			// Explicitly evaluated checks affect the score.
		default:
			// Not-applicable, unknown, and unevaluated checks are excluded.
			continue
		}
		weight := weightFor(header.Name)
		possible += weight
		switch header.Status {
		case "pass":
			earned += weight
		case "warn":
			earned += weight / 2
		case "fail":
			// Failed checks earn no points.
		}
	}
	if isHTTPS && tlsInfo.Evaluated {
		// TLS points are only awarded for evidence that was actually observed.
		if tlsInfo.Valid {
			possible += 10
			earned += 10
		} else {
			possible += 10
		}
		switch tlsInfo.Version {
		case "TLS 1.2", "TLS 1.3":
			possible += 10
			earned += 10
		case "TLS 1.0", "TLS 1.1":
			possible += 10
		}
		if tlsInfo.CipherSuite != "" && !strings.HasPrefix(tlsInfo.CipherSuite, "Unknown") {
			possible += 10
			if !isWeakCipher(tlsInfo.CipherSuite) {
				earned += 10
			}
		}
	}
	if possible == 0 {
		return -1
	}
	score := earned * 100 / possible
	if score > 100 {
		return 100
	}
	return score
}

func calculateRating(score int) string {
	if score < 0 {
		return "N/A"
	}
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
