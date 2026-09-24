package validation

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateURL validates an HTTP(S) target and rejects local/reserved addresses
// commonly associated with SSRF attacks.
func ValidateURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("URL cannot be empty")
	}

	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %w", err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("only http and https schemes are allowed")
	}

	if parsedURL.Host == "" || parsedURL.Hostname() == "" {
		return "", fmt.Errorf("host cannot be empty")
	}

	if isPrivateIP(parsedURL.Hostname()) {
		return "", fmt.Errorf("access to private or reserved IP addresses is not allowed")
	}

	return parsedURL.String(), nil
}

// isPrivateIP rejects IP literals that should never be used as remote scan targets.
func isPrivateIP(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}
