package validation

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func ValidateURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("URL cannot be empty")
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("only http and https schemes are allowed")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("host cannot be empty")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("URL userinfo is not allowed")
	}
	if parsed.Fragment != "" {
		return "", fmt.Errorf("URL fragments are not allowed")
	}
	if isPrivateIP(parsed.Hostname()) {
		return "", fmt.Errorf("access to private or reserved IP addresses is not allowed")
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	return parsed.String(), nil
}

func isPrivateIP(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return !isPublicIP(ip)
}

func isPublicIP(ip net.IP) bool {
	return ip != nil &&
		!ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsUnspecified() &&
		!ip.IsMulticast()
}
