package validation

import (
    "fmt"
    "net/url"
    "strings"
)

// ValidateURL checks if the provided URL is valid and safe to analyze
func ValidateURL(rawURL string) (string, error) {
    if rawURL == "" {
        return "", fmt.Errorf("URL cannot be empty")
    }

    // Add https:// if no scheme is present
    if !strings.Contains(rawURL, "://") {
        rawURL = "https://" + rawURL
    }

    parsedURL, err := url.Parse(rawURL)
    if err != nil {
        return "", fmt.Errorf("invalid URL format: %w", err)
    }

    // Only allow http and https schemes
    if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
        return "", fmt.Errorf("only http and https schemes are allowed")
    }

    // Check host is not empty
    if parsedURL.Host == "" {
        return "", fmt.Errorf("host cannot be empty")
    }

    // Check for potential SSRF attempts
    host := parsedURL.Hostname()
    if isPrivateIP(host) {
        return "", fmt.Errorf("access to private IP addresses is not allowed")
    }

    return parsedURL.String(), nil
}

// isPrivateIP checks if the host is a private/reserved IP address
func isPrivateIP(host string) bool {
    privatePrefixes := []string{
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.",
        "127.",
        "0.",
        "localhost",
    }

    for _, prefix := range privatePrefixes {
        if strings.HasPrefix(host, prefix) {
            return true
        }
    }
    return false
}