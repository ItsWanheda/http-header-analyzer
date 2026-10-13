package validation

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

var blockedNetworks = mustParseNetworks([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001::/23",
	"2001:db8::/32", "2002::/16", "5f00::/16", "fc00::/7",
	"fe80::/10", "ff00::/8",
})

func mustParseNetworks(cidrRanges []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrRanges))
	for _, cidr := range cidrRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid built-in CIDR range: " + cidr)
		}
		networks = append(networks, network)
	}
	return networks
}

// IsPublicIP is deliberately conservative: special-use, private, and non-global
// destinations are rejected before the scanner opens an outbound connection.
func IsPublicIP(ip net.IP) bool {
	if ip == nil { return false }
	if ipv4 := ip.To4(); ipv4 != nil { ip = ipv4 }
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		!ip.IsGlobalUnicast() {
		return false
	}
	for _, network := range blockedNetworks {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

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
	parsed.Scheme = strings.ToLower(parsed.Scheme)
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

	host := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(parsed.Hostname()), "."), ".")
	if host == "" || strings.Contains(host, "%") || host == "localhost" ||
		strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".test") ||
		strings.HasSuffix(host, ".invalid") ||
		strings.HasSuffix(host, ".example") {
		return "", fmt.Errorf("local or reserved hostnames are not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && !IsPublicIP(ip) {
		return "", fmt.Errorf("private, reserved, or non-public IP addresses are not allowed")
	}

	port := parsed.Port()
	if port != "" {
		expectedPort := "80"
		if parsed.Scheme == "https" {
			expectedPort = "443"
		}
		if port != expectedPort {
			return "", fmt.Errorf("only the default port for the selected scheme is allowed")
		}
	}

	parsed.Host = strings.TrimSuffix(parsed.Host, ".")
	return parsed.String(), nil
}
