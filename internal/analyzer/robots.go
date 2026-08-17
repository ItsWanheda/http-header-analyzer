package analyzer

import (
	"bufio"
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/zharfatech/http-header-analyzer/internal/models"
)

func analyzeRobots(
	ctx context.Context,
	client *http.Client,
	targetURL string,
) models.RobotsInfo {

	result := models.RobotsInfo{}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return result
	}

	robotsURL := strings.TrimRight(
		parsed.Scheme+"://"+parsed.Host,
		"/",
	) + "/robots.txt"

	result.URL = robotsURL

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		robotsURL,
		nil,
	)
	if err != nil {
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		return result
	}

	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	if resp.StatusCode != http.StatusOK {
		return result
	}

	result.Found = true

	scanner := bufio.NewScanner(resp.Body)

	var currentUserAgent string

	for scanner.Scan() {
		line := strings.TrimSpace(
			scanner.Text(),
		)

		result.LineCount++

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(
			line,
			":",
			2,
		)

		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(
			strings.TrimSpace(parts[0]),
		)

		value := strings.TrimSpace(
			parts[1],
		)

		switch key {

		case "user-agent":
			currentUserAgent = value

			if !containsIgnoreCase(
				result.UserAgents,
				value,
			) {
				result.UserAgents =
					append(
						result.UserAgents,
						value,
					)
			}

		case "disallow":
			if value != "" {
				result.Disallowed =
					append(
						result.Disallowed,
						value,
					)

				if isInterestingRobotsPath(
					value,
				) {
					result.SensitivePaths =
						append(
							result.SensitivePaths,
							value,
						)
				}
			}

		case "allow":
			if value != "" {
				result.Allowed =
					append(
						result.Allowed,
						value,
					)
			}

		case "sitemap":
			if value != "" {
				result.Sitemaps =
					append(
						result.Sitemaps,
						value,
					)
			}
		}

		_ = currentUserAgent
	}

	return result
}

func isInterestingRobotsPath(
	path string,
) bool {

	value := strings.ToLower(path)

	keywords := []string{
		"admin",
		"administrator",
		"backup",
		"private",
		"internal",
		"secret",
		"config",
		"database",
		"db",
		"staging",
		"test",
		"dev",
		".git",
		".env",
		"upload",
		"uploads",
		"debug",
	}

	for _, keyword := range keywords {
		if strings.Contains(
			value,
			keyword,
		) {
			return true
		}
	}

	return false
}

func containsIgnoreCase(
	values []string,
	target string,
) bool {

	for _, value := range values {
		if strings.EqualFold(
			value,
			target,
		) {
			return true
		}
	}

	return false
}