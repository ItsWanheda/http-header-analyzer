package analyzer

import (
    "net/http"
    "strings"

    "github.com/zharfatech/http-header-analyzer/internal/models"
)

// analyzeRedirects follows the redirect chain and returns information about each step
func (a *Analyzer) analyzeRedirects(targetURL string) []models.RedirectInfo {
    var redirects []models.RedirectInfo

    // Create a custom client that doesn't follow redirects
    client := &http.Client{
        Timeout:   defaultTimeout,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse // Stop following redirects
        },
    }

    resp, err := client.Get(targetURL)
    if err != nil {
        // If we can't even make the initial request, return empty
        return redirects
    }
    defer resp.Body.Close()

    redirects = append(redirects, models.RedirectInfo{
        StatusCode: resp.StatusCode,
        Location:   resp.Header.Get("Location"),
        IsRedirect: isRedirectStatusCode(resp.StatusCode),
    })

    // If it was a redirect, follow it once to get the final destination
    if isRedirectStatusCode(resp.StatusCode) {
        location := resp.Header.Get("Location")
        if location != "" {
            finalResp, err := client.Get(location)
            if err == nil {
                defer finalResp.Body.Close()
                redirects = append(redirects, models.RedirectInfo{
                    StatusCode: finalResp.StatusCode,
                    Location:   "",
                    IsRedirect: isRedirectStatusCode(finalResp.StatusCode),
                })
            }
        }
    }

    return redirects
}

// isRedirectStatusCode checks if the status code indicates a redirect
func isRedirectStatusCode(code int) bool {
    return code >= 300 && code < 400
}

// hasHSTSHeader checks if HSTS header is present (for redirect analysis)
func hasHSTSHeader(resp *http.Response) bool {
    return resp.Header.Get("Strict-Transport-Security") != ""
}

// isHTTPRedirect checks if the redirect is from HTTP to HTTPS
func isHTTPRedirect(fromURL, toURL string) bool {
    return strings.HasPrefix(fromURL, "http://") && strings.HasPrefix(toURL, "https://")
}