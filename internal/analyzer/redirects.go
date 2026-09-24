package analyzer

import (
	"context"
	"net/http"
	"net/url"

	"github.com/zharfatech/http-header-analyzer/internal/models"
)

func (a *Analyzer) analyzeRedirects(targetURL string) []models.RedirectInfo {
	redirects := make([]models.RedirectInfo, 0, maxRedirects)

	ctx, cancel := context.WithTimeout(context.Background(), 8*timeSecond)
	defer cancel()

	current, err := url.Parse(targetURL)
	if err != nil {
		return redirects
	}

	for i := 0; i <= maxRedirects; i++ {
		if !isSafeRemoteURL(current) {
			break
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodHead, current.String(), nil)
		if err != nil {
			break
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := a.client.Do(req)
		if err != nil {
			break
		}

		location := resp.Header.Get("Location")
		isRedirect := isRedirectStatusCode(resp.StatusCode)
		resp.Body.Close()

		redirects = append(redirects, models.RedirectInfo{
			StatusCode: resp.StatusCode,
			Location:   location,
			IsRedirect: isRedirect,
		})

		if !isRedirect || location == "" {
			break
		}

		next, err := current.Parse(location)
		if err != nil || !isSafeRemoteURL(next) {
			break
		}
		current = next
	}

	return redirects
}

const timeSecond = 1

func isRedirectStatusCode(code int) bool {
	return code >= 300 && code < 400
}

func hasHSTSHeader(resp *http.Response) bool {
	return resp.Header.Get("Strict-Transport-Security") != ""
}

func isHTTPRedirect(fromURL, toURL string) bool {
	from, err1 := url.Parse(fromURL)
	to, err2 := url.Parse(toURL)
	return err1 == nil && err2 == nil && from.Scheme == "http" && to.Scheme == "https"
}
