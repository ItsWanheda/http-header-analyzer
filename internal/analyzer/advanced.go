package analyzer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ItsWanheda/http-header-analyzer/internal/models"
)


// ============================================================
// HSTS ANALYZER
// ============================================================

func analyzeHSTS(headers http.Header) models.HSTSAnalysis {
	value := headers.Get("Strict-Transport-Security")

	result := models.HSTSAnalysis{
		Present: value != "",
		Value:   value,
		Status:  "fail",
	}

	if value == "" {
		result.Message = "Strict-Transport-Security header is missing."
		return result
	}

	lower := strings.ToLower(value)

	// max-age
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)

		if strings.HasPrefix(strings.ToLower(part), "max-age=") {
			raw := strings.TrimSpace(
				strings.TrimPrefix(
					strings.ToLower(part),
					"max-age=",
				),
			)

			if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
				result.MaxAge = n
			}
		}
	}

	result.IncludeSubDomains =
		strings.Contains(lower, "includesubdomains")

	result.Preload =
		strings.Contains(lower, "preload")

	switch {
	case result.MaxAge <= 0:
		result.Status = "fail"
		result.Message = "HSTS max-age is missing or zero."

	case result.MaxAge < 31536000:
		result.Status = "warn"
		result.Message = "HSTS max-age is shorter than one year."

	case !result.IncludeSubDomains:
		result.Status = "warn"
		result.Message = "includeSubDomains is not enabled."

	default:
		result.Status = "pass"
		result.Strong = true
		result.Message = "Strong HSTS configuration detected."
	}

	return result
}


// ============================================================
// SECURITY.TXT
// ============================================================

func (a *Analyzer) analyzeSecurityTxt(
	ctx context.Context,
	targetURL string,
) models.SecurityTxtAnalysis {

	result := models.SecurityTxtAnalysis{}

	base, err := url.Parse(targetURL)
	if err != nil {
		result.Message = "Invalid target URL."
		return result
	}

	base.Path = "/.well-known/security.txt"
	base.RawQuery = ""
	base.Fragment = ""

	securityURL := base.String()

	result.URL = securityURL

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		securityURL,
		nil,
	)

	if err != nil {
		result.Message = err.Error()
		return result
	}

	resp, err := a.client.Do(req)

	if err != nil {
		result.Message = "security.txt could not be fetched."
		return result
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Message =
			fmt.Sprintf(
				"security.txt returned HTTP %d.",
				resp.StatusCode,
			)

		return result
	}

	result.Found = true

	buf := make([]byte, 1024*1024)

	n, _ := resp.Body.Read(buf)

	content := string(buf[:n])

	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" ||
			strings.HasPrefix(line, "#") {
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

		case "contact":
			result.Contact =
				append(
					result.Contact,
					value,
				)

		case "policy":
			result.Policy =
				append(
					result.Policy,
					value,
				)

		case "acknowledgments":
			result.Acknowledgments =
				append(
					result.Acknowledgments,
					value,
				)

		case "encryption":
			result.Encryption =
				append(
					result.Encryption,
					value,
				)

		case "expires":
			result.Expires = value
		}
	}

	result.Valid =
		len(result.Contact) > 0

	if result.Valid {
		result.Message =
			"Valid security.txt contact information detected."
	} else {
		result.Message =
			"security.txt exists but has no Contact field."
	}

	return result
}


// ============================================================
// TECHNOLOGY DETECTION
// ============================================================

func detectTechnologies(
	headers http.Header,
	body string,
) models.TechnologyDetection {

	var technologies []models.Technology

	add := func(
		name string,
		category string,
		confidence int,
		evidence string,
	) {
		technologies = append(
			technologies,
			models.Technology{
				Name:       name,
				Category:   category,
				Confidence: confidence,
				Evidence: []string{
					evidence,
				},
			},
		)
	}

	server := headers.Get("Server")

	if strings.Contains(
		strings.ToLower(server),
		"nginx",
	) {
		add(
			"nginx",
			"Web Server",
			95,
			"Server header",
		)
	}

	if strings.Contains(
		strings.ToLower(server),
		"apache",
	) {
		add(
			"Apache",
			"Web Server",
			95,
			"Server header",
		)
	}

	if strings.Contains(
		strings.ToLower(server),
		"cloudflare",
	) {
		add(
			"Cloudflare",
			"CDN / Proxy",
			95,
			"Server header",
		)
	}

	poweredBy :=
		headers.Get(
			"X-Powered-By",
		)

	if strings.Contains(
		strings.ToLower(poweredBy),
		"express",
	) {
		add(
			"Express",
			"Framework",
			90,
			"X-Powered-By header",
		)
	}

	if strings.Contains(
		strings.ToLower(poweredBy),
		"php",
	) {
		add(
			"PHP",
			"Runtime",
			90,
			"X-Powered-By header",
		)
	}

	bodyLower :=
		strings.ToLower(body)

	if strings.Contains(
		bodyLower,
		"wp-content",
	) ||
		strings.Contains(
			bodyLower,
			"wp-includes",
		) {

		add(
			"WordPress",
			"CMS",
			90,
			"WordPress asset path",
		)
	}

	if strings.Contains(
		bodyLower,
		"__next",
	) {
		add(
			"Next.js",
			"Framework",
			85,
			"__NEXT_DATA__/__next asset",
		)
	}

	if strings.Contains(
		bodyLower,
		"react",
	) {
		add(
			"React",
			"JavaScript Framework",
			70,
			"React reference",
		)
	}

	if strings.Contains(
		bodyLower,
		"vue",
	) {
		add(
			"Vue.js",
			"JavaScript Framework",
			70,
			"Vue reference",
		)
	}

	return models.TechnologyDetection{
		Technologies: technologies,
	}
}


// ============================================================
// INFORMATION DISCLOSURE
// ============================================================

func analyzeInformationDisclosure(
	headers http.Header,
	body string,
) []models.InformationDisclosure {

	var findings []models.InformationDisclosure

	add := func(
		kind string,
		severity string,
		value string,
		header string,
		message string,
	) {
		findings = append(
			findings,
			models.InformationDisclosure{
				Type:     kind,
				Severity: severity,
				Value:    value,
				Header:   header,
				Message:  message,
			},
		)
	}

	server :=
		headers.Get("Server")

	if server != "" &&
		containsVersion(server) {

		add(
			"Server Version",
			"medium",
			server,
			"Server",
			"Server software version is exposed.",
		)
	}

	poweredBy :=
		headers.Get("X-Powered-By")

	if poweredBy != "" {
		add(
			"Technology Disclosure",
			"medium",
			poweredBy,
			"X-Powered-By",
			"Application technology is exposed.",
		)
	}

	debugHeaders := []string{
		"X-Debug",
		"X-Debug-Token",
		"X-Runtime",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
	}

	for _, name := range debugHeaders {
		if value := headers.Get(name); value != "" {
			add(
				"Debug / Framework Disclosure",
				"medium",
				value,
				name,
				"Potentially sensitive framework or debug information is exposed.",
			)
		}
	}

	bodyLower :=
		strings.ToLower(body)

	interesting := []string{
		"stack trace",
		"fatal error",
		"debug mode",
		"traceback",
		"exception",
	}

	for _, marker := range interesting {
		if strings.Contains(
			bodyLower,
			marker,
		) {
			add(
				"Error Disclosure",
				"high",
				marker,
				"",
				"Response body appears to contain debugging or error information.",
			)

			break
		}
	}

	return findings
}


func containsVersion(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' &&
			value[i] <= '9' {

			if i+2 < len(value) &&
				value[i+1] == '.' {

				return true
			}
		}
	}

	return false
}


// ============================================================
// HTTP METHODS
// ============================================================

func (a *Analyzer) analyzeHTTPMethods(ctx context.Context, targetURL string) models.HTTPMethodsAnalysis {
	result := models.HTTPMethodsAnalysis{Status: "unknown", Message: "HTTP method support could not be determined"}
	// OPTIONS is the only method probed. Never send POST, PUT, PATCH, DELETE,
	// TRACE, or CONNECT just to infer whether an application supports them.
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, targetURL, nil)
	if err != nil {
		return result
	}
	req.Header.Set("User-Agent", userAgent)
	probeClient := *a.client
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := probeClient.Do(req)
	if err != nil {
		result.Message = "OPTIONS probe failed; method support is unknown"
		return result
	}
	defer resp.Body.Close()
	allow := resp.Header.Values("Allow")
	if len(allow) == 0 {
		result.Message = "The server did not advertise an Allow header; method support is unknown"
		return result
	}
	known := map[string]bool{}
	for _, value := range allow {
		for _, method := range strings.Split(value, ",") {
			method = strings.ToUpper(strings.TrimSpace(method))
			if method != "" && !known[method] {
				known[method] = true
				result.Methods = append(result.Methods, method)
			}
		}
	}
	result.Status = "pass"
	for _, method := range result.Methods {
		switch method {
		case http.MethodTrace, http.MethodPut, http.MethodDelete, http.MethodConnect:
			result.Dangerous = append(result.Dangerous, method)
		}
		switch method {
		case http.MethodTrace:
			result.TraceEnabled = true
		case http.MethodPut:
			result.PutEnabled = true
		case http.MethodDelete:
			result.DeleteEnabled = true
		}
	}
	if len(result.Dangerous) > 0 {
		result.Status = "warn"
		result.Message = "The server advertises potentially sensitive HTTP methods in Allow; this is not proof that the methods are exploitable"
	} else {
		result.Message = "No obviously dangerous methods were advertised in Allow"
	}
	return result
}

// ============================================================
// CORS ANALYZER
// ============================================================

func analyzeCORS(
	headers http.Header,
) models.CORSAnalysis {

	origin :=
		headers.Get(
			"Access-Control-Allow-Origin",
		)

	result :=
		models.CORSAnalysis{
			Present:     origin != "",
			AllowOrigin: origin,
			Status:      "pass",
		}

	if origin == "" {
		result.Status = "not_applicable"
		result.Message = "No CORS allow-origin header was observed on this response"
		return result
	}

	result.AllowMethods =
		splitHeaderList(
			headers.Get(
				"Access-Control-Allow-Methods",
			),
		)

	result.AllowHeaders =
		splitHeaderList(
			headers.Get(
				"Access-Control-Allow-Headers",
			),
		)

	result.ExposedHeaders =
		splitHeaderList(
			headers.Get(
				"Access-Control-Expose-Headers",
			),
		)

	result.AllowCredentials =
		strings.EqualFold(
			headers.Get(
				"Access-Control-Allow-Credentials",
			),
			"true",
		)

	result.MaxAge =
		headers.Get(
			"Access-Control-Max-Age",
		)

	if origin == "*" &&
		result.AllowCredentials {

		result.Dangerous = true
		result.Status = "fail"
		result.Message =
			"Wildcard CORS origin is combined with credentials."
		return result
	}

	if origin == "*" {
		result.Status = "warn"
		result.Message =
			"CORS allows requests from any origin."
		return result
	}

	if result.AllowCredentials {
		result.Status = "warn"
		result.Message =
			"CORS allows credentials for a specific origin."
		return result
	}

	result.Message =
		"CORS configuration appears restricted."

	return result
}


// analyzeCORSWithContext sends one non-mutating preflight-style OPTIONS request
// using a deliberately unrelated origin, then evaluates the observed headers.
func (a *Analyzer) analyzeCORSWithContext(ctx context.Context, targetURL string, initial http.Header) models.CORSAnalysis {
	result := analyzeCORS(initial)
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, targetURL, nil)
	if err != nil {
		return result
	}
	const probeOrigin = "https://hha-probe.invalid"
	req.Header.Set("Origin", probeOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	req.Header.Set("User-Agent", userAgent)
	probeClient := *a.client
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := probeClient.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	probed := analyzeCORS(resp.Header)
	if probed.Present {
		result = probed
		if strings.EqualFold(strings.TrimSpace(probed.AllowOrigin), probeOrigin) {
			result.Status = "warn"
			result.Dangerous = true
			result.Message = "The preflight response reflects an arbitrary Origin value; review the CORS allowlist"
		}
		if strings.EqualFold(strings.TrimSpace(probed.AllowOrigin), "*") && probed.AllowCredentials {
			result.Status = "fail"
			result.Dangerous = true
			result.Message = "Wildcard origin and credentials were observed together; browsers reject this combination, but it indicates a configuration error"
		}
	}
	return result
}

func splitHeaderList(value string) []string {
	if value == "" {
		return nil
	}

	var result []string

	for _, item :=
		range strings.Split(value, ",") {

		item =
			strings.TrimSpace(item)

		if item != "" {
			result =
				append(
					result,
					item,
				)
		}
	}

	return result
}


// ============================================================
// UTILITY
// ============================================================

func isPublicHost(targetURL string) bool {
	parsed, err :=
		url.Parse(targetURL)

	if err != nil {
		return false
	}

	host := parsed.Hostname()

	ip := net.ParseIP(host)

	if ip == nil {
		return true
	}

	return !ip.IsPrivate()
}