const { test, expect } = require("@playwright/test");

function report({ includeFinding = true, timestamp = new Date().toISOString() } = {}) {
  return {
    url: "https://example.com",
    timestamp,
    http_status: 200,
    duration_ms: 123,
    score: includeFinding ? 82 : 96,
    rating: includeFinding ? "B-" : "A",
    security_headers: [
      { name: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains", present: true, status: "pass", message: "HSTS is configured." },
      { name: "Content-Security-Policy", value: "default-src 'self'", present: true, status: includeFinding ? "fail" : "pass", message: includeFinding ? "A restrictive policy needs review." : "CSP is present." }
    ],
    tls: { evaluated: true, valid: true, version: "TLS 1.3", cipher_suite: "TLS_AES_128_GCM_SHA256", certificate: "valid", expires_at: "2027-01-01T00:00:00Z", subject: "example.com", issuer: "Example CA" },
    certificate: { present: true, valid: true, subject: "example.com", issuer: "Example CA", serial_number: "1234", not_before: "2026-01-01T00:00:00Z", not_after: "2027-01-01T00:00:00Z", days_remaining: 81, signature_algorithm: "SHA256-RSA", public_key: "RSA", dns_names: ["example.com"], wildcard: false, matches_target: true },
    robots: { found: false, url: "https://example.com/robots.txt", status_code: 404, user_agents: [], disallowed: [], allowed: [], sitemaps: [], line_count: 0, sensitive_paths: [] },
    redirects: [],
    issues: includeFinding ? [{ header: "Content-Security-Policy", status: "fail", severity: "High", explanation: "The policy requires review.", remediation: "Review the CSP and restrict script sources." }] : [],
    hsts: { present: true, value: "max-age=31536000; includeSubDomains", max_age: 31536000, include_subdomains: true, preload: false, strong: true, status: "pass", message: "HSTS is configured." },
    security_txt: { found: false, valid: false, url: "https://example.com/.well-known/security.txt", contact: [], policy: [], message: "Not found." },
    technologies: { technologies: [] },
    information_disclosure: [],
    http_methods: { methods: ["GET", "HEAD", "OPTIONS"], dangerous: [], unexpected: [], trace_enabled: false, put_enabled: false, delete_enabled: false, status: "pass", message: "No dangerous methods advertised." },
    cors: { present: false, allow_origin: "", allow_methods: [], allow_headers: [], allow_credentials: false, exposed_headers: [], max_age: "", dangerous: false, status: "not_applicable", message: "No CORS allow-origin header observed." }
  };
}

test("dashboard theme, executive summary, history, and regression compare work", async ({ page }) => {
  let scans = 0;
  await page.addInitScript(() => localStorage.clear());
  await page.route("**/api/analyze", async route => {
    scans++;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(report({ includeFinding: scans === 1, timestamp: new Date(Date.now() + scans * 1000).toISOString() }))
    });
  });

  await page.goto("/");
  await expect(page.locator("h1")).toContainText("HTTP_HEADER_ANALYZER");
  await expect(page.locator("#themeToggle")).toHaveAttribute("aria-pressed", "false");
  await page.locator("#themeToggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator("#themeToggle")).toHaveAttribute("aria-pressed", "true");

  await page.locator("#urlInput").fill("https://example.com");
  await page.locator("#analyzeBtn").click();
  await expect(page.locator("#summaryTarget")).toContainText("https://example.com");
  await expect(page.locator("#countHigh")).toHaveText("1");
  await expect(page.locator("#issuesCard")).toBeVisible();
  await expect(page.locator("#scanHistoryList")).toContainText("example.com");

  await page.locator("#analyzeBtn").click();
  await expect(page.locator("#countHigh")).toHaveText("0");
  await expect(page.locator("#regressionSummary")).toContainText("1 resolved");
  await expect(page.locator("#scanHistoryList .history-entry")).toHaveCount(2);

  await page.locator("#clearHistoryBtn").click();
  await expect(page.locator("#scanHistoryList")).toContainText("No saved scans");
});

test("batch targets are submitted to the bounded batch API", async ({ page }) => {
  await page.addInitScript(() => localStorage.clear());
  await page.route("**/api/analyze/batch", async route => {
    const request = route.request().postDataJSON();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ total: request.urls.length, results: request.urls.map(url => ({ url, result: report({ includeFinding: false }) })) })
    });
  });
  await page.goto("/");
  await page.locator("#batchUrls").fill("https://example.com\nhttps://example.org");
  await page.locator("#batchScanBtn").click();
  await expect(page.locator("#batchResults")).toContainText("96/100");
  await expect(page.locator("#scanHistoryList")).toContainText("example.com");
});
