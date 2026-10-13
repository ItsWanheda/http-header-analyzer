"use strict";

/*
 * HTTP Header Analyzer
 * Frontend application
 *
 * Supports:
 * - Security headers
 * - CSP Visualizer
 * - Security score / A+ → F
 * - TLS information
 * - Certificate Analyzer
 * - Robots.txt Analyzer
 * - Issues / recommendations
 * - JSON export
 * - Copy JSON
 */

let lastResult = null;
let activeScanController = null;
let currentHistoryID = null;
const SCAN_HISTORY_KEY = "hha.scanHistory.v1";
const MAX_LOCAL_HISTORY = 20;


/* =========================================================
   DOM HELPERS
   ========================================================= */

function $(id) {
  return document.getElementById(id);
}


function escapeHtml(value) {
  if (value === null || value === undefined) {
    return "";
  }

  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


function showElement(element) {
  if (!element) return;

  element.style.display = "";
  element.hidden = false;
}


function hideElement(element) {
  if (!element) return;

  element.hidden = true;
}


function setText(id, value) {
  const element = $(id);

  if (!element) return;

  element.textContent =
    value === null ||
      value === undefined ||
      value === ""
      ? "—"
      : String(value);
}


/* =========================================================
   TOAST
   ========================================================= */

function showToast(message, type = "info") {
  let toast = $("toast");

  if (!toast) {
    toast = document.createElement("div");
    toast.id = "toast";
    toast.className = "toast";

    document.body.appendChild(toast);
  }

  toast.textContent = message;

  toast.className =
    `toast toast-${type}`;

  toast.classList.add("show");

  clearTimeout(
    window.__toastTimer
  );

  window.__toastTimer =
    setTimeout(() => {
      toast.classList.remove("show");
    }, 3000);
}


/* =========================================================
   API
   ========================================================= */

async function analyzeTarget(target, signal) {
  const response =
    await fetch("/api/analyze", {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json"
      },

      body: JSON.stringify({
        url: target
      }),
      signal
    });

  let data;

  try {
    data = await response.json();
  } catch (error) {
    throw new Error(
      "Server returned invalid JSON."
    );
  }

  if (!response.ok) {
    throw new Error(
      data?.error ||
      data?.message ||
      `Request failed (${response.status})`
    );
  }

  return data;
}


/* =========================================================
   MAIN SCAN
   ========================================================= */

async function runScan() {
  const input = $("urlInput");
  if (!input) { showToast("URL input not found.", "error"); return; }
  let target = input.value.trim();
  if (!target) { showToast("Enter a URL first.", "error"); input.focus(); return; }
  if (!/^https?:\/\//i.test(target)) target = "https://" + target;

  const scanButton = $("analyzeBtn");
  const cancelButton = $("cancelScanBtn");
  const preloader = $("preloader");
  const originalText = scanButton ? scanButton.innerHTML : "";
  activeScanController = new AbortController();
  try {
    if (scanButton) {
      scanButton.disabled = true;
      scanButton.innerHTML = '<span class="btn-text"><i class="fas fa-spinner fa-spin" aria-hidden="true"></i> SCANNING...</span>';
    }
    if (cancelButton) cancelButton.hidden = false;
    if (preloader) preloader.classList.remove("hidden");
    setText("status", "SCANNING");
    showToast("Scanning target…", "info");
    const result = await analyzeTarget(target, activeScanController.signal);
    lastResult = result;
    saveScanHistory(result);
    displayResults(result);
    setText("status", "COMPLETE");
    showToast("Scan completed successfully.", "success");
  } catch (error) {
    const cancelled = error && error.name === "AbortError";
    setText("status", cancelled ? "CANCELLED" : "ERROR");
    showToast(cancelled ? "Scan cancelled." : (error.message || "Scan failed."), cancelled ? "info" : "error");
  } finally {
    activeScanController = null;
    if (scanButton) { scanButton.disabled = false; scanButton.innerHTML = originalText; }
    if (cancelButton) cancelButton.hidden = true;
    if (preloader) preloader.classList.add("hidden");
  }
}


/* =========================================================
   DISPLAY RESULTS
   ========================================================= */

function displayResults(result) {
  if (!result) {
    return;
  }

  lastResult = result;

  showResultsSection();

  displayExecutiveSummary(result);
  renderScanHistory();
  displayScore(result);

  displaySecurityHeaders(
    result.security_headers ||
    []
  );

  displayTLS(
    result.tls ||
    {}
  );

  displayCertificate(
    result.certificate ||
    null
  );

  displayRobots(
    result.robots ||
    null
  );

  displayRedirects(
    result.redirects ||
    []
  );

  displayIssues(
    result.issues ||
    []
  );

  displayCSP(
    result.security_headers ||
    []
  );

  updateJSONPreview(
    result
  );

  displayHSTS(result.hsts);

  displaySecurityTxt(
    result.security_txt
  );

  displayTechnologies(
    result.technologies
  );

  displayInformationDisclosure(
    result.information_disclosure
  );

  displayHTTPMethods(
    result.http_methods
  );

  displayCORS(
    result.cors
  );
}


/* =========================================================
   EXECUTIVE SUMMARY / LOCAL HISTORY / REGRESSION
   ========================================================= */

function hostForResult(result) {
  try { return new URL(result.url).hostname.toLowerCase(); } catch { return String(result.url || "unknown"); }
}

function severityCounts(issues) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  (Array.isArray(issues) ? issues : []).forEach(issue => {
    const severity = String(issue.severity || "low").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(counts, severity)) counts[severity]++;
  });
  return counts;
}

function findingKey(issue) {
  return [issue.header, issue.severity, issue.explanation].map(value => String(value || "").trim().toLowerCase()).join("|");
}

function compareFindingSets(current, previous) {
  const currentIssues = Array.isArray(current?.issues) ? current.issues : [];
  const previousIssues = Array.isArray(previous?.issues) ? previous.issues : [];
  const currentKeys = new Set(currentIssues.map(findingKey));
  const previousKeys = new Set(previousIssues.map(findingKey));
  return {
    added: currentIssues.filter(issue => !previousKeys.has(findingKey(issue))),
    resolved: previousIssues.filter(issue => !currentKeys.has(findingKey(issue))),
    unchanged: currentIssues.filter(issue => previousKeys.has(findingKey(issue)))
  };
}

function displayExecutiveSummary(result) {
  if (!result) return;
  const issues = Array.isArray(result.issues) ? result.issues : [];
  const counts = severityCounts(issues);
  const headers = Array.isArray(result.security_headers) ? result.security_headers : [];
  const passCount = headers.filter(item => String(item.status).toLowerCase() === "pass").length;
  const failCount = headers.filter(item => String(item.status).toLowerCase() === "fail").length;
  const protocol = (() => { try { return new URL(result.url).protocol; } catch { return ""; } })();
  const tls = result.tls || {};
  const tlsText = protocol !== "https:" ? "N/A" : (!tls.evaluated ? "Unknown" : (tls.valid && ["TLS 1.2", "TLS 1.3"].includes(tls.version) ? "Verified" : "Review"));
  setText("summaryTarget", result.url || "Unknown target");
  setText("summaryScore", Number(result.score) < 0 ? "N/A" : Number(result.score || 0));
  setText("summaryRating", result.rating || getRating(Number(result.score)));
  setText("countCritical", counts.critical);
  setText("countHigh", counts.high);
  setText("countMedium", counts.medium);
  setText("countLow", counts.low);
  setText("countHeadersPass", passCount);
  setText("countHeadersFail", failCount);
  setText("summaryHTTPStatus", result.http_status || "—");
  setText("summaryTLSStatus", tlsText);
  setText("summaryDuration", Number.isFinite(Number(result.duration_ms)) ? `${Math.max(0, Number(result.duration_ms))} ms` : "—");
  const stamp = result.timestamp ? new Date(result.timestamp) : null;
  setText("summaryTimestamp", stamp && !Number.isNaN(stamp.getTime()) ? stamp.toLocaleString() : "—");
  const history = getScanHistory();
  const previous = history.find(item => item.id !== currentHistoryID && item.hostname === hostForResult(result));
  const regression = $("regressionSummary");
  if (regression) {
    if (!previous) {
      regression.textContent = "No earlier scan for this host is saved in this browser. This scan becomes the comparison baseline.";
    } else {
      const diff = compareFindingSets(result, previous.result);
      regression.textContent = `Compared with ${new Date(previous.timestamp).toLocaleString()}: ${diff.added.length} new, ${diff.resolved.length} resolved, ${diff.unchanged.length} unchanged findings.`;
      regression.dataset.baselineId = previous.id;
    }
  }
}

function getScanHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(SCAN_HISTORY_KEY) || "[]");
    return Array.isArray(value) ? value.filter(item => item && item.id && item.result && item.hostname) : [];
  } catch { return []; }
}

function saveScanHistory(result) {
  try {
    const history = getScanHistory();
    const timestamp = result.timestamp || new Date().toISOString();
    const entry = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp, url: result.url || "", hostname: hostForResult(result),
      score: Number.isFinite(Number(result.score)) ? Number(result.score) : -1,
      rating: result.rating || "N/A", result
    };
    currentHistoryID = entry.id;
    history.unshift(entry);
    localStorage.setItem(SCAN_HISTORY_KEY, JSON.stringify(history.slice(0, MAX_LOCAL_HISTORY)));
    renderScanHistory();
  } catch {
    currentHistoryID = null;
    showToast("This browser could not save scan history. Export the report to keep a copy.", "error");
  }
}

function renderScanHistory() {
  const container = $("scanHistoryList");
  if (!container) return;
  const history = getScanHistory();
  if (!history.length) {
    container.innerHTML = '<p class="text-muted">No saved scans yet. Run a scan to start local history.</p>';
    return;
  }
  container.innerHTML = history.slice(0, 10).map(item => {
    const stamp = new Date(item.timestamp);
    const when = Number.isNaN(stamp.getTime()) ? "Unknown date" : stamp.toLocaleString();
    const score = item.score < 0 ? "N/A" : `${item.score}/100`;
    return `<button type="button" class="history-entry" data-scan-id="${escapeHtml(item.id)}">
      <span><strong>${escapeHtml(item.hostname)}</strong><small>${escapeHtml(when)}</small></span>
      <span class="history-score">${escapeHtml(score)} · ${escapeHtml(item.rating)}</span>
      <span class="history-compare">Compare</span>
    </button>`;
  }).join("");
}

function compareWithHistory(scanID) {
  const selected = getScanHistory().find(item => item.id === scanID);
  if (!selected || !lastResult) { showToast("Select a saved scan after completing a scan.", "error"); return; }
  if (selected.hostname !== hostForResult(lastResult)) { showToast("Compare only scans for the same hostname.", "error"); return; }
  const diff = compareFindingSets(lastResult, selected.result);
  setText("regressionSummary", `Compared with ${new Date(selected.timestamp).toLocaleString()}: ${diff.added.length} new, ${diff.resolved.length} resolved, ${diff.unchanged.length} unchanged findings.`);
  showToast("Regression comparison updated.", "success");
}

function setSeverityFilter(severity) {
  const selector = $("issueSeverityFilter");
  if (selector) selector.value = severity || "all";
  displayIssues(lastResult?.issues || []);
  $("issuesCard")?.scrollIntoView?.({ behavior: "smooth", block: "start" });
}


/* =========================================================
   RESULTS SECTION
   ========================================================= */

function showResultsSection() {
  const candidates = [
    $("results"),
    $("resultsSection"),
    $("report"),
    $("dashboard"),
    $("analysisResults")
  ];

  candidates.forEach(
    element => {
      if (element) {
        showElement(element);
      }
    }
  );
}


/* =========================================================
   SCORE / GRADE
   ========================================================= */

function getRating(score) {
  score = Number(score);
  if (!Number.isFinite(score) || score < 0) return "N/A";

  if (score >= 97) return "A+";
  if (score >= 93) return "A";
  if (score >= 90) return "A-";
  if (score >= 87) return "B+";
  if (score >= 83) return "B";
  if (score >= 80) return "B-";
  if (score >= 77) return "C+";
  if (score >= 73) return "C";
  if (score >= 70) return "C-";
  if (score >= 60) return "D";

  return "F";
}


function getGradeClass(grade) {
  if (!grade) {
    return "grade-f";
  }

  return (
    "grade-" +
    grade
      .toLowerCase()
      .replace("+", "plus")
      .replace("-", "minus")
  );
}


function displayScore(result) {
  const score =
    Number(result.score || 0);

  const rating =
    result.rating ||
    getRating(score);

  setText(
    "scoreValue",
    score
  );

  setText(
    "ratingValue",
    rating
  );

  setText(
    "securityScore",
    score
  );

  setText(
    "securityRating",
    rating
  );

  setText(
    "gradeValue",
    rating
  );

  const scoreElements = [
    $("scoreValue"),
    $("securityScore"),
    $("score")
  ];

  scoreElements.forEach(
    element => {
      if (!element) return;

      element.textContent =
        score;
    }
  );

  const ratingElements = [
    $("ratingValue"),
    $("securityRating"),
    $("gradeValue"),
    $("rating")
  ];

  ratingElements.forEach(
    element => {
      if (!element) return;

      element.textContent =
        rating;

      element.classList.remove(
        "grade-a-plus",
        "grade-a",
        "grade-a-minus",
        "grade-b-plus",
        "grade-b",
        "grade-b-minus",
        "grade-c-plus",
        "grade-c",
        "grade-c-minus",
        "grade-d",
        "grade-f"
      );

      element.classList.add(
        getGradeClass(rating)
      );
    }
  );

  const progress =
    $("scoreProgress") ||
    $("scoreBar");

  if (progress) {
    if (
      progress.tagName === "PROGRESS"
    ) {
      progress.max = 100;
      progress.value = score;
    } else {
      progress.style.width =
        `${score}%`;
    }
  }
}


/* =========================================================
   SECURITY HEADERS
   ========================================================= */

function displaySecurityHeaders(headers) {
  const container =
    $("securityHeaders") ||
    $("headersList") ||
    $("securityHeaderList");

  if (!container) {
    return;
  }

  if (!headers.length) {
    container.innerHTML = `
            <div class="empty-state">
                No security headers analyzed.
            </div>
        `;

    return;
  }

  container.innerHTML =
    headers.map(header => {

      const status =
        String(
          header.status ||
          "unknown"
        ).toLowerCase();

      const statusClass =
        status === "pass"
          ? "status-pass"
          : status === "warn"
            ? "status-warn"
            : "status-fail";

      const icon =
        status === "pass"
          ? "fa-check"
          : status === "warn"
            ? "fa-triangle-exclamation"
            : "fa-xmark";

      return `
                <div class="security-header-item ${statusClass}">

                    <div class="security-header-main">

                        <div class="security-header-name">
                            ${escapeHtml(
        header.name
      )}
                        </div>

                        <div class="security-header-status">
                            <i class="fas ${icon}"></i>
                            ${escapeHtml(
        status.toUpperCase()
      )}
                        </div>

                    </div>

                    <div class="security-header-value">
                        ${escapeHtml(
        header.value || "Not present"
      )}
                    </div>

                    ${header.message
          ? `
                                <div class="security-header-message">
                                    ${escapeHtml(
            header.message
          )}
                                </div>
                              `
          : ""
        }

                </div>
            `;
    }).join("");
}


/* =========================================================
   TLS
   ========================================================= */

function displayTLS(tls) {
  if (!tls) {
    return;
  }

  setText(
    "tlsVersion",
    tls.version
  );

  setText(
    "cipherSuite",
    tls.cipher_suite
  );

  setText(
    "tlsCertificate",
    tls.certificate
  );

  setText(
    "tlsSubject",
    tls.subject
  );

  setText(
    "tlsIssuer",
    tls.issuer
  );

  setText(
    "tlsExpires",
    tls.expires_at
  );

  const valid =
    $("tlsValid");

  if (valid) {
    valid.textContent =
      tls.valid
        ? "VALID"
        : "INVALID";

    valid.classList.toggle(
      "status-pass",
      Boolean(tls.valid)
    );

    valid.classList.toggle(
      "status-fail",
      !tls.valid
    );
  }
}


/* =========================================================
   CERTIFICATE ANALYZER
   ========================================================= */

function displayCertificate(cert) {
  const container =
    $("certificateDetails");

  if (!container) {
    return;
  }

  if (
    !cert ||
    !cert.present
  ) {
    container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-certificate"></i>
                <span>
                    No certificate information available.
                </span>
            </div>
        `;

    return;
  }

  const valid =
    Boolean(cert.valid);

  const matches =
    Boolean(cert.matches_target);

  const certificateOK =
    valid && matches;

  const days =
    Number(
      cert.days_remaining
    );

  let expiryClass =
    "status-pass";

  if (days <= 30) {
    expiryClass =
      "status-warn";
  }

  if (days <= 0) {
    expiryClass =
      "status-fail";
  }

  container.innerHTML = `
        <div class="certificate-grid">

            <div class="tls-detail">

                <dt>STATUS</dt>

                <dd class="${certificateOK
      ? "status-pass"
      : "status-fail"
    }">

                    <i class="fas ${certificateOK
      ? "fa-check"
      : "fa-xmark"
    }"></i>

                    ${certificateOK
      ? "VALID"
      : "INVALID"
    }

                </dd>

            </div>


            <div class="tls-detail">

                <dt>SUBJECT</dt>

                <dd>
                    ${escapeHtml(
      cert.subject
    )}
                </dd>

            </div>


            <div class="tls-detail">

                <dt>ISSUER</dt>

                <dd>
                    ${escapeHtml(
      cert.issuer
    )}
                </dd>

            </div>


            <div class="tls-detail">

                <dt>EXPIRES</dt>

                <dd>
                    ${escapeHtml(
      cert.not_after
    )}
                </dd>

            </div>


            <div class="tls-detail">

                <dt>DAYS REMAINING</dt>

                <dd class="${expiryClass}">
                    ${Number.isFinite(days)
      ? days
      : "—"}
                </dd>

            </div>


            <div class="tls-detail">

                <dt>HOSTNAME MATCH</dt>

                <dd class="${matches
      ? "status-pass"
      : "status-fail"
    }">

                    ${matches
      ? "YES"
      : "NO"
    }

                </dd>

            </div>


            <div class="tls-detail">

                <dt>SIGNATURE</dt>

                <dd>
                    ${escapeHtml(
      cert.signature_algorithm
    )}
                </dd>

            </div>


            <div class="tls-detail">

                <dt>PUBLIC KEY</dt>

                <dd>
                    ${escapeHtml(
      cert.public_key
    )}
                </dd>

            </div>


            <div class="tls-detail">

                <dt>SERIAL NUMBER</dt>

                <dd class="break-word">
                    ${escapeHtml(
      cert.serial_number
    )}
                </dd>

            </div>


            <div class="tls-detail">

                <dt>WILDCARD</dt>

                <dd>
                    ${cert.wildcard
      ? "YES"
      : "NO"
    }
                </dd>

            </div>

        </div>

        ${Array.isArray(
      cert.dns_names
    ) &&
      cert.dns_names.length
      ? `
                    <div class="certificate-san">

                        <strong>
                            SAN / DNS NAMES
                        </strong>

                        <div class="tag-list">

                            ${cert.dns_names
        .map(
          name => `
                                        <span class="tag">
                                            ${escapeHtml(name)}
                                        </span>
                                    `
        )
        .join("")}

                        </div>

                    </div>
                  `
      : ""
    }
    `;
}


/* =========================================================
   ROBOTS.TXT ANALYZER
   ========================================================= */

function displayRobots(robots) {
  const container =
    $("robotsDetails");

  if (!container) {
    return;
  }

  if (
    !robots ||
    !robots.found
  ) {
    container.innerHTML = `
            <div class="empty-state">

                <i class="fas fa-robot"></i>

                <span>
                    robots.txt was not found.
                </span>

            </div>
        `;

    return;
  }

  const disallowed =
    Array.isArray(
      robots.disallowed
    )
      ? robots.disallowed
      : [];

  const allowed =
    Array.isArray(
      robots.allowed
    )
      ? robots.allowed
      : [];

  const sensitive =
    Array.isArray(
      robots.sensitive_paths
    )
      ? robots.sensitive_paths
      : [];

  const sitemaps =
    Array.isArray(
      robots.sitemaps
    )
      ? robots.sitemaps
      : [];

  container.innerHTML = `
        <div class="robots-summary">

            <div class="csp-metric">

                <strong>
                    ${disallowed.length}
                </strong>

                <span>
                    DISALLOWED
                </span>

            </div>


            <div class="csp-metric">

                <strong>
                    ${allowed.length}
                </strong>

                <span>
                    ALLOWED
                </span>

            </div>


            <div class="csp-metric">

                <strong>
                    ${sitemaps.length}
                </strong>

                <span>
                    SITEMAPS
                </span>

            </div>


            <div class="csp-metric ${sensitive.length
      ? "warn"
      : "pass"
    }">

                <strong>
                    ${sensitive.length}
                </strong>

                <span>
                    INTERESTING PATHS
                </span>

            </div>

        </div>


        ${sensitive.length
      ? `
                    <div class="robots-warning">

                        <h4>
                            <i class="fas fa-triangle-exclamation"></i>
                            Interesting Disallowed Paths
                        </h4>

                        <div class="robots-path-list">

                            ${sensitive
        .map(
          path => `
                                        <div class="robots-path">

                                            <i class="fas fa-folder"></i>

                                            <code>
                                                ${escapeHtml(
            path
          )}
                                            </code>

                                        </div>
                                    `
        )
        .join("")}

                        </div>

                        <p>
                            These paths are discoverable through
                            robots.txt. This does not by itself
                            indicate a vulnerability.
                        </p>

                    </div>
                  `
      : `
                    <div class="empty-state">

                        <i class="fas fa-shield-halved"></i>

                        <span>
                            No obviously interesting paths detected.
                        </span>

                    </div>
                  `
    }


        ${disallowed.length
      ? `
                    <div class="robots-section">

                        <h4>
                            Disallowed Paths
                        </h4>

                        <div class="tag-list">

                            ${disallowed
        .map(
          path => `
                                        <span class="tag">
                                            ${escapeHtml(
            path
          )}
                                        </span>
                                    `
        )
        .join("")}

                        </div>

                    </div>
                  `
      : ""
    }


        ${sitemaps.length
      ? `
                    <div class="robots-section">

                        <h4>
                            Sitemaps
                        </h4>

                        <div class="robots-sitemaps">

                            ${sitemaps
        .map(
          sitemap => `
                                        <div>
                                            ${escapeHtml(
            sitemap
          )}
                                        </div>
                                    `
        )
        .join("")}

                        </div>

                    </div>
                  `
      : ""
    }
    `;
}


/* =========================================================
   REDIRECTS
   ========================================================= */

function displayRedirects(redirects) {
  const container =
    $("redirectsList") ||
    $("redirectList");

  if (!container) {
    return;
  }

  if (!redirects.length) {
    container.innerHTML = `
            <div class="empty-state">
                No redirects detected.
            </div>
        `;

    return;
  }

  container.innerHTML =
    redirects.map(
      (redirect, index) => `
                <div class="redirect-item">

                    <div class="redirect-number">
                        ${index + 1}
                    </div>

                    <div class="redirect-content">

                        <div>
                            HTTP
                            ${escapeHtml(
        redirect.status_code
      )}
                        </div>

                        ${redirect.location
          ? `
                                    <code>
                                        ${escapeHtml(
            redirect.location
          )}
                                    </code>
                                  `
          : ""
        }

                    </div>

                </div>
            `
    ).join("");
}


/* =========================================================
   ISSUES
   ========================================================= */

function displayIssues(issues) {
  const container = $("issuesList") || $("findingsList") || $("recommendationsList");
  const card = $("issuesCard");
  if (!container) return;
  if (card) showElement(card);
  const severityFilter = ($("issueSeverityFilter")?.value || "all").toLowerCase();
  const query = ($("issueSearch")?.value || "").trim().toLowerCase();
  const sort = $("issueSort")?.value || "severity";
  const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
  const filtered = (Array.isArray(issues) ? issues : []).filter(issue => {
    const severity = String(issue.severity || "low").toLowerCase();
    if (severityFilter !== "all" && severity !== severityFilter) return false;
    const searchable = [issue.header, issue.explanation, issue.remediation, issue.severity].join(" ").toLowerCase();
    return !query || searchable.includes(query);
  });
  filtered.sort((a, b) => sort === "name"
    ? String(a.header || "").localeCompare(String(b.header || ""))
    : (severityRank[String(b.severity || "low").toLowerCase()] || 0) - (severityRank[String(a.severity || "low").toLowerCase()] || 0));
  if (!filtered.length) {
    container.innerHTML = '<div class="empty-state"><i class="fas fa-shield-check" aria-hidden="true"></i><span>No findings match the current filters.</span></div>';
    return;
  }
  container.innerHTML = filtered.map((issue, index) => {
    const severity = String(issue.severity || "Low").toLowerCase();
    return `<details class="issue-card severity-${escapeHtml(severity)}" ${index === 0 ? "open" : ""}>
      <summary class="issue-header"><strong>${escapeHtml(issue.header || "Security finding")}</strong><span class="severity-badge">${escapeHtml(issue.severity || "Low")}</span></summary>
      ${issue.status ? `<p class="finding-status">Status: ${escapeHtml(issue.status)}</p>` : ""}
      ${issue.explanation ? `<p>${escapeHtml(issue.explanation)}</p>` : ""}
      ${issue.remediation ? `<div class="remediation"><strong>Recommendation:</strong> ${escapeHtml(issue.remediation)}</div>` : ""}
    </details>`;
  }).join("");
}


/* =========================================================
   CSP VISUALIZER
   ========================================================= */

function findHeader(
  headers,
  name
) {
  return headers.find(
    header =>
      String(
        header.name || ""
      ).toLowerCase() ===
      name.toLowerCase()
  );
}


function parseCSP(value) {
  const directives = [];

  if (!value) {
    return directives;
  }

  value
    .split(";")
    .map(
      part => part.trim()
    )
    .filter(Boolean)
    .forEach(
      part => {

        const tokens =
          part.split(
            /\s+/
          );

        const name =
          tokens.shift();

        directives.push({
          name,
          sources: tokens
        });
      }
    );

  return directives;
}


function displayCSP(headers) {
  const container =
    $("cspDirectives") ||
    $("cspVisualizer") ||
    $("cspDetails");

  if (!container) {
    return;
  }

  const csp =
    findHeader(
      headers,
      "Content-Security-Policy"
    );

  if (
    !csp ||
    !csp.value
  ) {
    container.innerHTML = `
            <div class="empty-state">

                <i class="fas fa-shield-halved"></i>

                <span>
                    Content-Security-Policy header not found.
                </span>

            </div>
        `;

    return;
  }

  const directives =
    parseCSP(
      csp.value
    );

  if (!directives.length) {
    container.innerHTML = `
            <div class="empty-state">
                CSP header is empty or invalid.
            </div>
        `;

    return;
  }

  container.innerHTML = `
        <div class="csp-summary">

            <div class="csp-metric">

                <strong>
                    ${directives.length}
                </strong>

                <span>
                    DIRECTIVES
                </span>

            </div>

        </div>


        <div class="csp-directives">

            ${directives
      .map(
        directive => `
                        <div class="csp-directive">

                            <div class="csp-directive-name">

                                <i class="fas fa-shield"></i>

                                ${escapeHtml(
          directive.name
        )}

                            </div>

                            <div class="csp-sources">

                                ${directive.sources.length
            ? directive.sources
              .map(
                source => `
                                                    <span class="csp-source">
                                                        ${escapeHtml(
                  source
                )}
                                                    </span>
                                                `
              )
              .join("")
            : `
                                            <span class="csp-source">
                                                No sources
                                            </span>
                                          `
          }

                            </div>

                        </div>
                    `
      )
      .join("")}

        </div>
    `;
}


/* =========================================================
   JSON PREVIEW
   ========================================================= */

function updateJSONPreview(result) {
  const container =
    $("jsonPreview") ||
    $("jsonOutput");

  if (!container) {
    return;
  }

  const json =
    JSON.stringify(
      result,
      null,
      2
    );

  if (
    container.tagName ===
    "TEXTAREA"
  ) {
    container.value =
      json;

    return;
  }

  container.textContent =
    json;
}


/* =========================================================
   COPY JSON
   ========================================================= */

async function copyJSON() {
  if (!lastResult) {
    showToast(
      "No scan result available.",
      "error"
    );

    return;
  }

  const json =
    JSON.stringify(
      lastResult,
      null,
      2
    );

  try {
    await navigator.clipboard.writeText(
      json
    );

    showToast(
      "JSON copied to clipboard.",
      "success"
    );

  } catch (error) {
    console.error(error);

    const textarea =
      document.createElement(
        "textarea"
      );

    textarea.value =
      json;

    document.body.appendChild(
      textarea
    );

    textarea.select();

    document.execCommand(
      "copy"
    );

    textarea.remove();

    showToast(
      "JSON copied.",
      "success"
    );
  }
}


/* =========================================================
   EXPORT JSON
   ========================================================= */

function exportJSON() {
  if (!lastResult) {
    showToast(
      "No scan result available.",
      "error"
    );

    return;
  }

  const json =
    JSON.stringify(
      lastResult,
      null,
      2
    );

  const blob =
    new Blob(
      [json],
      {
        type:
          "application/json"
      }
    );

  const url =
    URL.createObjectURL(
      blob
    );

  let hostname =
    "target";

  try {
    hostname =
      new URL(
        lastResult.url
      ).hostname;
  } catch {
    hostname =
      "target";
  }

  hostname =
    hostname.replace(
      /[^a-z0-9.-]/gi,
      "_"
    );

  const date =
    new Date()
      .toISOString()
      .slice(
        0,
        10
      );

  const filename =
    `security-report-${hostname}-${date}.json`;

  const link =
    document.createElement(
      "a"
    );

  link.href =
    url;

  link.download =
    filename;

  document.body.appendChild(
    link
  );

  link.click();

  link.remove();

  URL.revokeObjectURL(
    url
  );

  showToast(
    "JSON report exported.",
    "success"
  );
}


function csvCell(value) {
  let text = String(value ?? "");
  // Prevent spreadsheet formula injection in CSV opened by office software.
  if (/^[=+@\-\t\r]/.test(text)) text = "'" + text;
  return '"' + text.replace(/"/g, '""') + '"';
}

function exportCSV() {
  if (!lastResult) {
    showToast("Run a scan first.", "error");
    return;
  }
  const rows = [["record_type", "severity", "name", "status", "value", "details", "remediation"]];
  (lastResult.security_headers || []).forEach(item => rows.push([
    "header", "", item.name, item.status, item.value, item.message, ""
  ]));
  (lastResult.issues || []).forEach(item => rows.push([
    "finding", item.severity, item.header, item.status, "", item.explanation, item.remediation
  ]));
  const csv = rows.map(row => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
  const blob = new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  let hostname = "target";
  try { hostname = new URL(lastResult.url).hostname.replace(/[^a-z0-9.-]/gi, "_"); } catch {}
  const link = document.createElement("a");
  link.href = url;
  link.download = `security-report-${hostname}-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast("CSV report exported.", "success");
}


/* =========================================================
   DOWNLOAD JSON ALIAS
   ========================================================= */

function downloadJSON() {
  exportJSON();
}


/* =========================================================
   EVENT LISTENERS
   ========================================================= */

function initEventListeners() {
  const form = $("analyzeForm");
  if (form) form.addEventListener("submit", event => { event.preventDefault(); runScan(); });
  const cancelButton = $("cancelScanBtn");
  if (cancelButton) cancelButton.addEventListener("click", () => activeScanController?.abort());
  const themeButton = $("themeToggle");
  if (themeButton) themeButton.addEventListener("click", toggleTheme);
  const clearHistoryButton = $("clearHistoryBtn");
  if (clearHistoryButton) clearHistoryButton.addEventListener("click", () => {
    try { localStorage.removeItem(SCAN_HISTORY_KEY); } catch {}
    currentHistoryID = null;
    renderScanHistory();
    setText("regressionSummary", "Local scan history cleared.");
  });
  const severityFilter = $("issueSeverityFilter");
  if (severityFilter) severityFilter.addEventListener("change", () => displayIssues(lastResult?.issues || []));
  const issueSort = $("issueSort");
  if (issueSort) issueSort.addEventListener("change", () => displayIssues(lastResult?.issues || []));
  const issueSearch = $("issueSearch");
  if (issueSearch) issueSearch.addEventListener("input", () => displayIssues(lastResult?.issues || []));
  document.querySelectorAll("[data-severity-filter]").forEach(button => button.addEventListener("click", () => setSeverityFilter(button.dataset.severityFilter || "all")));
  const headerFilter = $("headerFilter");
  if (headerFilter) headerFilter.addEventListener("input", () => {
    const query = headerFilter.value.trim().toLowerCase();
    const rows = $("headersBody")?.querySelectorAll("tr") || [];
    rows.forEach(row => { row.hidden = !row.textContent.toLowerCase().includes(query); });
  });
  const batchButton = $("batchScanBtn");
  if (batchButton) batchButton.addEventListener("click", runBatchScan);
  const historyList = $("scanHistoryList");
  if (historyList) historyList.addEventListener("click", event => {
    const button = event.target.closest("[data-scan-id]");
    if (button) compareWithHistory(button.dataset.scanId);
  });
}

function initThemeToggle() {
  const root = document.documentElement;
  let preferred = "dark";
  try { preferred = localStorage.getItem("hha.theme") || "dark"; } catch {}
  root.dataset.theme = preferred === "light" ? "light" : "dark";
  updateThemeButton();
}
function toggleTheme() {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
  try { localStorage.setItem("hha.theme", root.dataset.theme); } catch {}
  updateThemeButton();
}
function updateThemeButton() {
  const button = $("themeToggle");
  if (!button) return;
  const light = document.documentElement.dataset.theme === "light";
  button.setAttribute("aria-pressed", String(light));
  button.setAttribute("aria-label", light ? "Switch to dark theme" : "Switch to light theme");
  button.title = light ? "Switch to dark theme" : "Switch to light theme";
}


async function runBatchScan() {
  const input = $("batchUrls");
  const output = $("batchResults");
  const button = $("batchScanBtn");
  const urls = (input?.value || "").split(/\r?\n/).map(value => value.trim()).filter(Boolean);
  if (!urls.length || urls.length > 10) {
    showToast("Enter between 1 and 10 URLs for a batch scan.", "error");
    input?.focus();
    return;
  }
  if (button) { button.disabled = true; button.textContent = "SCANNING BATCH…"; }
  if (output) output.textContent = "Batch scan running with bounded concurrency…";
  try {
    const response = await fetch("/api/analyze/batch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ urls }) });
    let data;
    try { data = await response.json(); } catch { throw new Error("Server returned invalid JSON."); }
    if (!response.ok) throw new Error(data?.error || `Batch request failed (${response.status})`);
    const results = Array.isArray(data.results) ? data.results : [];
    if (output) output.innerHTML = results.map((item, index) => {
      if (!item.result) return `<div class="batch-result batch-error"><span>${escapeHtml(item.url || urls[index])}</span><strong>${escapeHtml(item.error || "Scan failed")}</strong></div>`;
      const score = Number(item.result.score) < 0 ? "N/A" : `${item.result.score}/100`;
      return `<div class="batch-result"><span>${escapeHtml(item.url)}</span><strong>${escapeHtml(score)} · ${escapeHtml(item.result.rating || "N/A")}</strong><button type="button" data-batch-index="${index}">Open report</button></div>`;
    }).join("");
    results.forEach(item => { if (item.result) saveScanHistory(item.result); });
    if (output) output.querySelectorAll("[data-batch-index]").forEach(openButton => openButton.addEventListener("click", () => {
      const selected = results[Number(openButton.dataset.batchIndex)]?.result;
      if (selected) { lastResult = selected; displayResults(selected); document.getElementById("resultsSection")?.scrollIntoView({behavior:"smooth"}); }
    }));
    showToast(`Batch complete: ${results.filter(item => item.result).length}/${results.length} successful.`, "success");
    renderScanHistory();
  } catch (error) {
    if (output) output.textContent = error.message || "Batch scan failed.";
    showToast(error.message || "Batch scan failed.", "error");
  } finally {
    if (button) { button.disabled = false; button.textContent = "SCAN_BATCH"; }
  }
}


async function generatePDFReport() {
  if (!lastResult) { showToast("Run a scan first.", "error"); return; }
  const result = lastResult;
  const headers = Array.isArray(result.security_headers) ? result.security_headers : [];
  const issues = Array.isArray(result.issues) ? result.issues : [];
  const safeTarget = escapeHtml(result.url || "Unknown target");
  const headerRows = headers.map(item => `<tr><td>${escapeHtml(item.name)}</td><td><code>${escapeHtml(item.value)}</code></td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.message)}</td></tr>`).join("");
  const issueRows = issues.map(item => `<tr><td>${escapeHtml(item.severity)}</td><td>${escapeHtml(item.header)}</td><td>${escapeHtml(item.explanation)}</td><td>${escapeHtml(item.remediation)}</td></tr>`).join("");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Security Assessment Report</title><style>
    @page{size:A4;margin:16mm}body{font-family:Arial,sans-serif;color:#172026;line-height:1.45;font-size:11px}h1,h2{margin-bottom:6px}h1{font-size:22px}h2{font-size:15px;border-bottom:1px solid #cbd5e1;padding-bottom:4px;margin-top:24px}.meta{color:#475569;overflow-wrap:anywhere}.score{font-size:28px;font-weight:700}table{width:100%;border-collapse:collapse;table-layout:fixed;overflow-wrap:anywhere}th,td{border:1px solid #d1d5db;padding:6px;text-align:left;vertical-align:top}th{background:#f1f5f9}code{white-space:pre-wrap;overflow-wrap:anywhere}.footer{margin-top:30px;color:#64748b;border-top:1px solid #cbd5e1;padding-top:8px}</style></head><body>
    <h1>HTTP Header Analyzer</h1><p class="meta">Target: ${safeTarget}<br>Scanned: ${escapeHtml(result.timestamp || "Unknown")}<br>HTTP status: ${escapeHtml(result.http_status ?? "Unknown")}</p>
    <p class="score">Score: ${escapeHtml(Number(result.score)<0 ? "N/A" : result.score + "/100")} · ${escapeHtml(result.rating || "N/A")}</p>
    <h2>Findings (${issues.length})</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence / explanation</th><th>Remediation</th></tr></thead><tbody>${issueRows || "<tr><td colspan='4'>No findings recorded.</td></tr>"}</tbody></table>
    <h2>Security headers (${headers.length})</h2><table><thead><tr><th>Header</th><th>Value</th><th>Status</th><th>Details</th></tr></thead><tbody>${headerRows || "<tr><td colspan='4'>No header data.</td></tr>"}</tbody></table>
    <h2>TLS configuration</h2><p>Evaluated: ${escapeHtml(result.tls?.evaluated ? "Yes" : "No / not applicable")}<br>Version: ${escapeHtml(result.tls?.version || "Unknown")}<br>Cipher: ${escapeHtml(result.tls?.cipher_suite || "Unknown")}<br>Certificate valid: ${escapeHtml(result.tls?.valid === true ? "Yes" : result.tls?.evaluated ? "No / review" : "Unknown")}</p>
    <div class="footer">Generated by HTTP Header Analyzer. A score reflects observed configuration, not a guarantee that the target is secure.</div><script>window.addEventListener("load",()=>window.print())</script></body></html>`;
  const reportWindow = window.open("", "_blank");
  if (!reportWindow) { showToast("Popup blocked. Allow popups to print or save this report.", "error"); return; }
  reportWindow.document.open();
  reportWindow.document.write(html);
  reportWindow.document.close();
}


document.addEventListener("DOMContentLoaded", () => {
  initEventListeners();
  initThemeToggle();
  renderScanHistory();
  const pdfBtn = $("pdfBtn");
  if (pdfBtn) pdfBtn.addEventListener("click", generatePDFReport);
});


function displayHSTS(hsts) {
  const container =
    document.getElementById(
      "hstsDetails"
    );

  if (!container) return;

  if (!hsts) {
    container.innerHTML =
      `<div class="empty-state">No HSTS data.</div>`;
    return;
  }

  container.innerHTML = `
        <div class="certificate-grid">

            <div class="tls-detail">
                <dt>STATUS</dt>
                <dd class="status-${escapeHtml(hsts.status)}">
                    ${escapeHtml(hsts.status)}
                </dd>
            </div>

            <div class="tls-detail">
                <dt>MAX-AGE</dt>
                <dd>
                    ${escapeHtml(hsts.max_age)}
                </dd>
            </div>

            <div class="tls-detail">
                <dt>INCLUDE SUBDOMAINS</dt>
                <dd>
                    ${hsts.include_subdomains ? "YES" : "NO"}
                </dd>
            </div>

            <div class="tls-detail">
                <dt>PRELOAD</dt>
                <dd>
                    ${hsts.preload ? "YES" : "NO"}
                </dd>
            </div>

        </div>

        <p class="text-muted">
            ${escapeHtml(hsts.message)}
        </p>
    `;
}


function displaySecurityTxt(data) {
  const container =
    document.getElementById(
      "securityTxtDetails"
    );

  if (!container) return;

  if (!data || !data.found) {
    container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-file-shield"></i>
                security.txt not found.
            </div>
        `;

    return;
  }

  container.innerHTML = `
        <div class="certificate-grid">

            <div class="tls-detail">
                <dt>FOUND</dt>
                <dd class="status-pass">
                    YES
                </dd>
            </div>

            <div class="tls-detail">
                <dt>VALID</dt>
                <dd class="${data.valid
      ? "status-pass"
      : "status-warn"
    }">
                    ${data.valid ? "YES" : "NO"}
                </dd>
            </div>

            <div class="tls-detail">
                <dt>CONTACTS</dt>
                <dd>
                    ${data.contact?.length || 0}
                </dd>
            </div>

            <div class="tls-detail">
                <dt>EXPIRES</dt>
                <dd>
                    ${escapeHtml(
      data.expires || "—"
    )}
                </dd>
            </div>

        </div>

        <p class="text-muted">
            ${escapeHtml(data.message)}
        </p>

        ${data.contact?.length
      ? `
                    <div class="tag-list">
                        ${data.contact.map(
        contact => `
                                <span class="tag">
                                    ${escapeHtml(contact)}
                                </span>
                            `
      ).join("")}
                    </div>
                  `
      : ""
    }
    `;
}


function displayTechnologies(data) {
  const container =
    document.getElementById(
      "technologyDetails"
    );

  if (!container) return;

  const technologies =
    data?.technologies || [];

  if (!technologies.length) {
    container.innerHTML = `
            <div class="empty-state">
                No technologies detected.
            </div>
        `;

    return;
  }

  container.innerHTML = `
        <div class="csp-directives">

            ${technologies.map(
    tech => `
                    <div class="csp-directive">

                        <div class="csp-directive-name">
                            <i class="fas fa-microchip"></i>
                            ${escapeHtml(
      tech.name
    )}
                        </div>

                        <div class="csp-sources">

                            <span class="csp-source">
                                ${escapeHtml(
      tech.category
    )}
                            </span>

                            <span class="csp-source">
                                ${escapeHtml(
      tech.confidence
    )}% confidence
                            </span>

                            ${tech.evidence?.length
        ? tech.evidence.map(
          evidence => `
                                            <span class="csp-source">
                                                ${escapeHtml(
            evidence
          )}
                                            </span>
                                        `
        ).join("")
        : ""
      }

                        </div>

                    </div>
                `
  ).join("")}

        </div>
    `;
}


function displayInformationDisclosure(
  findings
) {
  const container =
    document.getElementById(
      "informationDisclosureDetails"
    );

  if (!container) return;

  if (!findings?.length) {
    container.innerHTML = `
            <div class="empty-state">
                No obvious information disclosure detected.
            </div>
        `;

    return;
  }

  container.innerHTML =
    findings.map(
      finding => `
                <div class="issue-card">

                    <div class="issue-header">

                        <strong>
                            ${escapeHtml(
        finding.type
      )}
                        </strong>

                        <span class="severity-badge">
                            ${escapeHtml(
        finding.severity
      )}
                        </span>

                    </div>

                    ${finding.header
          ? `
                                <code>
                                    ${escapeHtml(
            finding.header
          )}
                                </code>
                              `
          : ""
        }

                    <p>
                        ${escapeHtml(
          finding.message
        )}
                    </p>

                    <code>
                        ${escapeHtml(
          finding.value
        )}
                    </code>

                </div>
            `
    ).join("");
}


function displayHTTPMethods(data) {
  const container =
    document.getElementById(
      "httpMethodsDetails"
    );

  if (!container) return;

  container.innerHTML = `
        <div class="csp-summary">

            <div class="csp-metric">
                <strong>
                    ${data?.methods?.length || 0}
                </strong>
                <span>
                    METHODS
                </span>
            </div>

            <div class="csp-metric ${data?.dangerous?.length
      ? "warn"
      : "pass"
    }">

                <strong>
                    ${data?.dangerous?.length || 0}
                </strong>

                <span>
                    DANGEROUS
                </span>

            </div>

        </div>

        <div class="tag-list">

            ${(data?.methods || [])
      .map(
        method => `
                        <span class="tag">
                            ${escapeHtml(method)}
                        </span>
                    `
      )
      .join("")}

        </div>

        ${data?.dangerous?.length
      ? `
                    <p class="status-warn">
                        Dangerous:
                        ${data.dangerous
        .map(
          escapeHtml
        )
        .join(", ")}
                    </p>
                  `
      : `
                    <p class="status-pass">
                        No dangerous methods detected.
                    </p>
                  `
    }
    `;
}


function displayCORS(data) {
  const container =
    document.getElementById(
      "corsDetails"
    );

  if (!container) return;

  if (!data?.present) {
    container.innerHTML = `
            <div class="empty-state">
                No CORS policy detected.
            </div>
        `;

    return;
  }

  container.innerHTML = `
        <div class="certificate-grid">

            <div class="tls-detail">

                <dt>STATUS</dt>

                <dd class="status-${escapeHtml(
    data.status
  )}">

                    ${escapeHtml(
    data.status
  )}

                </dd>

            </div>

            <div class="tls-detail">

                <dt>ALLOW ORIGIN</dt>

                <dd>
                    ${escapeHtml(
    data.allow_origin
  )}
                </dd>

            </div>

            <div class="tls-detail">

                <dt>CREDENTIALS</dt>

                <dd>
                    ${data.allow_credentials
      ? "YES"
      : "NO"
    }
                </dd>

            </div>

        </div>

        <p class="${data.dangerous
      ? "status-fail"
      : "text-muted"
    }">

            ${escapeHtml(
      data.message
    )}

        </p>
    `;
}

/* =========================================================
   INITIALIZATION
   ========================================================= */

document.addEventListener(
  "DOMContentLoaded",
  () => {

    initEventListeners();

    console.log(
      "HTTP Header Analyzer initialized."
    );

  }
);