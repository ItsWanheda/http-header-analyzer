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

async function analyzeTarget(target) {
    const response =
        await fetch("/api/analyze", {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                url: target
            })
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
    const input =
        $("urlInput") ||
        $("url") ||
        $("targetUrl");

    if (!input) {
        showToast(
            "URL input not found.",
            "error"
        );

        return;
    }

    let target =
        input.value.trim();

    if (!target) {
        showToast(
            "Enter a URL first.",
            "error"
        );

        input.focus();

        return;
    }

    if (
        !target.startsWith("http://") &&
        !target.startsWith("https://")
    ) {
        target =
            "https://" + target;
    }

    const scanButton =
        $("scanBtn") ||
        $("analyzeBtn") ||
        $("scanButton");

    const originalText =
        scanButton
            ? scanButton.innerHTML
            : "";

    try {
        if (scanButton) {
            scanButton.disabled = true;

            scanButton.innerHTML =
                `
                <i class="fas fa-spinner fa-spin"></i>
                SCANNING...
                `;
        }

        showToast(
            "Scanning target...",
            "info"
        );

        const result =
            await analyzeTarget(target);

        lastResult = result;

        displayResults(result);

        showToast(
            "Scan completed successfully.",
            "success"
        );

    } catch (error) {
        console.error(error);

        showToast(
            error.message ||
            "Scan failed.",
            "error"
        );

    } finally {
        if (scanButton) {
            scanButton.disabled = false;

            scanButton.innerHTML =
                originalText;
        }
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

                    ${
                        header.message
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

                <dd class="${
                    certificateOK
                        ? "status-pass"
                        : "status-fail"
                }">

                    <i class="fas ${
                        certificateOK
                            ? "fa-check"
                            : "fa-xmark"
                    }"></i>

                    ${
                        certificateOK
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

                <dd class="${
                    matches
                        ? "status-pass"
                        : "status-fail"
                }">

                    ${
                        matches
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
                    ${
                        cert.wildcard
                            ? "YES"
                            : "NO"
                    }
                </dd>

            </div>

        </div>

        ${
            Array.isArray(
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


            <div class="csp-metric ${
                sensitive.length
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


        ${
            sensitive.length
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


        ${
            disallowed.length
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


        ${
            sitemaps.length
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

                        ${
                            redirect.location
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
    const container =
        $("issuesList") ||
        $("findingsList") ||
        $("recommendationsList");

    if (!container) {
        return;
    }

    if (!issues.length) {
        container.innerHTML = `
            <div class="empty-state">

                <i class="fas fa-shield-check"></i>

                <span>
                    No security issues detected.
                </span>

            </div>
        `;

        return;
    }

    container.innerHTML =
        issues.map(issue => {

            const severity =
                String(
                    issue.severity ||
                    "Low"
                ).toLowerCase();

            return `
                <div class="issue-card severity-${severity}">

                    <div class="issue-header">

                        <strong>
                            ${escapeHtml(
                                issue.header
                            )}
                        </strong>

                        <span class="severity-badge">
                            ${escapeHtml(
                                issue.severity ||
                                "Low"
                            )}
                        </span>

                    </div>


                    ${
                        issue.explanation
                            ? `
                                <p>
                                    ${escapeHtml(
                                        issue.explanation
                                    )}
                                </p>
                              `
                            : ""
                    }


                    ${
                        issue.remediation
                            ? `
                                <div class="remediation">

                                    <strong>
                                        Recommendation:
                                    </strong>

                                    ${escapeHtml(
                                        issue.remediation
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

                                ${
                                    directive.sources.length
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

    const scanButtons = [
        $("scanBtn"),
        $("analyzeBtn"),
        $("scanButton")
    ].filter(Boolean);

    scanButtons.forEach(
        button => {

            button.addEventListener(
                "click",
                runScan
            );

        }
    );


    const input =
        $("urlInput") ||
        $("url") ||
        $("targetUrl");

    if (input) {

        input.addEventListener(
            "keydown",
            event => {

                if (
                    event.key ===
                    "Enter"
                ) {
                    event.preventDefault();

                    runScan();
                }

            }
        );

    }


    const copyButtons = [
        $("copyBtn"),
        $("copyJsonBtn"),
        $("copyJSON")
    ].filter(Boolean);

    copyButtons.forEach(
        button => {

            button.addEventListener(
                "click",
                copyJSON
            );

        }
    );


    const exportButtons = [
        $("exportJsonBtn"),
        $("exportJSON"),
        $("downloadJsonBtn"),
        $("downloadJSON")
    ].filter(Boolean);

    exportButtons.forEach(
        button => {

            button.addEventListener(
                "click",
                exportJSON
            );

        }
    );
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