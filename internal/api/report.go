package api
import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/zharfatech/http-header-analyzer/internal/analyzer"
)

const reportTemplate = `
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<title>Security Assessment Report</title>

<style>

@page {
    size: A4;
    margin: 18mm;
}

body {
    font-family:
        Arial,
        Helvetica,
        sans-serif;

    color: #111;

    line-height: 1.5;

    font-size: 12px;
}

.header {
    border-bottom:
        3px solid #111;

    padding-bottom:
        15px;

    margin-bottom:
        25px;
}

.logo {
    font-size:
        24px;

    font-weight:
        bold;
}

.meta {
    color:
        #666;
}

.score {
    font-size:
        42px;

    font-weight:
        bold;
}

.grade {
    display:
        inline-block;

    padding:
        6px 14px;

    border:
        2px solid #111;

    font-size:
        18px;

    font-weight:
        bold;
}

.section {
    margin-top:
        25px;

    page-break-inside:
        avoid;
}

.section h2 {
    border-bottom:
        1px solid #ccc;

    padding-bottom:
        5px;

    font-size:
        17px;
}

table {
    width: 100%;

    border-collapse:
        collapse;
}

th,
td {
    padding:
        7px;

    border:
        1px solid #ddd;

    text-align:
        left;
}

th {
    background:
        #f3f3f3;
}

.pass {
    color:
        #087f23;
}

.warn {
    color:
        #9a6a00;
}

.fail {
    color:
        #b00020;
}

.footer {
    margin-top:
        40px;

    padding-top:
        10px;

    border-top:
        1px solid #ccc;

    color:
        #777;

    font-size:
        10px;
}

</style>

</head>

<body>

<div class="header">

    <div class="logo">
        HTTP HEADER ANALYZER
    </div>

    <div class="meta">
        Security Assessment Report
    </div>

    <p>
        Target:
        <strong>{{.URL}}</strong>
    </p>

    <p>
        Generated:
        {{.Timestamp}}
    </p>

</div>


<div class="section">

    <h2>Executive Summary</h2>

    <div class="score">
        {{.Score}} / 100
    </div>

    <div class="grade">
        Grade {{.Rating}}
    </div>

</div>


<div class="section">

    <h2>Security Headers</h2>

    <table>

        <thead>
            <tr>
                <th>Header</th>
                <th>Status</th>
                <th>Value</th>
            </tr>
        </thead>

        <tbody>

        {{range .SecurityHeaders}}

            <tr>

                <td>
                    {{.Name}}
                </td>

                <td>
                    {{.Status}}
                </td>

                <td>
                    {{.Value}}
                </td>

            </tr>

        {{end}}

        </tbody>

    </table>

</div>


<div class="section">

    <h2>HSTS Analysis</h2>

    <table>

        <tr>
            <th>Status</th>
            <td>{{.HSTS.Status}}</td>
        </tr>

        <tr>
            <th>Max Age</th>
            <td>{{.HSTS.MaxAge}}</td>
        </tr>

        <tr>
            <th>Include SubDomains</th>
            <td>{{.HSTS.IncludeSubDomains}}</td>
        </tr>

        <tr>
            <th>Preload</th>
            <td>{{.HSTS.Preload}}</td>
        </tr>

        <tr>
            <th>Message</th>
            <td>{{.HSTS.Message}}</td>
        </tr>

    </table>

</div>


<div class="section">

    <h2>Technology Detection</h2>

    <table>

        <thead>

            <tr>
                <th>Technology</th>
                <th>Category</th>
                <th>Confidence</th>
            </tr>

        </thead>

        <tbody>

        {{range .Technologies.Technologies}}

            <tr>

                <td>
                    {{.Name}}
                </td>

                <td>
                    {{.Category}}
                </td>

                <td>
                    {{.Confidence}}%
                </td>

            </tr>

        {{end}}

        </tbody>

    </table>

</div>


<div class="section">

    <h2>Security.txt</h2>

    <table>

        <tr>
            <th>Found</th>
            <td>{{.SecurityTxt.Found}}</td>
        </tr>

        <tr>
            <th>Valid</th>
            <td>{{.SecurityTxt.Valid}}</td>
        </tr>

        <tr>
            <th>Contacts</th>
            <td>
                {{range .SecurityTxt.Contact}}
                    {{.}}<br>
                {{end}}
            </td>
        </tr>

    </table>

</div>


<div class="section">

    <h2>CORS</h2>

    <table>

        <tr>
            <th>Allow Origin</th>
            <td>{{.CORS.AllowOrigin}}</td>
        </tr>

        <tr>
            <th>Credentials</th>
            <td>{{.CORS.AllowCredentials}}</td>
        </tr>

        <tr>
            <th>Status</th>
            <td>{{.CORS.Status}}</td>
        </tr>

        <tr>
            <th>Message</th>
            <td>{{.CORS.Message}}</td>
        </tr>

    </table>

</div>


<div class="section">

    <h2>HTTP Methods</h2>

    <table>

        <tr>
            <th>Supported</th>
            <td>
                {{range .HTTPMethods.Methods}}
                    {{.}}
                {{end}}
            </td>
        </tr>

        <tr>
            <th>Dangerous</th>
            <td>
                {{range .HTTPMethods.Dangerous}}
                    {{.}}
                {{end}}
            </td>
        </tr>

        <tr>
            <th>Status</th>
            <td>
                {{.HTTPMethods.Status}}
            </td>
        </tr>

    </table>

</div>


<div class="section">

    <h2>Information Disclosure</h2>

    <table>

        <thead>
            <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>Value</th>
                <th>Message</th>
            </tr>
        </thead>

        <tbody>

        {{range .InformationLeaks}}

            <tr>

                <td>
                    {{.Type}}
                </td>

                <td>
                    {{.Severity}}
                </td>

                <td>
                    {{.Value}}
                </td>

                <td>
                    {{.Message}}
                </td>

            </tr>

        {{end}}

        </tbody>

    </table>

</div>


<div class="section">

    <h2>Findings</h2>

    <table>

        <thead>
            <tr>
                <th>Severity</th>
                <th>Issue</th>
                <th>Recommendation</th>
            </tr>
        </thead>

        <tbody>

        {{range .Issues}}

            <tr>

                <td>
                    {{.Severity}}
                </td>

                <td>
                    {{.Explanation}}
                </td>

                <td>
                    {{.Remediation}}
                </td>

            </tr>

        {{end}}

        </tbody>

    </table>

</div>


<div class="footer">

    Generated by HTTP Header Analyzer.

    This report is an automated security assessment and
    should not be considered a complete penetration test.

</div>

</body>
</html>
`

func (h *Handler) HandleReport(
	w http.ResponseWriter,
	r *http.Request,
) {

	if r.Method != http.MethodPost {
		http.Error(
			w,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	var request struct {
		URL string `json:"url"`
	}

	if err := readJSON(r, &request); err != nil {
		http.Error(
			w,
			"Invalid request body",
			http.StatusBadRequest,
		)
		return
	}

	result, err :=
		h.analyzer.Analyze(
			strings.TrimSpace(
				request.URL,
			),
		)

	if err != nil {
		http.Error(
			w,
			fmt.Sprintf(
				"Analysis failed: %v",
				err,
			),
			http.StatusInternalServerError,
		)

		return
	}

	tmpl :=
		template.Must(
			template.New(
				"report",
			).Parse(
				reportTemplate,
			),
		)

	w.Header().Set(
		"Content-Type",
		"text/html; charset=utf-8",
	)

	if err := tmpl.Execute(
		w,
		result,
	); err != nil {
		http.Error(
			w,
			"Failed to generate report",
			http.StatusInternalServerError,
		)
	}
}