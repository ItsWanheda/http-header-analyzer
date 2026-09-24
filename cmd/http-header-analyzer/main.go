package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/zharfatech/http-header-analyzer/internal/analyzer"
	"github.com/zharfatech/http-header-analyzer/internal/models"
)

const version = "1.0.0"

var analyzeTarget = func(ctx context.Context, target string) (*models.AnalysisResult, error) {
	return analyzer.NewAnalyzer().AnalyzeWithContext(ctx, target)
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printUsage(stdout)
		return nil
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(stdout, version)
		return nil
	}
	if args[0] != "scan" {
		return fmt.Errorf("unknown command %q", args[0])
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "output the complete analysis as JSON")
	outputPath := fs.String("output", "", "write output to a file instead of stdout")
	timeout := fs.Duration("timeout", 15*time.Second, "maximum time allowed for the scan")
	minScore := fs.Int("min-score", -1, "fail if the security score is below this value (0-100)")
	failOn := fs.String("fail-on", "", "fail when an issue at or above this severity exists (critical, high, medium, low)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("scan requires exactly one URL")
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}
	if *minScore < -1 || *minScore > 100 {
		return fmt.Errorf("min-score must be between 0 and 100")
	}
	severity, err := parseFailOn(*failOn)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := analyzeTarget(ctx, strings.TrimSpace(fs.Arg(0)))
	if err != nil {
		return err
	}

	var data []byte
	if *jsonOutput {
		data, err = json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("encode JSON: %w", err)
		}
		data = append(data, '\n')
	} else {
		data = []byte(formatHumanResult(result))
	}

	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, data, 0o600); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
	} else if _, err := stdout.Write(data); err != nil {
		return err
	}

	if *minScore >= 0 && result.Score < *minScore {
		return fmt.Errorf("minimum score check failed: score %d is below required %d", result.Score, *minScore)
	}
	if severity != "" && hasIssueAtOrAbove(result.Issues, severity) {
		return fmt.Errorf("severity check failed: found issue at or above %s severity", severity)
	}

	return nil
}

func parseFailOn(value string) (models.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", nil
	case "critical":
		return models.SeverityCritical, nil
	case "high":
		return models.SeverityHigh, nil
	case "medium":
		return models.SeverityMedium, nil
	case "low":
		return models.SeverityLow, nil
	default:
		return "", fmt.Errorf("invalid fail-on severity %q; use critical, high, medium, or low", value)
	}
}

func hasIssueAtOrAbove(issues []models.Issue, threshold models.Severity) bool {
	thresholdRank := severityRank(threshold)
	for _, issue := range issues {
		if severityRank(issue.Severity) >= thresholdRank {
			return true
		}
	}
	return false
}

func severityRank(severity models.Severity) int {
	switch severity {
	case models.SeverityCritical:
		return 4
	case models.SeverityHigh:
		return 3
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 1
	default:
		return 0
	}
}

func formatHumanResult(result *models.AnalysisResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "HTTP Header Analyzer\n")
	fmt.Fprintf(&b, "====================\n")
	fmt.Fprintf(&b, "Target: %s\n", result.URL)
	fmt.Fprintf(&b, "Score:  %d/100 (%s)\n", result.Score, result.Rating)
	fmt.Fprintf(&b, "Scanned: %s\n", result.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "\nSecurity Headers\n")
	fmt.Fprintf(&b, "-----------------\n")

	for _, header := range result.SecurityHeaders {
		fmt.Fprintf(&b, "%-32s %-7s %s\n", header.Name, strings.ToUpper(header.Status), header.Message)
	}

	fmt.Fprintf(&b, "\nTLS\n")
	fmt.Fprintf(&b, "---\n")
	fmt.Fprintf(&b, "Version:     %s\n", result.TLS.Version)
	fmt.Fprintf(&b, "Cipher:      %s\n", result.TLS.CipherSuite)
	fmt.Fprintf(&b, "Certificate: %s\n", result.TLS.Certificate)
	fmt.Fprintf(&b, "Valid:       %t\n", result.TLS.Valid)

	fmt.Fprintf(&b, "\nIssues: %d\n", len(result.Issues))
	for _, issue := range result.Issues {
		fmt.Fprintf(&b, "- [%s] %s: %s\n", issue.Severity, issue.Header, issue.Explanation)
	}

	return b.String()
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "HTTP Header Analyzer CLI")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  http-header-analyzer scan <url> [flags]")
	fmt.Fprintln(w, "  http-header-analyzer version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --json             output the complete analysis as JSON")
	fmt.Fprintln(w, "  --output <file>    write output to a file")
	fmt.Fprintln(w, "  --timeout <dur>    maximum scan time (default 15s)")
	fmt.Fprintln(w, "  --min-score <n>    fail if score is below n (0-100)")
	fmt.Fprintln(w, "  --fail-on <level>  fail on issue severity: critical, high, medium, low")
}
