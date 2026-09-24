package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zharfatech/http-header-analyzer/internal/analyzer"
	"github.com/zharfatech/http-header-analyzer/internal/models"
)

const version = "1.0.0"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr *os.File) error {
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
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("scan requires exactly one URL")
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := analyzer.NewAnalyzer().AnalyzeWithContext(ctx, strings.TrimSpace(fs.Arg(0)))
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
		return nil
	}

	_, err = stdout.Write(data)
	return err
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

func printUsage(w *os.File) {
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
}
