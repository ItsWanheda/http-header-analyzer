package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/zharfatech/http-header-analyzer/internal/analyzer"
	"github.com/zharfatech/http-header-analyzer/internal/validation"
)

func main() {

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "scan":
		runScan(os.Args[2:])

	case "version":
		fmt.Println("HTTP Header Analyzer v1.0.0")

	case "help":
		usage()

	default:
		fmt.Printf(
			"Unknown command: %s\n\n",
			command,
		)

		usage()

		os.Exit(1)
	}
}

func runScan(args []string) {

	fs := flag.NewFlagSet(
		"scan",
		flag.ExitOnError,
	)

	jsonOutput :=
		fs.Bool(
			"json",
			false,
			"Output JSON",
		)

	output :=
		fs.String(
			"output",
			"",
			"Write JSON report to file",
		)

	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Println(
			"Usage: analyzer scan <url> [--json] [--output report.json]",
		)

		os.Exit(1)
	}

	target := fs.Arg(0)

	validURL, err :=
		validation.ValidateURL(
			target,
		)

	if err != nil {
		log.Fatalf(
			"Invalid URL: %v",
			err,
		)
	}

	a := analyzer.NewAnalyzer()

	fmt.Println()
	fmt.Println(
		"╔══════════════════════════════════════╗",
	)
	fmt.Println(
		"║       HTTP HEADER ANALYZER           ║",
	)
	fmt.Println(
		"╚══════════════════════════════════════╝",
	)
	fmt.Println()

	fmt.Printf(
		"Target: %s\n",
		validURL,
	)

	fmt.Println()
	fmt.Println(
		"[*] Scanning...",
	)

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			30*time.Second,
		)

	defer cancel()

	result, err :=
		a.AnalyzeWithContext(
			ctx,
			validURL,
		)

	if err != nil {
		log.Fatalf(
			"Scan failed: %v",
			err,
		)
	}

	if *jsonOutput {

		printJSON(
			result,
			*output,
		)

		return
	}

	printReport(result)

	if *output != "" {
		printJSON(
			result,
			*output,
		)
	}
}

func printReport(
	result interface{},
) {

	/*
	 * Convert to the actual result
	 * through JSON so this function
	 * remains simple.
	 */

	data, err :=
		json.Marshal(
			result,
		)

	if err != nil {
		log.Fatal(err)
	}

	var report struct {
		Score       int    `json:"score"`
		Rating      string `json:"rating"`
		URL         string `json:"url"`
		Timestamp   string `json:"timestamp"`
	}

	if err :=
		json.Unmarshal(
			data,
			&report,
		); err != nil {
		log.Fatal(err)
	}

	fmt.Println()
	fmt.Println(
		"──────────────────────────────────────",
	)

	fmt.Printf(
		"URL:   %s\n",
		report.URL,
	)

	fmt.Printf(
		"SCORE: %d/100\n",
		report.Score,
	)

	fmt.Printf(
		"GRADE: %s\n",
		report.Rating,
	)

	fmt.Println(
		"──────────────────────────────────────",
	)

	fmt.Println()
	fmt.Println(
		"Scan completed successfully.",
	)

	fmt.Println()
}

func printJSON(
	result interface{},
	output string,
) {

	data, err :=
		json.MarshalIndent(
			result,
			"",
			"  ",
		)

	if err != nil {
		log.Fatalf(
			"Failed to encode JSON: %v",
			err,
		)
	}

	if output != "" {

		err :=
			os.WriteFile(
				output,
				data,
				0644,
			)

		if err != nil {
			log.Fatalf(
				"Failed to write report: %v",
				err,
			)
		}

		fmt.Printf(
			"Report saved to %s\n",
			output,
		)

		return
	}

	fmt.Println(
		string(data),
	)
}

func usage() {

	fmt.Println(
		"HTTP Header Analyzer",
	)

	fmt.Println()

	fmt.Println(
		"Usage:",
	)

	fmt.Println(
		"  analyzer scan <url>",
	)

	fmt.Println(
		"  analyzer scan <url> --json",
	)

	fmt.Println(
		"  analyzer scan <url> --output report.json",
	)

	fmt.Println(
		"  analyzer version",
	)

	fmt.Println()

	fmt.Println(
		"Examples:",
	)

	fmt.Println(
		"  analyzer scan https://example.com",
	)

	fmt.Println(
		"  analyzer scan https://example.com --json",
	)

	fmt.Println(
		"  analyzer scan https://example.com --output report.json",
	)

	fmt.Println()

	fmt.Println(
		strings.Repeat("-", 40),
	)
}