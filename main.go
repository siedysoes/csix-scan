// csix-scan: pemindai rahasia (secret scanner) ringan untuk repository.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/siedysoes/csix-scan/internal/gitlog"
	"github.com/siedysoes/csix-scan/internal/rules"
	"github.com/siedysoes/csix-scan/internal/scan"
	"github.com/siedysoes/csix-scan/internal/ui"
)

const version = "0.1.0"

func main() {
	var (
		jsonOut     bool
		history     bool
		showSecrets bool
		noColor     bool
		exclude     string
		maxMB       int
		showVersion bool
	)
	flag.BoolVar(&jsonOut, "json", false, "output JSON (untuk CI/tooling)")
	flag.BoolVar(&history, "history", false, "pindai juga riwayat commit git")
	flag.BoolVar(&showSecrets, "show-secrets", false, "tampilkan nilai rahasia utuh (default: disamarkan)")
	flag.BoolVar(&noColor, "no-color", false, "matikan warna output")
	flag.StringVar(&exclude, "exclude", "", "nama direktori tambahan yang dilewati (dipisah koma)")
	flag.IntVar(&maxMB, "max-file-mb", 10, "ukuran file maksimum yang dipindai (MB)")
	flag.BoolVar(&showVersion, "version", false, "tampilkan versi")
	flag.Parse()

	if showVersion {
		fmt.Println("csix-scan v" + version)
		return
	}

	if !noColor {
		ui.Setup()
	}

	root := "."
	if flag.NArg() > 0 {
		root = flag.Args()[0]
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		absRoot = root
	}

	extraSkip := map[string]bool{}
	if exclude != "" {
		for _, d := range strings.Split(exclude, ",") {
			if d = strings.TrimSpace(d); d != "" {
				extraSkip[d] = true
			}
		}
	}

	findings, stats, scanErr := scan.ScanPath(absRoot, int64(maxMB)*1024*1024, extraSkip)
	if scanErr != nil {
		fatal(scanErr.Error())
	}

	if history {
		hist, err := gitlog.ScanHistory(absRoot)
		if err != nil {
			warn("riwayat git dilewati: " + err.Error())
		} else {
			findings = append(findings, hist...)
		}
	}

	scan.SortFindings(findings)

	if jsonOut {
		printJSON(absRoot, findings, stats)
	} else {
		printHuman(absRoot, findings, stats, showSecrets)
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
}

func printHuman(root string, findings []scan.Finding, stats scan.Stats, showSecrets bool) {
	fmt.Println(ui.Wrap(ui.Bold, "csix-scan v"+version) + ui.Wrap(ui.Gray, " — pemindai rahasia ringan untuk repo Anda"))
	fmt.Println(ui.Wrap(ui.Gray, "target: "+root))
	fmt.Println()

	if len(findings) == 0 {
		fmt.Println(ui.Wrap(ui.Green, "✓ tidak ditemukan rahasia (\"secret\") di file yang dipindai"))
	} else {
		for _, f := range findings {
			sevColor := ui.Yellow
			switch f.Severity {
			case rules.SeverityCritical:
				sevColor = ui.Red
			case rules.SeverityHigh:
				sevColor = ui.Yellow
			}
			loc := fmt.Sprintf("%s:%d", f.File, f.Line)
			if f.Commit != "" {
				loc += " (commit " + f.Commit[:minInt(7, len(f.Commit))] + ")"
			}
			secret := f.Secret
			if !showSecrets {
				secret = scan.Mask(secret)
			}
			fmt.Printf("[%s] %-24s %s\n", ui.Wrap(sevColor, pad(string(f.Severity), 8)), pad(f.RuleID, 22), loc)
			fmt.Println("           " + ui.Wrap(ui.Gray, "secret: "+secret))
		}
	}

	bySev := map[string]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}
	fmt.Println()
	fmt.Printf("%s %d temuan (critical %d, high %d, medium %d) · %d file dipindai · %.1fs\n",
		ui.Wrap(ui.Gray, "──"), len(findings),
		bySev[rules.SeverityCritical], bySev[rules.SeverityHigh], bySev[rules.SeverityMedium],
		stats.FilesScanned, stats.DurationSecs)
}

type jsonReport struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Target   string         `json:"target"`
	Stats    scan.Stats     `json:"stats"`
	Findings []scan.Finding `json:"findings"`
}

func printJSON(target string, findings []scan.Finding, stats scan.Stats) {
	if findings == nil {
		findings = []scan.Finding{}
	}
	rep := jsonReport{
		Tool:     "csix-scan",
		Version:  version,
		Target:   target,
		Stats:    stats,
		Findings: findings,
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fatal(err.Error())
	}
	fmt.Println(string(b))
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, ui.Wrap(ui.Red, "error: ")+msg)
	os.Exit(2)
}

func warn(msg string) {
	fmt.Fprintln(os.Stderr, ui.Wrap(ui.Yellow, "peringatan: ")+msg)
}
