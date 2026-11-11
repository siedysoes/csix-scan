// Package scan mengimplementasikan pemindaian file untuk rahasia.
package scan

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/siedysoes/csix-scan/internal/rules"
)

// Finding adalah satu temuan rahasia.
type Finding struct {
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Secret   string `json:"secret"`
	Match    string `json:"match"`
	Commit   string `json:"commit,omitempty"`
}

// Stats adalah ringkasan hasil pemindaian.
type Stats struct {
	FilesScanned int     `json:"files_scanned"`
	DurationSecs float64 `json:"duration_secs"`
}

var defaultSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "__pycache__": true,
	"dist": true, "build": true, "target": true, ".idea": true, ".vscode": true,
	".next": true, ".terraform": true, ".venv": true, "venv": true,
}

// ScanPath memindai seluruh file teks di bawah root (rekursif).
func ScanPath(root string, maxBytes int64, extraSkip map[string]bool) (findings []Finding, stats Stats, err error) {
	start := time.Now()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return nil
		}
		if d.IsDir() {
			if defaultSkipDirs[d.Name()] || (extraSkip != nil && extraSkip[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		info, e2 := d.Info()
		if e2 != nil || info.Size() == 0 || info.Size() > maxBytes {
			return nil
		}
		data, e3 := os.ReadFile(path)
		if e3 != nil || isBinary(data) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		findings = append(findings, ScanText(rel, string(data))...)
		stats.FilesScanned++
		return nil
	})
	stats.DurationSecs = time.Since(start).Seconds()
	return findings, stats, err
}

// isBinary mendeteksi file biner lewat keberadaan byte NUL di awal file.
func isBinary(data []byte) bool {
	n := len(data)
	if n > 2048 {
		n = 2048
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}

// ScanText memindai konten teks dan mengembalikan daftar temuan.
func ScanText(name, content string) []Finding {
	var out []Finding
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		out = append(out, ScanLine(name, strings.TrimRight(line, "\r"), i+1)...)
	}
	return out
}

// ScanLine memindai satu baris teks terhadap seluruh aturan.
func ScanLine(name, text string, lineNo int) []Finding {
	var out []Finding
	for _, r := range rules.Rules {
		for _, m := range r.Pattern.FindAllStringSubmatch(text, -1) {
			secret := m[0]
			if r.SecretGroup > 0 && r.SecretGroup < len(m) {
				secret = m[r.SecretGroup]
			}
			if r.MinEntropy > 0 && rules.Entropy(secret) < r.MinEntropy {
				continue
			}
			if rules.IsPlaceholder(secret) {
				continue
			}
			out = append(out, Finding{
				RuleID:   r.ID,
				Title:    r.Title,
				Severity: r.Severity,
				File:     name,
				Line:     lineNo,
				Secret:   secret,
				Match:    strings.TrimSpace(text),
			})
		}
	}
	return dedupeLine(out)
}

// dedupeLine menggabungkan temuan rahasia yang sama di baris yang sama,
// menyimpan aturan dengan keparahan tertinggi.
func dedupeLine(fs []Finding) []Finding {
	if len(fs) < 2 {
		return fs
	}
	seen := map[string]int{}
	var res []Finding
	for _, f := range fs {
		if i, ok := seen[f.Secret]; ok {
			if rules.SeverityRank(f.Severity) < rules.SeverityRank(res[i].Severity) {
				res[i] = f
			}
			continue
		}
		seen[f.Secret] = len(res)
		res = append(res, f)
	}
	return res
}

// Mask menyamarkan nilai rahasia agar aman ditampilkan/dicopy.
func Mask(s string) string {
	r := []rune(s)
	if len(r) <= 12 {
		return "****"
	}
	return string(r[:5]) + "..." + string(r[len(r)-4:])
}

// SortFindings mengurutkan temuan: keparahan, lalu file, lalu baris.
func SortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		ri, rj := rules.SeverityRank(fs[i].Severity), rules.SeverityRank(fs[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}
