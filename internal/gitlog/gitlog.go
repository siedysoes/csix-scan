// Package gitlog memindai riwayat commit git untuk rahasia yang pernah
// masuk ke history (biasanya lebih berbahaya daripada file di working tree).
package gitlog

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/siedysoes/csix-scan/internal/scan"
)

var hunkRE = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// ScanHistory menjalankan `git log -p` di root dan memindai setiap baris yang
// ditambahkan pada diff commit. Temuan didedup berdasarkan rule+file+secret
// agar history panjang tidak berisik.
func ScanHistory(root string) ([]scan.Finding, error) {
	cmd := exec.Command("git", "-C", root, "log", "-p", "-U0", "--no-color", "--full-history")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to run git: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)

	commit, file := "", ""
	newLine := 0
	seen := map[string]bool{}
	var findings []scan.Finding

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "commit "):
			f := strings.Fields(line)
			if len(f) >= 2 {
				commit = f[1]
			}
		case strings.HasPrefix(line, "+++ b/"):
			file = strings.TrimPrefix(line, "+++ b/")
		case strings.HasPrefix(line, "@@ "):
			if m := hunkRE.FindStringSubmatch(line); m != nil {
				newLine, _ = strconv.Atoi(m[1])
			}
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			content := line[1:]
			for _, f := range scan.ScanLine(file, content, newLine) {
				key := f.RuleID + "|" + f.File + "|" + f.Secret
				if seen[key] {
					continue
				}
				seen[key] = true
				f.Commit = commit
				findings = append(findings, f)
			}
			newLine++
		}
	}

	scanErr := scanner.Err()
	waitErr := cmd.Wait()
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if scanErr == nil && (strings.Contains(msg, "not a git repository") ||
			strings.Contains(msg, "does not have any commits yet")) {
			return nil, nil
		}
		return nil, fmt.Errorf("git log failed: %s", msg)
	}
	if scanErr != nil {
		return nil, scanErr
	}
	return findings, nil
}
