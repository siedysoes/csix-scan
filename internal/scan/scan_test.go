package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/siedysoes/csix-scan/internal/rules"
)

func TestEntropy(t *testing.T) {
	if got := rules.Entropy("aaaa"); got > 0.01 {
		t.Errorf("entropy('aaaa') = %v, harus ~0", got)
	}
	if got := rules.Entropy("ab"); got < 0.99 || got > 1.01 {
		t.Errorf("entropy('ab') = %v, harus ~1", got)
	}
}

func TestScanLineDetectsSecrets(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantRule string
	}{
		{"aws key", `const AK = "AKIAIOSFODNN7EXAMPLE"`, "aws-access-key-id"},
		{"github pat", `ghp_` + strings.Repeat("a", 36), "github-pat"},
		{"private key", `-----BEGIN RSA PRIVATE KEY-----`, "private-key"},
		{"db url", `DSN="postgres://produser:Sup3rS3cretPw@db.example.org/app"`, "db-connection-string"},
		{"slack webhook", "curl -X POST " + slackWebhookFixture(), "slack-webhook"},
		{"quoted password", `password: "Tr0ub4dor&3xample!"`, "generic-secret-quoted"},
		{"unquoted token", `DB_PASSWORD=Kx9$wQ2#nLp7vRt8`, "generic-secret-unquoted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := ScanLine("test.txt", tt.line, 1)
			for _, f := range fs {
				if f.RuleID == tt.wantRule {
					return
				}
			}
			t.Errorf("tidak menemukan rule %q pada baris: %q (dapat: %v)", tt.wantRule, tt.line, fs)
		})
	}
}

func TestScanLineIgnoresPlaceholders(t *testing.T) {
	lines := []string{
		`password = "changeme"`,
		`password = "xxxxxxxx"`,
		`password = "123456789"`,
		`secret = "<your-secret-here>"`,
		`API_KEY = "${API_KEY}"`,
	}
	for _, l := range lines {
		if fs := ScanLine("test.txt", l, 1); len(fs) > 0 {
			t.Errorf("placeholder %q seharusnya tidak jadi temuan, dapat %v", l, fs)
		}
	}
}

func TestScanTextLineNumbering(t *testing.T) {
	content := "baris biasa\npassword = \"Tr0ub4dor&3xample!\"\n"
	fs := ScanText("app.py", content)
	if len(fs) != 1 {
		t.Fatalf("diharapkan 1 temuan, dapat %d", len(fs))
	}
	if fs[0].Line != 2 || fs[0].File != "app.py" {
		t.Errorf("posisi salah: file=%q line=%d", fs[0].File, fs[0].Line)
	}
}

func TestScanPath(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("tidak ada rahasia di sini\n"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "dirty.env"), []byte("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "bin.dat"), []byte{0x00, 0x01, 0x02}, 0o644))
	must(os.Mkdir(filepath.Join(dir, ".git"), 0o755))
	must(os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(`token = "xoxb-000000000000000000000000000000"`), 0o644))

	findings, stats, err := ScanPath(dir, 10*1024*1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesScanned != 2 {
		t.Errorf("diharapkan 2 file dipindai, dapat %d (biner & .git harus dilewati)", stats.FilesScanned)
	}
	if len(findings) != 1 || findings[0].RuleID != "aws-access-key-id" {
		t.Errorf("diharapkan 1 temuan aws, dapat %v", findings)
	}
}

func TestMask(t *testing.T) {
	if got := Mask("pendek"); got != "****" {
		t.Errorf("Mask pendek = %q", got)
	}
	long := "ghp_abcdefghijklmnopqrstuvwxyz1234567"
	if got := Mask(long); !strings.Contains(got, "...") {
		t.Errorf("Mask panjang = %q", got)
	}
}

// slackWebhookFixture membangun URL webhook contoh saat runtime — sengaja
// tidak ditulis utuh di file agar tidak memicu GitHub Push Protection
// (deteksi rahasia saat push).
func slackWebhookFixture() string {
	return "https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
}
