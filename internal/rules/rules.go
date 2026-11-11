// Package rules berisi pola deteksi rahasia (secret) yang digunakan csix-scan.
package rules

import (
	"math"
	"regexp"
	"strings"
)

// Tingkat keparahan temuan.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
)

// Rule adalah satu pola deteksi secret.
type Rule struct {
	ID       string         // identitas aturan, mis. "github-pat"
	Title    string         // nama yang mudah dibaca manusia
	Severity string         // critical | high | medium
	Pattern  *regexp.Regexp // pola regex (RE2)
	// SecretGroup adalah index capture group yang berisi nilai rahasia.
	// 0 berarti seluruh hasil cocok adalah nilainya.
	SecretGroup int
	// MinEntropy adalah ambang entropy Shannon minimum (0 = tidak dicek).
	MinEntropy float64
}

// Rules adalah daftar semua pola deteksi.
var Rules = []Rule{
	{
		ID:       "aws-access-key-id",
		Title:    "AWS Access Key ID",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
	},
	{
		ID:       "github-pat",
		Title:    "GitHub Personal Access Token",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b(ghp_[0-9A-Za-z]{36})\b`),
	},
	{
		ID:       "github-oauth-token",
		Title:    "GitHub OAuth/App Token",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b(gh[ousr]_[0-9A-Za-z]{36})\b`),
	},
	{
		ID:       "github-fine-grained-pat",
		Title:    "GitHub Fine-Grained PAT",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b(github_pat_[0-9A-Za-z_]{22,})\b`),
	},
	{
		ID:       "gitlab-pat",
		Title:    "GitLab Personal Access Token",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b(glpat-[0-9A-Za-z_-]{20,})\b`),
	},
	{
		ID:       "slack-token",
		Title:    "Slack Token",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z-]{10,})\b`),
	},
	{
		ID:       "slack-webhook",
		Title:    "Slack Incoming Webhook URL",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+`),
	},
	{
		ID:       "google-api-key",
		Title:    "Google API Key",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`),
	},
	{
		ID:       "stripe-live-key",
		Title:    "Stripe Live Secret Key",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b([sr]k_live_[0-9A-Za-z]{20,})\b`),
	},
	{
		ID:       "openai-api-key",
		Title:    "OpenAI API Key",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b(sk-[A-Za-z0-9_-]{20,})\b`),
	},
	{
		ID:       "twilio-api-key",
		Title:    "Twilio API Key",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b(SK[0-9a-f]{32})\b`),
	},
	{
		ID:       "sendgrid-key",
		Title:    "SendGrid API Key",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b(SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64})\b`),
	},
	{
		ID:       "npm-token",
		Title:    "npm Access Token",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`),
	},
	{
		ID:       "telegram-bot-token",
		Title:    "Telegram Bot Token",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b([0-9]{8,10}:AA[A-Za-z0-9_-]{33,})\b`),
	},
	{
		ID:       "mailgun-key",
		Title:    "Mailgun API Key",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\b(key-[0-9A-Za-z]{32})\b`),
	},
	{
		ID:       "private-key",
		Title:    "Private Key (PEM)",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`),
	},
	{
		ID:       "jwt",
		Title:    "JSON Web Token (JWT)",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`),
	},
	{
		ID:       "db-connection-string",
		Title:    "Database connection string with credentials",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/"']+:[^\s@/"']+@[^\s"']+)`),
	},
	{
		ID:       "basic-auth-url",
		Title:    "URL with embedded credentials (basic auth)",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\bhttps?://[^\s:@/"']:[^\s@/"']+@`),
	},
	{
		ID:       "aws-secret-key",
		Title:    "AWS Secret Access Key",
		Severity: SeverityCritical,
		Pattern:  regexp.MustCompile(`(?i)aws.{0,40}?secret.{0,20}?["']([A-Za-z0-9/+=]{40})["']`),
	},
	{
		ID:          "generic-secret-quoted",
		Title:       "Credential-like assignment (quoted value)",
		Severity:    SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?key|client[_-]?secret)\s*[:=]\s*["']([^"'\s]{8,})["']`),
		SecretGroup: 1,
		MinEntropy:  3.0,
	},
	{
		ID:          "generic-secret-unquoted",
		Title:       "Credential-like assignment (unquoted value)",
		Severity:    SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s"';,]{8,})`),
		SecretGroup: 1,
		MinEntropy:  3.2,
	},
}

// Entropy menghitung entropy Shannon (bits/char) dari sebuah string.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]float64, len(s))
	total := 0.0
	for _, r := range s {
		freq[r]++
		total++
	}
	var e float64
	for _, c := range freq {
		p := c / total
		e -= p * math.Log2(p)
	}
	return e
}

var placeholderWords = map[string]bool{
	"example": true, "sample": true, "test": true, "dummy": true,
	"placeholder": true, "changeme": true, "change-me": true, "password": true,
	"secret": true, "yourpassword": true, "your_password": true, "newpassword": true,
	"yourtoken": true, "todo": true, "fixme": true, "redacted": true,
	"hidden": true, "insert": true, "xxxxxxxx": true, "password123": true,
	"12345678": true, "123456789": true, "abcdef": true, "qwerty": true,
}

var (
	placeholdersOnlyRE = regexp.MustCompile(`^[xX*._\-~<>]+$`)
	numericOnlyRE      = regexp.MustCompile(`^\d+$`)
)

// IsPlaceholder mengecek apakah sebuah nilai adalah placeholder, bukan rahasia nyata.
func IsPlaceholder(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	if placeholderWords[l] {
		return true
	}
	if placeholdersOnlyRE.MatchString(l) {
		return true
	}
	if numericOnlyRE.MatchString(l) {
		return true
	}
	if strings.Contains(l, "${") || strings.HasPrefix(l, "$(") {
		return true
	}
	if strings.HasPrefix(l, "<") {
		return true
	}
	if strings.Contains(l, "example.com") || strings.Contains(l, "example.net") {
		return true
	}
	return false
}

// SeverityRank mengembalikan urutan prioritas keparahan untuk pengurutan.
func SeverityRank(sev string) int {
	switch sev {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	}
	return 3
}
