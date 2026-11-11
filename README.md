# csix-scan

**Pemindai rahasia (secret scanner) ringan untuk repository — murni Go, nol dependency, single binary.**

[![CI](https://github.com/siedysoes/csix-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/siedysoes/csix-scan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`csix-scan` mendeteksi API key, token, kredensial, dan private key yang
tertanam di file atau **riwayat commit git** — sebelum penyerang menemukannya
lebih dulu. Output JSON + exit code bawaan membuatnya mudah dipakai sebagai
gerbang CI.

## Fitur

- 🔍 **22 pola deteksi**: AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI,
  Twilio, SendGrid, npm, Telegram, Mailgun, JWT, private key (PEM),
  connection string DB, URL basic-auth, dan assignment generik
- 🧠 **Validasi entropy Shannon** + filter placeholder untuk menekan false positive
- 📜 **Scan riwayat commit** (`--history`) — rahasia yang pernah masuk ke
  git tetap terdeteksi walaupun sudah dihapus dari file
- 🎨 Output berwarna, nilai rahasia **disamarkan secara default**
- 📦 `--json` untuk integrasi tooling/CI
- ⚡ Single binary, tanpa runtime, tanpa koneksi jaringan

## Instalasi

```sh
go install github.com/siedysoes/csix-scan@latest
```

Atau build dari source:

```sh
git clone https://github.com/siedysoes/csix-scan
cd csix-scan
go build -o csix-scan .
```

## Penggunaan

```sh
# pindai direktori saat ini
csix-scan .

# pindai direktori tertentu + riwayat commit git
csix-scan --history ./proyek-anda

# output JSON untuk CI
csix-scan --json .
```

Contoh output:

```
csix-scan v0.1.0 — pemindai rahasia ringan untuk repo Anda
target: C:\proyek\backend

[CRITICAL] github-pat               src/config.go:12
           secret: ghp_****...b3fA
[CRITICAL] private-key              keys/prod.pem:1
           secret: -----B...KEY-----

── 2 temuan (critical 2, high 0, medium 0) · 143 file dipindai · 0.3s
```

## Opsi

| Flag | Fungsi |
|------|--------|
| `--history` | Pindai juga riwayat commit git |
| `--json` | Output JSON |
| `--show-secrets` | Tampilkan nilai rahasia utuh (default: disamarkan) |
| `--exclude <a,b>` | Lewati direktori tertentu (dipisah koma) |
| `--max-file-mb <n>` | Batas ukuran file (default 10 MB) |
| `--no-color` | Matikan warna (juga menghormati `NO_COLOR`) |
| `--version` | Tampilkan versi |

**Exit code:** `0` bersih · `1` ditemukan rahasia · `2` error

## Integrasi CI

```yaml
- name: Scan untuk rahasia bocor
  run: |
    go install github.com/siedysoes/csix-scan@latest
    csix-scan --history .
```

## Catatan

Ini alat **heuristik**. Ia bisa menghasilkan false positive — karena itu
temuan harus ditinjau manusia, bukan langsung dianggap kebocoran nyata.
Selalu verifikasi sebelum memutuskan suatu token rahasia.

## Dukungan Bahasa

- English (this file)
- [Bahasa Indonesia](README.id.md)

## Lisensi

MIT — lihat [LICENSE](LICENSE). Gunakan hanya untuk tujuan defensif dan
audit keamanan milik Anda sendiri.
