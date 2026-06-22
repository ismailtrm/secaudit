# secaudit

Passive domain reconnaissance with a terminal report. Give it a domain; it runs
read-only recon checks (DNS, TLS, RDAP, mail/HTTP security policy) and produces a
shareable markdown/JSON report and an interactive TUI.

> **Passive by default.** Active probing (port/vuln scans) is gated behind an
> ownership guardrail: scanning a third-party system you neither own nor are
> authorized to test is refused.

## Install

```sh
go install github.com/ismailtrm/secaudit@latest
```

Or from a clone:

```sh
go build -o secaudit .
```

## Usage

```sh
secaudit scan example.com                 # interactive TUI (default)
secaudit scan example.com --no-tui        # headless: print summary + write files
secaudit scan example.com --format json   # write only JSON
secaudit checkers list                    # show registered checkers + availability
```

Flags (`scan`):

| Flag | Default | Values |
|---|---|---|
| `--ownership` | `own` | `own`, `authorized`, `third-party` |
| `--mode` | `passive` | `passive`, `active` |
| `--no-tui` | `false` | headless mode |
| `--format` | `both` | `both`, `md`, `json`, `none` |
| `--out` | `.` | output directory for report files |

Reports are written as `report-<domain>-<timestamp>.{md,json}`.

## Checkers (passive)

| Checker | What it reports |
|---|---|
| `dns.records` | A/AAAA/MX/NS/SOA |
| `dns.policy` | CAA, SPF, DMARC, MTA-STS, TLS-RPT (with quality scoring) |
| `tls.cert` | certificate expiry, SAN/hostname, chain trust, protocol version |
| `http.headers` | server banner, redirect chain, CSP/HSTS/X-Frame-Options/Referrer-Policy |
| `rdap` | registrar, creation/expiry, nameservers, DNSSEC, hosting network |
| `osint.crtsh` | subdomains from Certificate Transparency logs (cached, retry on 502) |

crt.sh results are cached in a small SQLite TTL store (`~/.config/secaudit/cache.db`)
so repeated scans don't re-hit the flaky service.

Adding a checker is one file: implement `checker.Checker` and call
`checker.Register` from an `init()`. The engine and TUI discover it automatically.

## Architecture

```
cmd/            CLI (cobra): scan, checkers
internal/
  checker/      plugin contract + checkers + registry
  engine/       concurrent fan-out, streams Results
  tui/          bubbletea screens (wizard → progress → results)
  report/       markdown / JSON / text rendering
  guard/        ownership × mode authorization (the legal hard-fail)
  tool/         external-binary discovery (active checkers)
  cache/        SQLite TTL cache
  config/       on-disk paths
```
