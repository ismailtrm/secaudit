# secaudit

Domain reconnaissance with a terminal report. Give it a domain; it runs read-only
passive recon (DNS, TLS, RDAP, mail/HTTP security policy, CT logs, DNSSEC) and, on
targets you own or are authorized to test, optional active scans (nmap/nuclei/httpx).
Results land in a live split-pane TUI plus a shareable markdown/JSON report.

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
secaudit                       # full-screen launcher (centered search + mode bar)
secaudit example.com           # jump straight in (launcher prefilled)
secaudit example.com --no-tui  # headless: print summary + write report files
secaudit example.com --format json
secaudit checkers list         # registered checkers + availability
```

**Launcher keys:** type a domain · `tab` cycle ownership · `↑/↓` toggle mode
(passive only / passive + active) · `enter` scan · `esc` quit.
**Scanning keys:** `esc` cancel and return to launcher · `?` help · `ctrl+c` quit.
**Results keys:** `↑/↓` move · `←/→` switch passive/active pane · `PgDn/PgUp`
scroll detail · `f` filter by severity · `s` sort · `w` write report · `n` new
scan · `?` help · `q` quit.

The results screen splits passive findings (left) and active findings (right) with
a full-width detail pane below; a passive-only scan shows a single list. The
interactive UI runs full-screen (alternate screen) and restores your terminal on
exit. `--no-tui` is a plain headless run.

Flags:

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
| `rdap` | registrar, creation/expiry, nameservers, hosting network |
| `dns.dnssec` | live DNSSEC: DS at parent + DNSKEY/RRSIG at apex (chain of trust) |
| `dns.subdomains` | wordlist probe of common labels (with wildcard-DNS detection) |
| `osint.crtsh` | subdomains from Certificate Transparency logs (cached, retry on 502) |
| `osint.wayback` | Internet Archive snapshot availability (cached) |

crt.sh and Wayback results are cached in a small SQLite TTL store
(`~/.config/secaudit/cache.db`) so repeated scans don't re-hit flaky services.

## Checkers (active — own/authorized targets only)

Active checkers probe the target directly and only run with `--mode active`,
which the guardrail permits solely for `own`/`authorized` ownership. They shell
out to installed binaries and skip gracefully if a binary is missing. Findings
**stream into the live feed as they're discovered** (nuclei especially).

| Checker | What it does | Binary |
|---|---|---|
| `active.nmap` | top-1000 TCP port/service scan; flags risky exposed services (DB, telnet, Docker API, …) | `nmap` |
| `active.nuclei` | ProjectDiscovery template scan (low+ severity), streamed live | `nuclei` |
| `active.httpx` | alive-probe of the apex + discovered subdomains (cached crt.sh + wordlist) with tech detection | `httpx` |

```sh
secaudit example.com --mode active --ownership own   # headless active scan
# or pick "active" + "own" in the launcher's bottom bar
```

Adding a checker is one file: implement `checker.Checker` and call
`checker.Register` from an `init()`. The engine and TUI discover it automatically.

## Architecture

```
cmd/            CLI (cobra): scan, checkers
internal/
  checker/      plugin contract + checkers + registry
  engine/       concurrent fan-out, streams Results
  tui/          bubbletea screens (launcher → live scan → split-pane results)
  report/       markdown / JSON / text rendering
  guard/        ownership × mode authorization (the legal hard-fail)
  tool/         external-binary discovery (active checkers)
  cache/        SQLite TTL cache
  config/       on-disk paths
```
