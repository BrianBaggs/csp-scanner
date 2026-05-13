# CSP Scanner

A Python script that fetches and audits the `Content-Security-Policy` header of any target URL, flags misconfigurations and weaknesses by severity, and generates rich reports in HTML, JSON, and plain-text formats.

> **Warning:** This tool is intended for authorized penetration testing only. Only scan targets you have explicit permission to test. The author is not responsible for any misuse.

---

## Table of Contents

- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Options](#options)
  - [Examples](#examples)
- [Output](#output)
- [Severity Levels](#severity-levels)
- [Checks Performed](#checks-performed)
- [License](#license)

---

## Requirements

- Python 3.9+
- No external dependencies — uses the standard library only

---

## Quick Start

```bash
python3 csp-scanner.py -u https://example.com
```

Reports are automatically saved to a timestamped folder under `results/`.

---

## Usage

```
python3 csp-scanner.py -u <URL> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-u`, `--url` **(required)** | Target URL to scan. Must begin with `http://` or `https://`. |
| `-o`, `--output` | Directory to save report files. Defaults to an auto-generated folder under `results/`. |
| `--no-save` | Print findings to the terminal only. No files are written to disk. |
| `--min-severity` | Minimum severity level to display. Choices: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Defaults to `INFO` (show all). |

### Examples

```bash
# Scan a URL and save all reports (default behavior)
python3 csp-scanner.py -u https://example.com

# Save the report to a custom directory
python3 csp-scanner.py -u https://example.com -o results/my-scan/

# Print findings to the terminal only — no files saved
python3 csp-scanner.py -u https://example.com --no-save

# Show only HIGH and CRITICAL findings
python3 csp-scanner.py -u https://example.com --min-severity HIGH
```

---

## Output

Unless `--no-save` is used, three report files are written to:

```
results/csp-scan_<host>_<timestamp>/
├── report.html     ← Self-contained, styled HTML report (recommended)
├── report.txt      ← Plain-text summary
└── findings.json   ← Machine-readable JSON for further processing
```

A color-coded summary is also printed to the terminal during every run.

---

## Severity Levels

Findings are grouped and ordered by severity:

| Level | Color | Meaning |
|-------|-------|---------|
| `CRITICAL` | Red (bold) | Immediate risk — CSP can be fully bypassed or is absent |
| `HIGH` | Red | Significant weakness enabling script injection or XSS |
| `MEDIUM` | Yellow | Notable misconfiguration that broadens the attack surface |
| `LOW` | Blue | Minor issue or use of deprecated directives |
| `INFO` | Cyan | Informational observation — no direct security risk |

---

## Checks Performed

### Critical
- Missing CSP header entirely
- Wildcard (`*`) in `script-src` or `default-src`
- `Content-Security-Policy-Report-Only` with no enforcement header

### High
- `'unsafe-inline'` or `'unsafe-eval'` in script sources
- Missing `object-src` or `base-uri` directives
- Missing `frame-ancestors` directive
- `data:`, `blob:`, `http:`, or `https:` schemes in `script-src`
- Known CDN/JSONP bypass domains (e.g., `ajax.googleapis.com`, `cdn.jsdelivr.net`, `unpkg.com`)
- Static or predictable nonce values

### Medium
- `'unsafe-inline'` in style sources
- `'unsafe-hashes'` usage
- Missing `form-action` directive
- Broad wildcard host patterns
- `'strict-dynamic'` without a nonce or hash
- Unrestricted `connect-src`
- Missing `worker-src` directive

### Low
- Use of deprecated CSP directives
- No violation reporting endpoint configured
- Deprecated CSP headers present
- Missing `default-src` fallback
- Deprecated `navigate-to` directive

### Info
- `Content-Security-Policy-Report-Only` mode active
- Nonce or hash sources detected
- `upgrade-insecure-requests` present
- `sandbox` directive in use
- `trusted-types` configured
- `wasm-unsafe-eval` present
- `X-Frame-Options` header note

---

## License

Open-source — free to use and modify. Redistribution for sale is not permitted.
