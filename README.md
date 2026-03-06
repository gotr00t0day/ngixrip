# NGXRIP

Nginx CVE scanner — detects nginx version (Server header + fallbacks), checks against a curated vuln database, and optionally runs Nuclei with nginx tags.

## Features

- **Version detection** — Parses nginx version from HTTP `Server` header (with fallbacks)
- **CVE lookup** — 20+ CVEs from nginx.org security advisories and NVD
- **EOL warning** — Flags end-of-life versions
- **NVD API** — Optional fetch for additional nginx-related CVEs
- **Nuclei module** — Run Nuclei with nginx tags for template-based vuln scanning
- **JSON output** — Machine-readable format for automation

## Installation

```bash
pip install requests
```

## Usage

```bash
# Basic scan
python ngxrip.py https://example.com

# Skip SSL verification (for self-signed certs)
python ngxrip.py https://example.com -k

# JSON output
python ngxrip.py https://example.com -j

# Quiet mode (minimal output)
python ngxrip.py https://example.com -q

# Fetch additional CVEs from NVD API (slow, rate-limited)
python ngxrip.py https://example.com --nvd

# Run Nuclei with nginx tags (requires nuclei installed)
python ngxrip.py https://example.com --nuclei
```

## Options

| Flag | Description |
|------|-------------|
| `-k, --insecure` | Skip SSL certificate verification |
| `-t, --timeout` | Request timeout in seconds (default: 10) |
| `--no-cve` | Skip CVE database lookup |
| `--nvd` | Fetch additional CVEs from NVD API |
| `--nuclei` | Run Nuclei with nginx tags (requires [nuclei](https://github.com/projectdiscovery/nuclei) installed) |
| `-q, --quiet` | Minimal output |
| `-j, --json` | JSON output |

## Example Output

```
 ________   ________     ___    ___ ________  ___  ________   
|\   ___  \|\   ____\   |\  \  /  /|\   __  \|\  \|\   __  \  
\ \  \\ \  \ \  \___|   \ \  \/  / | \  \|\  \ \  \ \  \|\  \ 
 \ \  \\ \  \ \  \  ___  \ \    / / \ \   _  _\ \  \ \   ____\
  \ \  \\ \  \ \  \|\  \  /     \/   \ \  \\  \\ \  \ \  \___|
   \ \__\\ \__\ \_______\/  /\   \    \ \__\\ _\\ \__\ \__\   
    \|__| \|__|\|_______/__/ /\ __\    \|__|\|__|\|__|\|__|   
                        |__|/ \|__|                           
                                                

  Target: https://example.com

  › Server: nginx/1.15.12
  › Nginx: 1.15.12

  CVE Database (8 affecting this version)

  ✗ CVE-2019-20372 [medium]
    │ HTTP request smuggling (error_page URL redirect)
    │ https://nvd.nist.gov/vuln/detail/CVE-2019-20372
  ✗ CVE-2019-9511 [medium]
    │ Excessive CPU usage in HTTP/2 (small window updates)
  ...

  ! Version is EOL - upgrade recommended
```

## JSON Output

```json
{
  "url": "https://example.com",
  "nginx": true,
  "version": "1.15.12",
  "cves": [
    {
      "id": "CVE-2019-20372",
      "severity": "medium",
      "description": "HTTP request smuggling (error_page URL redirect)"
    }
  ],
  "nvd_cves": [],
  "nuclei": [],
  "eol": true
}
```

## CVE Database

The built-in database includes CVEs from [nginx.org security advisories](https://nginx.org/en/security_advisories.html), including:

- CVE-2019-20372 — HTTP request smuggling
- CVE-2019-9511, CVE-2019-9513, CVE-2019-9516 — HTTP/2 DoS
- CVE-2018-16843, CVE-2018-16844, CVE-2018-16845 — HTTP/2, mp4 module
- CVE-2017-7529 — Integer overflow (range filter)
- CVE-2022-41741, CVE-2022-41742 — mp4 module memory issues
- CVE-2024-7347 — Buffer overread (mp4)
- And more...

## Nuclei Integration

With `--nuclei`, ngxrip runs [Nuclei](https://github.com/projectdiscovery/nuclei) using only nginx-tagged templates:

```bash
nuclei -u <url> -tags nginx -silent -jsonl
```

**Install Nuclei:**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates   # fetch nginx templates
```

Findings are parsed from JSONL output and included in the report and JSON export.

## References

- [nginx security advisories](https://nginx.org/en/security_advisories.html)
- [NVD](https://nvd.nist.gov/)
- [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates)
