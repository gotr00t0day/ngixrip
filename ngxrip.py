#!/usr/bin/env python3

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import urlparse

import requests

requests.packages.urllib3.disable_warnings()



NGINX_CVE_DB = [
    ("CVE-2019-20372", "medium", "HTTP request smuggling (error_page URL redirect)", [((1, 0, 0), (1, 17, 6))]),
    ("CVE-2019-9511", "medium", "Excessive CPU usage in HTTP/2 (small window updates)", [((1, 9, 5), (1, 17, 2))]),
    ("CVE-2019-9513", "low", "Excessive CPU usage in HTTP/2 (priority changes)", [((1, 9, 5), (1, 17, 2))]),
    ("CVE-2019-9516", "low", "Excessive memory usage in HTTP/2 (zero length headers)", [((1, 9, 5), (1, 17, 2))]),
    ("CVE-2018-16843", "low", "Excessive memory usage in HTTP/2", [((1, 9, 5), (1, 15, 5))]),
    ("CVE-2018-16844", "low", "Excessive CPU usage in HTTP/2", [((1, 9, 5), (1, 15, 5))]),
    ("CVE-2018-16845", "medium", "Memory disclosure in ngx_http_mp4_module", [((1, 1, 3), (1, 15, 5)), ((1, 0, 7), (1, 0, 15))]),
    ("CVE-2017-7529", "medium", "Integer overflow in range filter", [((0, 5, 6), (1, 13, 2))]),
    ("CVE-2016-4450", "medium", "NULL pointer dereference (client request body)", [((1, 3, 9), (1, 11, 0))]),
    ("CVE-2016-0742", "medium", "Invalid pointer dereference in resolver", [((0, 6, 18), (1, 9, 9))]),
    ("CVE-2016-0746", "medium", "Use-after-free in resolver (CNAME)", [((0, 6, 18), (1, 9, 9))]),
    ("CVE-2016-0747", "medium", "Insufficient limits of CNAME resolution", [((0, 6, 18), (1, 9, 9))]),
    ("CVE-2014-3616", "medium", "SSL session reuse vulnerability", [((0, 5, 6), (1, 7, 4))]),
    ("CVE-2014-3556", "medium", "STARTTLS command injection", [((1, 5, 6), (1, 7, 3))]),
    ("CVE-2014-0133", "major", "SPDY heap buffer overflow", [((1, 3, 15), (1, 5, 11))]),
    ("CVE-2013-4547", "medium", "Request line parsing vulnerability", [((0, 8, 41), (1, 5, 6))]),
    ("CVE-2022-41741", "medium", "Memory corruption in ngx_http_mp4_module", [((1, 1, 3), (1, 23, 1)), ((1, 0, 7), (1, 0, 15))]),
    ("CVE-2022-41742", "medium", "Memory disclosure in ngx_http_mp4_module", [((1, 1, 3), (1, 23, 1)), ((1, 0, 7), (1, 0, 15))]),
    ("CVE-2021-23017", "medium", "1-byte memory overwrite in resolver", [((0, 6, 18), (1, 20, 0))]),
    ("CVE-2024-7347", "low", "Buffer overread in ngx_http_mp4_module", [((1, 5, 13), (1, 27, 0))]),
]


def version_in_range(ver: tuple, min_v: tuple, max_v: tuple) -> bool:
    return min_v <= ver <= max_v


def is_affected(ver: tuple, cve_entry: tuple) -> bool:
    _, _, _, ranges = cve_entry
    for min_v, max_v in ranges:
        if version_in_range(ver, min_v, max_v):
            return True
    return False


def fetch_nvd_cves(version: str, timeout: int = 15) -> list[dict]:
    results = []
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": "nginx", "resultsPerPage": 30}
        r = requests.get(url, params=params, timeout=timeout)
        if r.status_code != 200:
            return results
        data = r.json()
        for v in data.get("vulnerabilities", [])[:20]:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id or cve_id in [e[0] for e in NGINX_CVE_DB]:
                continue
            desc = next((d.get("value", "")[:150] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            if "nginx" not in desc.lower():
                continue
            metrics = cve.get("metrics", {}) or {}
            cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
            severity = (cvss_list[0].get("cvssData", {}).get("baseSeverity", "unknown")).lower() if cvss_list else "unknown"
            results.append({"cve_id": cve_id, "severity": severity, "description": desc, "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})
        time.sleep(6)
    except Exception:
        pass
    return results


class Colors:
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    RESET = "\033[0m"


BANNER = r"""
 ________   ________     ___    ___ ________  ___  ________   
|\   ___  \|\   ____\   |\  \  /  /|\   __  \|\  \|\   __  \  
\ \  \\ \  \ \  \___|   \ \  \/  / | \  \|\  \ \  \ \  \|\  \ 
 \ \  \\ \  \ \  \  ___  \ \    / / \ \   _  _\ \  \ \   ____\
  \ \  \\ \  \ \  \|\  \  /     \/   \ \  \\  \\ \  \ \  \___|
   \ \__\\ \__\ \_______\/  /\   \    \ \__\\ _\\ \__\ \__\   
    \|__| \|__|\|_______/__/ /\ __\    \|__|\|__|\|__|\|__|   
                        |__|/ \|__|                           
                                                              
"""


def parse_nginx_version(server_header: str) -> tuple[str | None, tuple[int, ...] | None]:
    if not server_header:
        return None, None
    m = re.search(r"nginx/([\d.]+)", server_header, re.I)
    if not m:
        return None, None
    raw = m.group(1)
    try:
        parts = [int(x) for x in raw.split(".")[:3]]
        return raw, tuple(parts)
    except (ValueError, IndexError):
        return raw, None


NGINX_VERSION_RE = re.compile(r"nginx[/\s](\d+\.\d+(?:\.\d+)?)", re.I)

VERSION_HEADERS = ["Server", "X-Nginx-Version", "X-Powered-By", "X-Server", "X-Backend-Server"]


def fetch_response(url: str, path: str = "", timeout: int = 10, verify: bool = False):
    try:
        full_url = url.rstrip("/") + path if path else url
        r = requests.get(full_url, timeout=timeout, verify=verify, allow_redirects=True)
        return r, r.text
    except Exception:
        return None, ""


def extract_version_from_text(text: str) -> str | None:
    if not text:
        return None
    m = NGINX_VERSION_RE.search(text)
    return m.group(1) if m else None


def get_nginx_version(url: str, timeout: int = 10, verify: bool = False) -> tuple[str | None, str | None, str]:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    body = ""

    r, body = fetch_response(url, timeout=timeout, verify=verify)
    if r:
        for h in VERSION_HEADERS:
            val = r.headers.get(h)
            if val:
                ver = extract_version_from_text(val)
                if ver:
                    return ver, ("Server" if h.lower() == "server" else f"header:{h}"), val

        ver = extract_version_from_text(body[:50000])
        if ver:
            return ver, "body", None

    r, body = fetch_response(base, "/__ngxrip_404_probe__", timeout=timeout, verify=verify)
    if r and r.status_code == 404:
        for h in VERSION_HEADERS:
            val = r.headers.get(h)
            if val:
                ver = extract_version_from_text(val)
                if ver:
                    return ver, "404_header", val
        ver = extract_version_from_text(body[:20000])
        if ver:
            return ver, "404_body", None

    r, body = fetch_response(base, "/nginx_status", timeout=timeout, verify=verify)
    if r:
        for h in VERSION_HEADERS:
            val = r.headers.get(h)
            if val:
                ver = extract_version_from_text(val)
                if ver:
                    return ver, "nginx_status", val
        ver = extract_version_from_text(body[:20000])
        if ver:
            return ver, "nginx_status", None

    return None, None, None


def test_version(url: str, timeout: int, verify: bool) -> dict:
    result = {"nginx": False, "version": None, "eol": False, "source": None}
    ver, source, raw = get_nginx_version(url, timeout, verify)
    if not ver:
        return result

    result["nginx"] = True
    result["version"] = ver
    result["source"] = source or "Server"
    result["server_header"] = raw

    numeric = None
    try:
        parts = [int(x) for x in ver.split(".")[:3]]
        numeric = tuple(parts)
    except (ValueError, IndexError):
        pass

    if numeric is not None:
        result["eol"] = numeric < (1, 18, 0)

    return result


def run_nuclei_scan(url: str, timeout: int = 120) -> list[dict]:
    """
    Run Nuclei with nginx tags against the target URL.
    Returns list of findings (template-id, name, severity, matched-at, etc.).
    Requires nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    """
    if not shutil.which("nuclei"):
        return []

    cmd = [
        "nuclei",
        "-u", url,
        "-tags", "nginx",
        "-silent",
        "-jsonl",
        "-timeout", str(timeout),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
        findings = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return findings
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return []


def main():
    parser = argparse.ArgumentParser(description="NGX — nginx CVE scanner — version lookup + vuln database")
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout in seconds")
    parser.add_argument("-k", "--insecure", action="store_true", help="Skip SSL verification")
    parser.add_argument("--no-cve", action="store_true", help="Skip CVE database lookup")
    parser.add_argument("--nvd", action="store_true", help="Fetch additional CVEs from NVD API (slow, rate-limited)")
    parser.add_argument("--nuclei", action="store_true", help="Run Nuclei with nginx tags (requires nuclei installed)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    parser.add_argument("-j", "--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    verify = not args.insecure
    report = {"url": url, "nginx": False, "version": None, "cves": [], "nvd_cves": [], "nuclei": [], "tests": {}}

    if not args.quiet and not args.json:
        print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
        print(f"  {Colors.DIM}Target:{Colors.RESET} {url}\n")

    ver_result = test_version(url, args.timeout, verify)
    report["version_result"] = ver_result

    if ver_result["nginx"]:
        report["nginx"] = True
        report["version"] = ver_result["version"]
        ver_tuple = None
        try:
            parts = ver_result["version"].split(".")
            ver_tuple = tuple(int(x) for x in parts[:3])
        except (ValueError, IndexError):
            ver_tuple = None

        if not args.quiet and not args.json:
            src = ver_result.get("source", "Server")
            print(f"  {Colors.CYAN}›{Colors.RESET} Nginx: {ver_result['version']} {Colors.DIM}(from {src}){Colors.RESET}")

        if not args.no_cve and ver_tuple:
            affected = [e for e in NGINX_CVE_DB if is_affected(ver_tuple, e)]
            report["cves"] = [{"id": c[0], "severity": c[1], "description": c[2]} for c in affected]

            if not args.quiet and not args.json:
                if affected:
                    print(f"\n  {Colors.BOLD}CVE Database{Colors.RESET} ({len(affected)} affecting this version)\n")
                    for cve_id, sev, desc, _ in affected:
                        color = Colors.RED if sev in ("major", "high", "critical") else Colors.YELLOW if sev == "medium" else Colors.DIM
                        print(f"  {color}✗{Colors.RESET} {cve_id} [{sev}]")
                        print(f"    {Colors.DIM}│{Colors.RESET} {desc[:80]}…" if len(desc) > 80 else f"    {Colors.DIM}│{Colors.RESET} {desc}")
                        print(f"    {Colors.DIM}│{Colors.RESET} https://nvd.nist.gov/vuln/detail/{cve_id}")
                else:
                    print(f"\n  {Colors.GREEN}✓{Colors.RESET} No CVEs in database affecting this version")

            if args.nvd and ver_tuple:
                if not args.quiet and not args.json:
                    print(f"\n  {Colors.DIM}›{Colors.RESET} Fetching NVD API…")
                nvd = fetch_nvd_cves(ver_result["version"], args.timeout)
                report["nvd_cves"] = nvd
                if not args.quiet and not args.json and nvd:
                    print(f"  {Colors.CYAN}›{Colors.RESET} NVD: {len(nvd)} additional nginx-related CVEs (review manually)")
                    for c in nvd[:5]:
                        print(f"    {Colors.DIM}│{Colors.RESET} {c['cve_id']} [{c['severity']}] - {c['description'][:60]}…")

        if ver_result["eol"]:
            if not args.quiet and not args.json:
                print(f"  {Colors.YELLOW}!{Colors.RESET} Version is EOL - upgrade recommended")

    else:
        if not args.quiet and not args.json:
            print(f"  {Colors.YELLOW}!{Colors.RESET} Nginx not detected in Server header")

    if args.nuclei:
        if not args.quiet and not args.json:
            print(f"\n  {Colors.BOLD}Nuclei (nginx tags){Colors.RESET}")
            print(f"  {Colors.DIM}›{Colors.RESET} Running nuclei -tags nginx…")
        nuclei_findings = run_nuclei_scan(url, timeout=args.timeout * 6)
        report["nuclei"] = nuclei_findings
        if not args.quiet and not args.json:
            if not shutil.which("nuclei"):
                print(f"  {Colors.YELLOW}!{Colors.RESET} nuclei not found (install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)")
            elif nuclei_findings:
                print(f"  {Colors.RED}✗{Colors.RESET} {len(nuclei_findings)} finding(s)\n")
                for f in nuclei_findings[:15]:
                    tid = f.get("template-id", f.get("templateID", "?"))
                    info = f.get("info") or {}
                    name = info.get("name", tid) if isinstance(info, dict) else tid
                    sev = info.get("severity", "unknown") if isinstance(info, dict) else "unknown"
                    matched = f.get("matched-at", f.get("host", url))
                    color = Colors.RED if sev in ("critical", "high") else Colors.YELLOW if sev == "medium" else Colors.CYAN
                    print(f"    {color}•{Colors.RESET} {tid} [{sev}]")
                    print(f"      {Colors.DIM}│{Colors.RESET} {str(name)[:70]}{'…' if len(str(name)) > 70 else ''}")
                    print(f"      {Colors.DIM}│{Colors.RESET} {matched}")
            else:
                print(f"  {Colors.GREEN}✓{Colors.RESET} No nuclei findings")

    if not args.quiet and not args.json:
        print(f"\n  {Colors.DIM}Refs: nginx.org/security_advisories, NVD{Colors.RESET}\n")

    if args.json:
        out = {
            "url": report["url"],
            "nginx": report["nginx"],
            "version": report.get("version"),
            "cves": report.get("cves", []),
            "nvd_cves": report.get("nvd_cves", []),
            "nuclei": report.get("nuclei", []),
            "eol": ver_result.get("eol", False),
        }
        print(json.dumps(out, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
