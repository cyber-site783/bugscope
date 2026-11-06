#!/usr/bin/env python3
"""
BugScope v1 - Recon and Safe Vulnerability Checker

A small Python tool for learning bug bounty and reconnaissance.
It performs only safe, non-destructive checks on authorized targets.

Use only on authorized targets:
- Your own lab (localhost, your own virtual machines)
- Practice sites (OWASP Juice Shop on localhost:3000, DVWA on localhost:8080)
- A bug bounty program or client domain, only when it is in scope
  and you have written permission

What it does:
1. Resolves the domain to an IP address (DNS)
2. Finds subdomains from crt.sh (public certificate logs)
3. Checks whether the website is live
4. Checks for missing security headers
5. Checks whether common files are exposed (read-only GET requests)
6. Saves the results to a text report

Usage:
    python3 bugscope.py --domain example.com
    python3 bugscope.py --url http://localhost:3000
    python3 bugscope.py --domain example.com --output report.txt
"""

import argparse
import socket
import sys
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("The 'requests' library is not installed.")
    print("On Kali Linux, run: sudo apt install python3-requests -y")
    sys.exit(1)


# Security headers that a well-configured website should send
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

# Read-only paths to check. Nothing is changed or deleted.
COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
]


def clean_domain(user_input):
    """Extract a clean domain name from a URL or domain string."""
    user_input = user_input.strip()
    if "://" not in user_input:
        user_input = "http://" + user_input
    parsed = urlparse(user_input)
    return parsed.netloc.split(":")[0]


def get_ip(domain):
    """Resolve a domain name to an IP address using DNS."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_subdomains(domain):
    """Find subdomains from crt.sh (public certificate transparency logs)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            return []
        data = response.json()
        found = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and "*" not in sub and sub.endswith(domain):
                    found.add(sub)
        return sorted(found)
    except Exception:
        return []


def check_website(url):
    """Check whether a website is reachable and return its response."""
    try:
        return requests.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"[!] Could not connect to the website: {e}")
        return None


def check_headers(response):
    """Return the security headers that are present and missing."""
    missing = []
    present = []
    for header in SECURITY_HEADERS:
        if header in response.headers:
            present.append(header)
        else:
            missing.append(header)
    return present, missing


def check_common_paths(base_url):
    """Check the HTTP status code of common paths (read-only)."""
    results = []
    for path in COMMON_PATHS:
        try:
            response = requests.get(base_url + path, timeout=5)
            results.append((path, response.status_code))
        except requests.exceptions.RequestException:
            results.append((path, "error"))
    return results


def main():
    parser = argparse.ArgumentParser(description="BugScope v1 - Recon and Safe Checker")
    parser.add_argument("--domain", help="Domain, for example example.com")
    parser.add_argument("--url", help="Full URL, for example http://localhost:3000")
    parser.add_argument("--output", default="bugscope-report.txt",
                        help="Report file name (default: bugscope-report.txt)")
    args = parser.parse_args()

    if not args.domain and not args.url:
        parser.print_help()
        print("\nExample: python3 bugscope.py --domain example.com")
        return

    target = args.url if args.url else args.domain
    domain = clean_domain(target)
    base_url = target if target.startswith("http") else "https://" + domain

    print(f"\n[+] BugScope v1 - Target: {domain}")
    print(f"[+] Time: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines = []
    lines.append(f"BugScope v1 Report - {domain}")
    lines.append(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("")

    # Step 1 - IP address
    print("\n[1] Resolving IP address (DNS)...")
    ip = get_ip(domain)
    if ip:
        print(f"    IP: {ip}")
        lines.append(f"IP: {ip}")
    else:
        print("    IP not found. Is the domain spelled correctly?")
        lines.append("IP: not found")

    # Step 2 - Subdomains
    print("\n[2] Finding subdomains (crt.sh)...")
    subs = get_subdomains(domain)
    if subs:
        print(f"    Found {len(subs)} subdomains:")
        for sub in subs[:20]:
            print(f"    - {sub}")
        lines.append(f"Subdomains ({len(subs)}): {', '.join(subs)}")
    else:
        print("    No subdomains found (or crt.sh did not respond).")
        lines.append("Subdomains: none found")

    # Step 3 - Website and headers
    print(f"\n[3] Checking website: {base_url} ...")
    response = check_website(base_url)
    if response is None:
        print("    Website did not open, skipping the remaining checks.")
        lines.append("Website: did not open")
    else:
        print(f"    Status: {response.status_code}")
        print(f"    Server: {response.headers.get('Server', 'unknown')}")
        lines.append(f"Website status: {response.status_code}")
        lines.append(f"Server header: {response.headers.get('Server', 'unknown')}")

        present, missing = check_headers(response)
        print("\n[4] Checking security headers...")
        for header in present:
            print(f"    [OK] {header} is present")
        for header in missing:
            print(f"    [MISSING] {header} is not present")
        lines.append(f"Headers present: {', '.join(present) if present else 'none'}")
        lines.append(f"Headers missing: {', '.join(missing) if missing else 'none'}")

        # Step 5 - Common paths
        print("\n[5] Checking common files (read-only, nothing is changed)...")
        for path, status in check_common_paths(base_url):
            print(f"    {path} -> {status}")
            lines.append(f"{path} -> {status}")

    # Save the report
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[+] Report saved: {args.output}")
    print("[+] Done. Read the report and review the missing headers.")


if __name__ == "__main__":
    main()
