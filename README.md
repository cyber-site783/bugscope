# BugScope

A beginner-friendly Python tool for reconnaissance and safe vulnerability checks, built for learning bug bounty hunting.

BugScope performs only safe, non-destructive checks. It reads public information and HTTP headers. It does not exploit vulnerabilities, brute-force logins, or change anything on the target.

## Authorized use only

Use BugScope only on targets you are allowed to test:

- Your own lab (localhost, your own virtual machines)
- Practice applications such as OWASP Juice Shop (`http://localhost:3000`) and DVWA (`http://localhost:8080`)
- A bug bounty program or a client domain, only when it is in scope and you have written permission

Never scan a website without permission.

## Quick start

```bash
git clone https://github.com/cyber-site783/bugscope.git
cd bugscope
sudo apt install python3-requests -y
python3 bugscope.py --domain example.com
```

## What it checks

1. **DNS / IP** — resolves the domain to an IP address
2. **Subdomains** — finds subdomains from crt.sh (public certificate transparency logs)
3. **Website status** — checks whether the website is live and reads the server header
4. **Security headers** — checks for missing headers:
   - `Strict-Transport-Security`
   - `Content-Security-Policy`
   - `X-Frame-Options`
   - `X-Content-Type-Options`
   - `Referrer-Policy`
5. **Exposed files** — checks the status code of common paths (`/robots.txt`, `/sitemap.xml`, `/.git/HEAD`) with read-only GET requests
6. **Report** — saves all results to a text report

## Installation

Python 3 and the `requests` library are required.

On Kali Linux:

```bash
sudo apt update
sudo apt install python3-requests -y
```

On other systems:

```bash
pip install -r requirements.txt
```

Check that `requests` is installed:

```bash
python3 -c "import requests; print('ok')"
```

## Usage

```bash
python3 bugscope.py --domain example.com
python3 bugscope.py --url http://localhost:3000
python3 bugscope.py --domain example.com --output report.txt
```

Example output:

```text
[+] BugScope v1 - Target: example.com
[1] Resolving IP address (DNS)...
[2] Finding subdomains (crt.sh)...
    No subdomains found
[3] Checking website: https://example.com ...
    Status: 200
[4] Checking security headers...
    [MISSING] Strict-Transport-Security is not present
[5] Checking common files...
    /robots.txt -> 404
[+] Report saved: bugscope-report.txt
```

## How it works

| Function | Purpose |
| --- | --- |
| `clean_domain()` | Extracts a clean domain name from a URL or domain string |
| `get_ip()` | Resolves a domain to an IP address with `socket.gethostbyname` |
| `get_subdomains()` | Reads the crt.sh public API for certificate logs |
| `check_website()` | Sends a GET request with `requests.get` (10 second timeout) |
| `check_headers()` | Compares the response headers with the 5 expected security headers |
| `check_common_paths()` | Reads the HTTP status code of common paths |
| `main()` | Runs the checks in order and writes the report |

## Project structure

```text
bugscope/
├── bugscope.py        # The tool
├── README.md          # This file
├── requirements.txt   # Python dependencies
├── LICENSE            # MIT License
└── .gitignore         # Ignored files (reports, cache)
```

## Roadmap

- CORS check
- Clickjacking check
- Subdomain takeover fingerprint check
- HTML report with severity, impact, and fix for each finding

## Disclaimer

This tool is for learning and authorized security testing only. The author is not responsible for misuse. Always follow the scope and rules of the bug bounty program or the written agreement with the client.
