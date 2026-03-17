# SAST Demo — Python Project

A Python project containing **intentional security vulnerabilities and code quality issues** designed to be detected by SAST tools such as **Bandit**, **SonarQube**, **Semgrep**, **Snyk**, **Safety**, and **pip-audit**.

> ⚠️ **DO NOT install or run this project in production.** Dependencies are pinned to versions with known CVEs for demonstration purposes only.

---

## Project Structure

```
sast-demo-python/
├── requirements.txt                  # Vulnerable dependency versions
├── main.py                           # Entry point
└── app/
    ├── sql_injection.py              # SQL injection (4 findings)
    ├── command_injection.py          # OS/eval/exec injection (6 findings)
    ├── crypto_issues.py              # Weak crypto & hardcoded secrets (7 findings)
    ├── insecure_deserialization.py   # pickle / marshal / yaml.load (5 findings)
    ├── web_vulnerabilities.py        # XSS, SSTI, SSRF, XXE, path traversal (10 findings)
    └── misc_issues.py                # Misc issues: empty except, assert, tempfile… (10 findings)
```

---

## Dependencies with Known CVEs

| Package | Version | CVE | Severity | Description |
|---------|---------|-----|----------|-------------|
| Flask | 0.12.2 | CVE-2018-1000656 | High | ReDoS via Werkzeug URL routing |
| Django | 2.2.0 | CVE-2019-14234 | Critical | SQL injection via key/value lookups |
| Django | 2.2.0 | CVE-2019-12781 | Medium | Incorrect HTTP detection behind reverse proxy |
| Pillow | 5.4.1 | CVE-2019-16865 | High | DoS via crafted image file |
| Pillow | 5.4.1 | CVE-2020-5313 | High | Out-of-bounds read in FLI image decoder |
| requests | 2.18.0 | CVE-2018-18074 | Medium | Credentials exposed in cross-origin redirect |
| PyYAML | 3.13 | CVE-2017-18342 | Critical | Arbitrary code execution via `yaml.load()` |
| cryptography | 2.2.2 | CVE-2018-10903 | High | GCM nonce reuse vulnerability |
| urllib3 | 1.22 | CVE-2018-20060 | Medium | CRLF injection / header injection |
| Jinja2 | 2.10 | CVE-2019-8341 | Critical | Sandbox escape enabling RCE |
| paramiko | 2.4.1 | CVE-2018-1000805 | Critical | Authentication bypass |
| lxml | 4.1.1 | CVE-2018-19787 | Medium | XSS via href attribute sanitization bypass |
| SQLAlchemy | 1.3.0 | CVE-2019-7164 | High | SQL injection via order_by clause |
| Werkzeug | 0.14.1 | CVE-2019-14806 | Medium | Predictable temporary filenames |
| pycrypto | 2.6.1 | CVE-2013-7459 | High | Heap buffer overflow in ALGnew |

---

## Expected SAST Findings

### 🔴 SQL Injection (`sql_injection.py`)

| # | Finding | Bandit | SonarQube |
|---|---------|--------|-----------|
| 1 | SQL query built with `%` string formatting | B608 | S3649 |
| 2 | SQL query built with f-string interpolation | B608 | S3649 |
| 3 | SQL query built with `.format()` | B608 | S3649 |
| 4 | Unsanitized `ORDER BY` via concatenation | B608 | S3649 |

### 🔴 Command / Code Injection (`command_injection.py`)

| # | Finding | Bandit | SonarQube |
|---|---------|--------|-----------|
| 5 | `os.system()` with user input | B605 | S2076 |
| 6 | `subprocess.call(shell=True)` with user input | B602 | S2076 |
| 7 | `subprocess.Popen(shell=True)` with user input | B602 | S2076 |
| 8 | `os.popen()` with user input | B605 | S2076 |
| 9 | `eval()` with user-controlled expression | B307 | S1523 |
| 10 | `exec()` with user-controlled code | B102 | S1523 |

### 🔴 Sensitive Data / Weak Cryptography (`crypto_issues.py`)

| # | Finding | Bandit | SonarQube |
|---|---------|--------|-----------|
| 11 | Hardcoded Django `SECRET_KEY` | B105 | S2068 |
| 12 | Hardcoded database password | B106 | S2068 |
| 13 | Hardcoded AWS secret key | B105 | S2068 |
| 14 | Hardcoded JWT secret | B105 | S2068 |
| 15 | MD5 used for password hashing | B303 | S2070 |
| 16 | SHA-1 used for password hashing | B303 | S2070 |
| 17 | DES cipher (56-bit, broken) + ECB mode | B304 | S5542 |
| 18 | RC4 / ARC4 (cryptographically broken) | B304 | S5547 |
| 19 | `random.choice()` for session token | B311 | S2245 |
| 20 | Timing-attack-vulnerable token comparison (`==`) | — | S4432 |

### 🔴 Insecure Deserialization (`insecure_deserialization.py`)

| # | Finding | Bandit | SonarQube |
|---|---------|--------|-----------|
| 21 | `pickle.loads()` on user-supplied bytes | B301 | S5135 |
| 22 | `pickle.load()` from user-supplied file path | B301 | S5135 |
| 23 | `marshal.loads()` on untrusted data | B302 | S5135 |
| 24 | `yaml.load()` without `Loader=` argument (CVE-2017-18342) | B506 | S5754 |
| 25 | `yaml.load()` from user-supplied file | B506 | S5754 |

### 🔴 Web Vulnerabilities (`web_vulnerabilities.py`)

| # | Finding | Bandit | SonarQube |
|---|---------|--------|-----------|
| 26 | Flask `debug=True` — exposes interactive debugger (RCE) | B201 | S4792 |
| 27 | XSS — user input concatenated into `render_template_string` | B703 | S5131 |
| 28 | SSTI — `jinja2.Template()` built from user input | B703 | S5131 |
| 29 | XSS via `Markup()` on unsanitized user input | B308 | S5131 |
| 30 | SSRF — `requests.get(user_url)` | B310 | S5144 |
| 31 | SSRF — `urllib.request.urlopen(user_url)` | B310 | S5144 |
| 32 | XXE — `xml.etree.ElementTree.fromstring()` on user XML | B320 | S2755 |
| 33 | XXE — SAX parser with external entities enabled | B313 | S2755 |
| 34 | Open redirect — user-controlled `next` parameter | — | S5146 |
| 35 | Path traversal — filename concatenated into file open | B602 | S2083 |

### 🟠 Miscellaneous Issues (`misc_issues.py`)

| # | Finding | Bandit | SonarQube |
|---|---------|--------|-----------|
| 36 | Empty `except` block — exception swallowed | B110 | S1166 |
| 37 | Sensitive data (password) written to logs | — | S2068 |
| 38 | `assert` used for security/access control | B101 | S5776 |
| 39 | `tempfile.mktemp()` — race condition / TOCTOU | B108 | S5445 |
| 40 | Predictable `/tmp` path — symlink attack | — | S5445 |
| 41 | JWT decoded without signature verification | — | S5659 |
| 42 | Binding to all interfaces (`0.0.0.0`) | — | S1313 |
| 43 | MD5 used in non-security context (flagged by strict tools) | B303 | S4790 |
| 44 | Sensitive credential exposed in exception message | — | S2068 |
| 45 | Session cookie without `Secure`/`HttpOnly` flags | — | S3330 |

---

**Total: 45 code findings + 15 vulnerable dependency versions** across 5 source files.

## Running a SAST Scan

```bash
# Bandit (code analysis)
pip install bandit
bandit -r app/ main.py

# Safety (dependency CVE check)
pip install safety
safety check -r requirements.txt

# pip-audit (dependency CVE check)
pip install pip-audit
pip-audit -r requirements.txt
```
