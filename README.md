# SAST Demo Projects

A collection of intentionally vulnerable applications for demonstrating and evaluating **Static Application Security Testing (SAST)** tools.

> ⚠️ These projects contain deliberate security vulnerabilities and must **never** be deployed to production.

---

## Projects

| Project | Language | Findings | CVEs |
|---------|----------|----------|------|
| [`sast-demo/`](./sast-demo/) | Java (Maven) | 11 code findings | 9 CVEs in dependencies |
| [`sast-demo-python/`](./sast-demo-python/) | Python | 45 code findings | 15 CVEs in dependencies |
| [`sast-demo-ts/`](./sast-demo-ts/) | TypeScript / Node.js | 55 code findings | 16 CVEs in dependencies |

---

## sast-demo — Java (Maven)

Recommended tools: **SpotBugs**, **SonarQube**, **FindSecBugs**, **Checkmarx**, **Semgrep**

### Structure

```
sast-demo/
├── pom.xml
└── src/main/java/com/example/sastdemo/
    ├── Main.java                  # Entry point; launches all threads
    ├── SharedCounterDemo.java     # Race condition on static int
    ├── SharedMapDemo.java         # Unsynchronized HashMap access
    └── VulnerableCode.java        # Additional SAST findings
```

### Build

```bash
cd sast-demo
mvn compile
mvn package
```

Requires Java 11+ and Maven 3.x.

### Expected Findings (11 total)

#### 🔴 Concurrency / Data Races

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 1 | `SharedCounterDemo.java` | Two threads read/write `static int counter` without `synchronized`, `volatile`, or `AtomicInteger` | SpotBugs `IS2_INCONSISTENT_SYNC`, SonarQube `S2885` |
| 2 | `SharedMapDemo.java` | Two threads call `put()`/`get()` on a `HashMap` without synchronization | SpotBugs `IS2_INCONSISTENT_SYNC`, SonarQube `S2885` |

#### 🔴 Injection

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 3 | `VulnerableCode.java` | **SQL Injection** — user input concatenated directly into SQL query | SpotBugs `SQL_INJECTION`, SonarQube `S3649` |

#### 🔴 Sensitive Data Exposure

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 4 | `VulnerableCode.java` | **Hardcoded password** (`s3cr3tP@ssw0rd!`) as a `String` constant | SonarQube `S2068`, Semgrep `hardcoded-credentials` |
| 5 | `VulnerableCode.java` | **Hardcoded API key** (`AKIAIOSFODNN7EXAMPLE`) as a `String` constant | SonarQube `S2068`, Semgrep `hardcoded-credentials` |

#### 🔴 Path Traversal

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 6 | `VulnerableCode.java` | **Path traversal** — unsanitized user input in `new File(…)` | SpotBugs `PATH_TRAVERSAL_IN`, SonarQube `S2083` |

#### 🟠 Reliability / Crash Risk

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 7 | `VulnerableCode.java` | **Null pointer dereference** — `System.getProperty()` used without null check | SpotBugs `NP_NULL_ON_SOME_PATH`, SonarQube `S2259` |
| 8 | `VulnerableCode.java` | **Resource leak** — `FileInputStream` never closed | SpotBugs `OBL_UNSATISFIED_OBLIGATION`, SonarQube `S2095` |
| 9 | `VulnerableCode.java` | **Empty catch block** — exception silently swallowed | SpotBugs `DE_MIGHT_IGNORE`, SonarQube `S1166` |

#### 🟡 Code Quality / Logic Errors

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 10 | `VulnerableCode.java` | **Insecure randomness** — `java.util.Random` for security token | SpotBugs `DMI_RANDOM_USED_ONLY_ONCE`, SonarQube `S2245` |
| 11 | `VulnerableCode.java` | **String `==` comparison** — reference equality instead of `.equals()` | SpotBugs `ES_COMPARING_STRINGS_WITH_EQ`, SonarQube `S1698` |

---

## sast-demo-python — Python

Recommended tools: **Bandit**, **SonarQube**, **Semgrep**, **Safety**, **pip-audit**, **Snyk**

### Structure

```
sast-demo-python/
├── requirements.txt                  # 15 CVE-carrying dependency versions
├── main.py                           # Entry point
└── app/
    ├── sql_injection.py              # SQL injection (4 findings)
    ├── command_injection.py          # OS/eval/exec injection (6 findings)
    ├── crypto_issues.py              # Weak crypto & hardcoded secrets (10 findings)
    ├── insecure_deserialization.py   # pickle / marshal / yaml.load (5 findings)
    ├── web_vulnerabilities.py        # XSS, SSTI, SSRF, XXE, path traversal (10 findings)
    └── misc_issues.py                # Empty except, assert, tempfile, JWT… (10 findings)
```

### Run SAST Scans

```bash
cd sast-demo-python

# Code analysis
pip install bandit
bandit -r app/ main.py

# Dependency CVE check
pip install safety
safety check -r requirements.txt

# Alternative dependency CVE check
pip install pip-audit
pip-audit -r requirements.txt
```

### Dependencies with Known CVEs (15 total)

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

### Expected Code Findings (45 total)

| Category | Count | Examples |
|----------|-------|---------|
| 🔴 SQL Injection | 4 | `%`, f-string, `.format()`, `ORDER BY` concatenation |
| 🔴 Command / Code Injection | 6 | `os.system`, `subprocess shell=True`, `eval()`, `exec()` |
| 🔴 Hardcoded Secrets | 4 | DB password, Django secret key, AWS key, JWT secret |
| 🔴 Weak Cryptography | 6 | MD5/SHA1 passwords, DES/RC4 ciphers, insecure random, timing attack |
| 🔴 Insecure Deserialization | 5 | `pickle.loads`, `marshal.loads`, `yaml.load` |
| 🔴 Web Vulnerabilities | 10 | XSS, SSTI, SSRF, XXE, open redirect, path traversal, Flask debug=True |
| 🟠 Reliability / Misc | 10 | Empty except, assert for security, `mktemp` TOCTOU, JWT no-verify, insecure cookie |

---

## sast-demo-ts — TypeScript / Node.js

Recommended tools: **npm audit**, **Snyk**, **Semgrep**, **NodeJsScan**, **SonarQube**, **ESLint (eslint-plugin-security)**

### Structure

```
sast-demo-ts/
├── package.json                  # 16 CVE-carrying dependency versions
├── tsconfig.json
└── src/
    ├── index.ts                  # Entry point
    ├── sqlInjection.ts           # SQL & NoSQL injection (5 findings)
    ├── commandInjection.ts       # Command injection, eval, prototype pollution (8 findings)
    ├── cryptoIssues.ts           # Weak crypto, hardcoded secrets, JWT issues (13 findings)
    ├── webVulnerabilities.ts     # XSS, SSRF, path traversal, CORS, ReDoS… (11 findings)
    ├── deserialization.ts        # node-serialize RCE, SSTI via ejs/handlebars (6 findings)
    └── miscIssues.ts             # Header injection, cleartext, ReDoS, XPath… (12 findings)
```

### Build & Scan

```bash
cd sast-demo-ts
npm install
npm run build     # tsc

# Dependency CVE audit
npm audit

# Code analysis
semgrep --config=p/javascript src/
```

### Dependencies with Known CVEs (16 total)

| Package | Version | CVE | Severity | Description |
|---------|---------|-----|----------|-------------|
| express | 4.17.1 | CVE-2022-24999 | High | Prototype pollution via qs query string parser |
| lodash | 4.17.15 | CVE-2021-23337 | Critical | Command injection via `_.template` |
| lodash | 4.17.15 | CVE-2020-8203 | High | Prototype pollution via `_.merge` |
| axios | 0.18.0 | CVE-2019-10742 | High | SSRF / ReDoS in URL handling |
| node-serialize | 0.0.4 | CVE-2017-5941 | Critical | RCE via deserialized IIFE |
| marked | 0.3.6 | CVE-2022-21681 | High | ReDoS via crafted markdown |
| jsonwebtoken | 8.5.1 | CVE-2022-23529 | High | Arbitrary file read via crafted token |
| mongoose | 5.9.0 | CVE-2022-24304 | High | Prototype pollution via schema options |
| ejs | 2.6.1 | CVE-2022-29078 | Critical | RCE via template option injection |
| minimist | 1.2.0 | CVE-2020-7598 | Medium | Prototype pollution via `__proto__` key |
| path-parse | 1.0.6 | CVE-2021-23343 | Medium | ReDoS via crafted path string |
| ws | 5.2.0 | CVE-2021-32640 | High | ReDoS via crafted HTTP upgrade header |
| handlebars | 4.5.3 | CVE-2021-23369 | Critical | Prototype pollution / RCE via template |
| multer | 1.4.2 | CVE-2022-24434 | High | Path traversal via crafted filename |
| nodemailer | 4.7.0 | CVE-2017-15085 | Medium | Header injection via unsanitized recipient |
| tar | 4.4.8 | CVE-2021-37701 | High | Path traversal via symlinks in archive |

### Expected Code Findings (55 total)

| Category | Count | Examples |
|----------|-------|---------|
| 🔴 SQL / NoSQL Injection | 5 | String concat, template literals, raw `req.body` into MongoDB |
| 🔴 Command / Code Injection | 8 | `exec`, `execSync`, `spawn shell:true`, `eval`, `new Function`, prototype pollution |
| 🔴 Hardcoded Secrets | 4 | DB password, JWT secret, AWS key, encryption key |
| 🔴 Weak Cryptography | 9 | MD5/SHA1 passwords, DES/RC4 ciphers, `Math.random()`, JWT `algorithm:none` |
| 🔴 Insecure Deserialization & SSTI | 6 | `node-serialize` RCE, `eval` on JSON, `ejs`/`handlebars` SSTI |
| 🔴 Web Vulnerabilities | 11 | XSS, SSRF, path traversal, open redirect, CORS `*`, insecure cookie, ReDoS |
| 🟠 Miscellaneous | 12 | Header injection, cleartext HTTP, XPath injection, disabled TLS, password logging |

---

## Summary

| | Java | Python | TypeScript |
|--|------|--------|------------|
| **Code findings** | 11 | 45 | 55 |
| **Dependency CVEs** | 9 | 15 | 16 |
| **Recommended tools** | SpotBugs, SonarQube, FindSecBugs | Bandit, Safety, pip-audit, Semgrep | npm audit, Semgrep, NodeJsScan, Snyk |
