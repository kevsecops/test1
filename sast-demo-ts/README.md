# SAST Demo — TypeScript Project

A TypeScript/Node.js project containing **intentional security vulnerabilities** for evaluating SAST tools such as **ESLint (security plugins)**, **SonarQube**, **Semgrep**, **Snyk**, **npm audit**, and **NodeJsScan**.

> ⚠️ **DO NOT install or run this project in production.** Dependencies are pinned to versions with known CVEs for demonstration purposes only.

---

## Project Structure

```
sast-demo-ts/
├── package.json                  # 15 CVE-carrying dependency versions
├── tsconfig.json
└── src/
    ├── index.ts                  # Entry point; calls all vulnerable modules
    ├── sqlInjection.ts           # SQL & NoSQL injection (5 findings)
    ├── commandInjection.ts       # Command injection, eval, prototype pollution (8 findings)
    ├── cryptoIssues.ts           # Weak crypto, hardcoded secrets, JWT issues (13 findings)
    ├── webVulnerabilities.ts     # XSS, SSRF, path traversal, CORS, ReDoS… (11 findings)
    ├── deserialization.ts        # node-serialize RCE, SSTI via ejs/handlebars (6 findings)
    └── miscIssues.ts             # Header injection, cleartext, ReDoS, XPath… (12 findings)
```

---

## Build

```bash
npm install
npm run build   # tsc
```

Requires Node.js 16+ and npm.

## Run SAST Scans

```bash
# Dependency CVE audit (built-in)
npm audit

# Semgrep code analysis
semgrep --config=p/javascript src/

# NodeJsScan
pip install nodejsscan
nodejsscan -d src/

# ESLint with security plugin
npm install --save-dev eslint eslint-plugin-security
npx eslint --rulesdir . --plugin security src/
```

---

## Dependencies with Known CVEs (15 total)

| Package | Version | CVE | Severity | Description |
|---------|---------|-----|----------|-------------|
| express | 4.17.1 | CVE-2022-24999 | High | Prototype pollution via qs query string parser |
| lodash | 4.17.15 | CVE-2021-23337 | Critical | Command injection via `_.template` |
| lodash | 4.17.15 | CVE-2020-8203 | High | Prototype pollution via `_.merge` / `_.zipObjectDeep` |
| axios | 0.18.0 | CVE-2019-10742 | High | SSRF / ReDoS in URL handling |
| node-serialize | 0.0.4 | CVE-2017-5941 | Critical | RCE via deserialized IIFE (arbitrary code execution) |
| marked | 0.3.6 | CVE-2022-21681 | High | ReDoS via specially crafted markdown |
| jsonwebtoken | 8.5.1 | CVE-2022-23529 | High | Arbitrary file read via crafted token secret |
| mongoose | 5.9.0 | CVE-2022-24304 | High | Prototype pollution via schema options |
| ejs | 2.6.1 | CVE-2022-29078 | Critical | RCE via `outputFunctionName` template option injection |
| minimist | 1.2.0 | CVE-2020-7598 | Medium | Prototype pollution via `__proto__` key |
| path-parse | 1.0.6 | CVE-2021-23343 | Medium | ReDoS via crafted path string |
| ws | 5.2.0 | CVE-2021-32640 | High | ReDoS via crafted HTTP upgrade header |
| handlebars | 4.5.3 | CVE-2021-23369 | Critical | Prototype pollution / RCE via template |
| multer | 1.4.2 | CVE-2022-24434 | High | Path traversal via crafted filename |
| nodemailer | 4.7.0 | CVE-2017-15085 | Medium | Header injection via unsanitized recipient |
| tar | 4.4.8 | CVE-2021-37701 | High | Path traversal via symlinks in archive |

---

## Expected Code Findings (55 total)

### 🔴 SQL / NoSQL Injection (`sqlInjection.ts`)

| # | Finding | CWE | SonarQube / Semgrep |
|---|---------|-----|---------------------|
| 1 | SQL injection via string concatenation | CWE-89 | S3649 |
| 2 | SQL injection via template literal | CWE-89 | S3649 |
| 3 | Unsanitized `ORDER BY` clause | CWE-89 | S3649 |
| 4 | NoSQL injection — raw `req.body` into MongoDB `find()` | CWE-943 | javascript.nosql-injection |
| 5 | SQL injection via `DELETE` template literal | CWE-89 | S3649 |

### 🔴 Command / Code Injection (`commandInjection.ts`)

| # | Finding | CWE | SonarQube / Semgrep |
|---|---------|-----|---------------------|
| 6 | `exec()` with user input — command injection | CWE-78 | S4721 |
| 7 | `execSync()` with template literal — command injection | CWE-78 | S4721 |
| 8 | `spawn()` with `shell:true` — command injection | CWE-78 | S4721 |
| 9 | `eval()` with user-controlled expression | CWE-95 | S1523 |
| 10 | `new Function()` with user input | CWE-95 | S1523 |
| 11 | `_.merge()` with untrusted object — prototype pollution (CVE-2020-8203) | CWE-1321 | javascript.prototype-pollution |
| 12 | Dynamic property assignment without key sanitization | CWE-1321 | javascript.prototype-pollution |
| 13 | `_.template()` with user string — RCE (CVE-2021-23337) | CWE-94 | S5334 |

### 🔴 Weak Cryptography & Secrets (`cryptoIssues.ts`)

| # | Finding | CWE | SonarQube / Semgrep |
|---|---------|-----|---------------------|
| 14 | Hardcoded database password | CWE-798 | S2068 |
| 15 | Hardcoded JWT secret | CWE-798 | S2068 |
| 16 | Hardcoded AWS API key | CWE-798 | S2068 |
| 17 | Hardcoded encryption key | CWE-798 | S2068 |
| 18 | MD5 for password hashing | CWE-327 | S4790 / S2070 |
| 19 | SHA-1 for password hashing | CWE-327 | S2070 |
| 20 | DES cipher (broken, 56-bit) | CWE-327 | S5542 |
| 21 | RC4 cipher (broken stream cipher) | CWE-327 | S5547 |
| 22 | `Math.random()` for security token | CWE-330 | S2245 |
| 23 | JWT signed with hardcoded secret + HS256 | CWE-798 | S2068 |
| 24 | JWT decoded without signature verification | CWE-347 | S5659 |
| 25 | JWT accepted with `algorithm:none` | CWE-347 | S5659 |
| 26 | Timing-attack-vulnerable `==` comparison for API key | CWE-208 | S4432 |

### 🔴 Web Vulnerabilities (`webVulnerabilities.ts`)

| # | Finding | CWE | SonarQube / Semgrep |
|---|---------|-----|---------------------|
| 27 | CORS `*` with `Allow-Credentials: true` | CWE-942 | S5122 |
| 28 | Missing security headers (CSP, HSTS, X-Frame-Options) | CWE-693 | S5725 |
| 29 | XSS — user input in template literal response | CWE-79 | S5131 |
| 30 | XSS via `marked` without sanitization (CVE-2022-21681) | CWE-79 | S5131 |
| 31 | SSRF — user URL in `axios.get()` (CVE-2019-10742) | CWE-918 | S5144 |
| 32 | Path traversal — user filename in `fs.readFileSync` | CWE-22 | S2083 |
| 33 | Open redirect — user-controlled `res.redirect()` | CWE-601 | S5146 |
| 34 | Insecure cookie — no `Secure`, `HttpOnly`, `SameSite` | CWE-614 | S3330 |
| 35 | Stack trace exposed in error response | CWE-209 | S4507 |
| 36 | ReDoS via catastrophic-backtracking regex | CWE-1333 | S2631 |
| 37 | Server binding to `0.0.0.0` | CWE-605 | S1313 |

### 🔴 Insecure Deserialization & SSTI (`deserialization.ts`)

| # | Finding | CWE | SonarQube / Semgrep |
|---|---------|-----|---------------------|
| 38 | `node-serialize.unserialize()` on untrusted data — RCE (CVE-2017-5941) | CWE-502 | S5135 |
| 39 | `eval()` on parsed JSON property | CWE-95 | S1523 |
| 40 | `ejs.render()` with user-controlled template — SSTI/RCE (CVE-2022-29078) | CWE-94 | S5334 |
| 41 | `ejs.renderFile()` with user-controlled filename — path traversal | CWE-22 | S2083 |
| 42 | `handlebars.compile()` with user template — prototype pollution/RCE (CVE-2021-23369) | CWE-94 | S5334 |
| 43 | `Object.assign()` with parsed JSON — prototype pollution via `__proto__` | CWE-1321 | javascript.prototype-pollution |

### 🟠 Miscellaneous Issues (`miscIssues.ts`)

| # | Finding | CWE | SonarQube / Semgrep |
|---|---------|-----|---------------------|
| 44 | Hardcoded SMTP password | CWE-798 | S2068 |
| 45 | Email header injection via nodemailer (CVE-2017-15085) | CWE-93 | S5167 |
| 46 | Cleartext HTTP for sensitive credentials | CWE-319 | S5332 |
| 47 | `tar.x()` without path filter — path traversal (CVE-2021-37701) | CWE-22 | S2083 |
| 48 | `RegExp` from user input — ReDoS (CVE-2021-32640 / path-parse) | CWE-730 | S2631 |
| 49 | XPath injection via string concatenation | CWE-643 | S2091 |
| 50 | `rejectUnauthorized: false` — TLS cert not verified | CWE-295 | S4830 |
| 51 | Password logged to console | CWE-532 | S2068 |
| 52 | `process.env` dumped to stdout | CWE-532 | S2068 |
| 53 | Prototype pollution via `minimist` (CVE-2020-7598) | CWE-1321 | javascript.prototype-pollution |
| 54 | Unhandled promise rejection — silent failure | CWE-755 | S4822 |
| 55 | `eval()` with user HTML content — DOM XSS | CWE-79 | S1523 |

---

**Total: 55 code findings + 16 CVE-carrying dependency versions** across 6 source files.
