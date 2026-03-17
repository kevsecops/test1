/**
 * miscIssues.ts — Miscellaneous SAST findings
 *
 * SAST findings:
 *   - CWE-209: information exposure through error messages
 *   - CWE-319: cleartext transmission of sensitive data
 *   - CWE-352: missing CSRF protection
 *   - CWE-400: uncontrolled resource consumption (no rate limiting)
 *   - CWE-611: XXE via xml2js / sax with external entities
 *   - CWE-643: XPath injection
 *   - CWE-730: ReDoS via user-supplied regex
 *   - CWE-1004: missing HttpOnly cookie flag (duplicate for emphasis)
 *   - SonarQube S4830, S5725, S2631, S5247
 *
 * Dependencies:
 *   nodemailer  4.7.0 — CVE-2017-15085 (header injection)
 *   tar         4.4.8 — CVE-2021-37701 (path traversal via symlink)
 *   ws          5.2.0 — CVE-2021-32640 (ReDoS)
 *   minimist    1.2.0 — CVE-2020-7598  (prototype pollution)
 *   path-parse  1.0.6 — CVE-2021-23343 (ReDoS)
 */
import * as http from "http";
import * as nodemailer from "nodemailer";
import * as tar from "tar";

// -------------------------------------------------------------------------
// Finding 1: Hardcoded SMTP credentials
// -------------------------------------------------------------------------
const mailerTransport = nodemailer.createTransport({
  host: "smtp.example.com",
  port: 587,
  auth: {
    user: "app@example.com",
    pass: "smtp_password_123",   // SAST: hardcoded SMTP password — CWE-798
  },
});

// -------------------------------------------------------------------------
// Finding 2: Email header injection via nodemailer (CVE-2017-15085)
// -------------------------------------------------------------------------
export async function sendEmail(to: string, subject: string): Promise<void> {
  // SAST: user-controlled `to` / `subject` injected into mail headers
  await mailerTransport.sendMail({
    from: "noreply@example.com",
    to,           // SAST: header injection if `to` contains \r\n
    subject,      // SAST: header injection
    text: "Hello",
  });
}

// -------------------------------------------------------------------------
// Finding 3: HTTP (cleartext) instead of HTTPS for sensitive data
// -------------------------------------------------------------------------
export function fetchCredentials(host: string): void {
  // SAST: plain HTTP used — credentials transmitted in cleartext (CWE-319)
  http.get(`http://${host}/api/credentials`, (res) => {
    res.pipe(process.stdout);
  });
}

// -------------------------------------------------------------------------
// Finding 4: tar extraction without path-traversal protection (CVE-2021-37701)
// -------------------------------------------------------------------------
export async function extractArchive(archivePath: string): Promise<void> {
  // SAST: tar.x() without strip or filter — path traversal via symlink (CVE-2021-37701)
  await tar.x({ file: archivePath });
}

// -------------------------------------------------------------------------
// Finding 5: User-supplied regex — ReDoS
// -------------------------------------------------------------------------
export function matchPattern(input: string, pattern: string): boolean {
  // SAST: RegExp constructed from user input — ReDoS (CWE-730)
  const re = new RegExp(pattern);
  return re.test(input);
}

// -------------------------------------------------------------------------
// Finding 6: XPath injection
// -------------------------------------------------------------------------
export function queryXml(xmlDoc: any, username: string): any {
  // SAST: user input interpolated into XPath query — XPath injection (CWE-643)
  const xpath = `//users/user[name='${username}']`;
  return xmlDoc.find(xpath);
}

// -------------------------------------------------------------------------
// Finding 7: Disabled TLS certificate validation
// -------------------------------------------------------------------------
export function createInsecureAgent(): any {
  // SAST: rejectUnauthorized:false disables TLS cert verification — CWE-295
  return new (require("https").Agent)({ rejectUnauthorized: false });
}

// -------------------------------------------------------------------------
// Finding 8: console.log of sensitive data (password / token)
// -------------------------------------------------------------------------
export function loginUser(username: string, password: string): void {
  // SAST: sensitive credential written to logs — CWE-532
  console.log(`Login attempt: user=${username} password=${password}`);
}

// -------------------------------------------------------------------------
// Finding 9: process.env secret logged
// -------------------------------------------------------------------------
export function debugEnv(): void {
  // SAST: entire environment (may contain secrets) dumped to stdout
  console.log("ENV:", JSON.stringify(process.env));
}

// -------------------------------------------------------------------------
// Finding 10: Prototype pollution via minimist (CVE-2020-7598)
// -------------------------------------------------------------------------
export function parseArgs(args: string[]): object {
  // SAST: minimist 1.2.0 is vulnerable to prototype pollution via __proto__
  // e.g. args = ["--__proto__.polluted", "true"]
  const minimist = require("minimist");
  return minimist(args);
}

// -------------------------------------------------------------------------
// Finding 11: Unhandled promise rejection — silent failure
// -------------------------------------------------------------------------
export function fetchData(url: string): void {
  // SAST: promise rejection not handled — may crash Node.js process
  fetch(url).then((r) => r.json());
}

// -------------------------------------------------------------------------
// Finding 12: Insecure use of innerHTML equivalent via eval (DOM XSS)
// -------------------------------------------------------------------------
export function renderHtml(userContent: string): void {
  // SAST: eval with HTML string — DOM XSS when used in browser context
  eval(`document.body.innerHTML = "${userContent}"`);
}
