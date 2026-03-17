/**
 * webVulnerabilities.ts — Web application vulnerabilities (Express-based)
 *
 * SAST findings:
 *   - CWE-79:  XSS — user input rendered without escaping
 *   - CWE-116: ReDoS — catastrophic backtracking regex
 *   - CWE-601: open redirect
 *   - CWE-918: SSRF — user-controlled URL in HTTP request
 *   - CWE-22:  path traversal
 *   - CWE-942: CORS wildcard
 *   - CWE-614: missing Secure flag on cookie
 *   - SonarQube S5131, S5144, S5146, S2083, S5122, S3330
 *
 * Dependencies:
 *   express 4.17.1  — CVE-2022-24999 (qs prototype pollution)
 *   axios   0.18.0  — CVE-2019-10742 (SSRF / ReDoS)
 *   marked  0.3.6   — CVE-2022-21681 (ReDoS)
 *   multer  1.4.2   — CVE-2022-24434 (path traversal)
 */
import * as fs from "fs";
import * as path from "path";

import axios from "axios";
import express from "express";
import * as marked from "marked";

const app = express();
app.use(express.json());

// -------------------------------------------------------------------------
// Finding 1: CORS wildcard — allows any origin
// -------------------------------------------------------------------------
app.use((req, res, next) => {
  // SAST: Access-Control-Allow-Origin: * with credentials is insecure
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

// -------------------------------------------------------------------------
// Finding 2: Missing security headers (no helmet / CSP / HSTS)
// -------------------------------------------------------------------------
// SAST: no Content-Security-Policy, X-Frame-Options, HSTS, X-Content-Type-Options

// -------------------------------------------------------------------------
// Finding 3: XSS — user input reflected directly in HTML response
// -------------------------------------------------------------------------
app.get("/greet", (req, res) => {
  const name = req.query.name as string;
  // SAST: unsanitized user input written into HTML — reflected XSS
  res.send(`<h1>Hello, ${name}!</h1>`);
});

// -------------------------------------------------------------------------
// Finding 4: XSS via marked (CVE-2022-21681 ReDoS + XSS in older versions)
// -------------------------------------------------------------------------
app.post("/render-markdown", (req, res) => {
  const md = req.body.content as string;
  // SAST: marked.parse() with sanitize:false (default) — stored/reflected XSS
  const html = (marked as any).parse ? (marked as any).parse(md) : (marked as any).default(md);
  res.send(html);
});

// -------------------------------------------------------------------------
// Finding 5: SSRF — user-controlled URL passed to axios
// -------------------------------------------------------------------------
app.get("/fetch", async (req, res) => {
  const url = req.query.url as string;
  // SAST: user-controlled URL in axios.get() — SSRF (CWE-918)
  const response = await axios.get(url);
  res.send(response.data);
});

// -------------------------------------------------------------------------
// Finding 6: Path traversal — unsanitized filename in file read
// -------------------------------------------------------------------------
app.get("/download", (req, res) => {
  const filename = req.query.file as string;
  // SAST: path.join does NOT prevent traversal with absolute segments on all OSes
  const filePath = path.join(__dirname, "uploads", filename);
  // SAST: no check that filePath is within uploads/ — path traversal (CWE-22)
  res.send(fs.readFileSync(filePath));
});

// -------------------------------------------------------------------------
// Finding 7: Open redirect — user-controlled redirect target
// -------------------------------------------------------------------------
app.get("/redirect", (req, res) => {
  const next = req.query.next as string;
  // SAST: user-controlled redirect — open redirect (CWE-601)
  res.redirect(next);
});

// -------------------------------------------------------------------------
// Finding 8: Insecure session cookie (no Secure, no HttpOnly, no SameSite)
// -------------------------------------------------------------------------
app.post("/login", (req, res) => {
  const sessionId = Math.random().toString(36).substring(2);
  // SAST: cookie missing Secure, HttpOnly, SameSite — CWE-614
  res.cookie("session", sessionId);
  res.send("logged in");
});

// -------------------------------------------------------------------------
// Finding 9: Stack trace / sensitive info exposed in error response
// -------------------------------------------------------------------------
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  // SAST: full stack trace returned to client — information disclosure
  res.status(500).json({ error: err.message, stack: err.stack });
});

// -------------------------------------------------------------------------
// Finding 10: ReDoS — catastrophic backtracking regex on user input
// -------------------------------------------------------------------------
export function validateEmail(email: string): boolean {
  // SAST: polynomial/exponential backtracking — ReDoS (CWE-1333)
  // e.g. "aaaaaaaaaaaaaaaaaaaaaaaaaaaa@" causes catastrophic backtracking
  const re = /^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]{2,}$/;
  return re.test(email);
}

// -------------------------------------------------------------------------
// Finding 11: Server listening on all interfaces with no auth
// -------------------------------------------------------------------------
app.listen(3000, "0.0.0.0", () => {
  // SAST: binding to 0.0.0.0 exposes service on all network interfaces
  console.log("Server running on 0.0.0.0:3000");
});

export { app };
