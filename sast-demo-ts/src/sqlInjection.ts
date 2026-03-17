/**
 * sqlInjection.ts — SQL and NoSQL Injection vulnerabilities
 *
 * SAST findings:
 *   - CWE-89: SQL injection via string concatenation / template literals
 *   - CWE-943: NoSQL injection via unsanitized MongoDB query object
 *   - SonarQube S3649, Semgrep javascript.lang.security.audit.sqli
 */
// Simulated DB connection (illustrative — no real driver needed for SAST analysis)
declare const db: { query: (sql: string, cb: Function) => void };
declare const UserModel: { find: (q: object) => Promise<any> };

// -------------------------------------------------------------------------
// Finding 1: SQL injection via string concatenation
// -------------------------------------------------------------------------
export function findUserByName(username: string): void {
  // SAST: unsanitized user input concatenated into SQL query
  const query = "SELECT * FROM users WHERE name = '" + username + "'";
  db.query(query, (err: any, rows: any) => console.log(rows));
}

// -------------------------------------------------------------------------
// Finding 2: SQL injection via template literal
// -------------------------------------------------------------------------
export function findUserById(id: string): void {
  // SAST: template literal interpolation in SQL — SQL injection
  const query = `SELECT * FROM users WHERE id = ${id}`;
  db.query(query, (err: any, rows: any) => console.log(rows));
}

// -------------------------------------------------------------------------
// Finding 3: SQL injection in ORDER BY clause
// -------------------------------------------------------------------------
export function listUsersSorted(sortColumn: string): void {
  // SAST: unsanitized ORDER BY value — SQL injection
  const query = "SELECT * FROM users ORDER BY " + sortColumn;
  db.query(query, (err: any, rows: any) => console.log(rows));
}

// -------------------------------------------------------------------------
// Finding 4: NoSQL injection — MongoDB query built from raw user object
// (lodash 4.17.15 — CVE-2020-8203 prototype pollution used in merge below)
// -------------------------------------------------------------------------
export async function findUserMongo(req: any): Promise<any> {
  // SAST: req.body passed directly into MongoDB find() — NoSQL injection
  // Attacker can send { "$gt": "" } to bypass authentication
  return UserModel.find(req.body);
}

// -------------------------------------------------------------------------
// Finding 5: SQL injection via format string in raw query
// -------------------------------------------------------------------------
export function deleteUser(username: string): void {
  // SAST: format-string SQL injection
  const query = `DELETE FROM users WHERE name = '${username}'`;
  db.query(query, (err: any) => console.log("deleted"));
}
