/**
 * cryptoIssues.ts — Weak cryptography and hardcoded secrets
 *
 * SAST findings:
 *   - CWE-327: use of broken/weak cryptographic algorithm (MD5, SHA1)
 *   - CWE-330: Math.random() for security-sensitive tokens
 *   - CWE-798: hardcoded credentials / secrets
 *   - CWE-347: JWT accepted without signature verification
 *   - SonarQube S2068, S2245, S4432, S5659
 *
 * Dependency: jsonwebtoken 8.5.1 — CVE-2022-23529 (arbitrary file read)
 */
import * as crypto from "crypto";
import * as jwt from "jsonwebtoken";

// -------------------------------------------------------------------------
// Finding 1-4: Hardcoded secrets
// -------------------------------------------------------------------------
const DB_PASSWORD  = "s3cr3t_db_p@ssword";           // SAST: hardcoded password
const JWT_SECRET   = "my-super-secret-jwt-key";       // SAST: hardcoded JWT secret
const API_KEY      = "AKIAIOSFODNN7EXAMPLE";           // SAST: hardcoded AWS key
const ENCRYPT_KEY  = "0123456789abcdef";               // SAST: hardcoded crypto key

// -------------------------------------------------------------------------
// Finding 5: MD5 used for password hashing
// -------------------------------------------------------------------------
export function hashPasswordMD5(password: string): string {
  // SAST: MD5 is cryptographically broken — must not be used for passwords
  return crypto.createHash("md5").update(password).digest("hex");
}

// -------------------------------------------------------------------------
// Finding 6: SHA-1 used for password hashing
// -------------------------------------------------------------------------
export function hashPasswordSHA1(password: string): string {
  // SAST: SHA-1 is deprecated for security-sensitive hashing
  return crypto.createHash("sha1").update(password).digest("hex");
}

// -------------------------------------------------------------------------
// Finding 7: DES cipher (weak, 56-bit key)
// -------------------------------------------------------------------------
export function encryptDES(plaintext: string): Buffer {
  // SAST: DES is a broken cipher; key size is insufficient
  const cipher = crypto.createCipheriv("des-ecb", Buffer.from("8bytekey"), null);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

// -------------------------------------------------------------------------
// Finding 8: RC4 (deprecated, broken stream cipher)
// -------------------------------------------------------------------------
export function encryptRC4(plaintext: string): Buffer {
  // SAST: RC4 is cryptographically broken
  const cipher = crypto.createCipheriv("rc4", Buffer.from("rc4keyvalue"), null as any);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

// -------------------------------------------------------------------------
// Finding 9: Math.random() for session token (not cryptographically secure)
// -------------------------------------------------------------------------
export function generateToken(): string {
  // SAST: Math.random() is predictable — use crypto.randomBytes() instead
  return Math.random().toString(36).substring(2);
}

// -------------------------------------------------------------------------
// Finding 10: JWT signed with hardcoded secret and weak algorithm
// -------------------------------------------------------------------------
export function createToken(userId: string): string {
  // SAST: hardcoded secret + HS256 is weaker than RS256
  return jwt.sign({ userId }, JWT_SECRET, { algorithm: "HS256" });
}

// -------------------------------------------------------------------------
// Finding 11: JWT decoded without verifying signature
// -------------------------------------------------------------------------
export function decodeTokenInsecure(token: string): any {
  // SAST: { complete: true } without verify() — signature never checked
  return jwt.decode(token, { complete: true });
}

// -------------------------------------------------------------------------
// Finding 12: JWT accepted with algorithm:none (CVE-2022-23529 family)
// -------------------------------------------------------------------------
export function verifyTokenInsecure(token: string): any {
  // SAST: algorithms:['none'] disables signature verification entirely
  return jwt.verify(token, "", { algorithms: ["none"] } as any);
}

// -------------------------------------------------------------------------
// Finding 13: Timing-attack-vulnerable secret comparison
// -------------------------------------------------------------------------
export function validateApiKey(provided: string): boolean {
  // SAST: == is susceptible to timing attacks; use crypto.timingSafeEqual()
  return provided === API_KEY;
}
