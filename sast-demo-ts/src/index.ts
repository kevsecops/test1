/**
 * index.ts — Entry point for the TypeScript SAST demo application.
 *
 * Imports and calls all vulnerable modules so SAST tools can trace
 * the full call graph. DO NOT run in production.
 */
import { calculate, getFileInfo, mergeUserPrefs, pingHost, renderTemplate } from "./commandInjection";
import { decodeTokenInsecure, generateToken, hashPasswordMD5, hashPasswordSHA1, validateApiKey } from "./cryptoIssues";
import { deserializeUserData, mergeSettings, renderEjs, renderHandlebars } from "./deserialization";
import { debugEnv, fetchCredentials, loginUser, matchPattern, parseArgs } from "./miscIssues";
import { deleteUser, findUserByName, findUserById, listUsersSorted } from "./sqlInjection";

async function main(): Promise<void> {
  console.log("=== TypeScript SAST Demo ===");

  // SQL injection demos
  findUserByName("alice' OR '1'='1");
  findUserById("1 OR 1=1");
  listUsersSorted("name; DROP TABLE users--");
  deleteUser("admin'--");

  // Command injection demos
  pingHost("127.0.0.1; cat /etc/passwd");
  console.log(getFileInfo(".; ls /"));
  console.log(calculate("require('child_process').execSync('id').toString()"));

  // Prototype pollution demo
  const merged = mergeUserPrefs({ theme: "light" }, { "__proto__": { "isAdmin": true } });
  console.log("merged:", merged);

  // Template injection demo (lodash CVE-2021-23337)
  console.log(renderTemplate("<%= require('child_process').execSync('id') %>", {}));

  // Crypto demos
  console.log("MD5:", hashPasswordMD5("password123"));
  console.log("SHA1:", hashPasswordSHA1("password123"));
  console.log("Token:", generateToken());
  console.log("JWT decoded:", decodeTokenInsecure("eyJ..."));
  console.log("API key valid:", validateApiKey("test"));

  // Deserialization demos
  const maliciousPayload = '{"cmd":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}';
  deserializeUserData(maliciousPayload);
  renderEjs("<%= process.env %>", {});
  renderHandlebars("{{#with (lookup . 'constructor')}}{{wrapHelper this}}{{/with}}", {});
  mergeSettings({}, '{"__proto__":{"polluted":true}}');

  // Misc demos
  loginUser("admin", "secret123");
  debugEnv();
  fetchCredentials("internal-api.example.com");
  matchPattern("input", "(a+)+$");   // ReDoS pattern
  console.log("Args:", parseArgs(["--__proto__.admin", "true"]));

  console.log("=== Demo complete ===");
}

main().catch(console.error);
