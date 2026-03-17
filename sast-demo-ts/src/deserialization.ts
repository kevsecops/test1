/**
 * deserialization.ts — Insecure deserialization and template injection
 *
 * SAST findings:
 *   - CWE-502: insecure deserialization (node-serialize — CVE-2017-5941)
 *   - CWE-94:  SSTI via ejs (CVE-2022-29078) and handlebars (CVE-2021-23369)
 *   - CWE-95:  eval of deserialized JSON content
 *   - SonarQube S5135, S5334
 *
 * Dependencies:
 *   node-serialize 0.0.4 — CVE-2017-5941 (RCE via deserialized function)
 *   ejs            2.6.1 — CVE-2022-29078 (RCE via template option injection)
 *   handlebars     4.5.3 — CVE-2021-23369 (prototype pollution / RCE)
 */
import * as ejs from "ejs";
import * as handlebars from "handlebars";
import * as serialize from "node-serialize";

// -------------------------------------------------------------------------
// Finding 1: node-serialize.unserialize on untrusted data (CVE-2017-5941)
// An attacker can embed an IIFE in the serialized string to achieve RCE:
// {"cmd":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
// -------------------------------------------------------------------------
export function deserializeUserData(raw: string): any {
  // SAST: node-serialize.unserialize executes embedded functions — RCE
  return serialize.unserialize(raw);
}

// -------------------------------------------------------------------------
// Finding 2: eval of parsed JSON property
// -------------------------------------------------------------------------
export function processConfig(jsonString: string): any {
  const config = JSON.parse(jsonString);
  // SAST: eval on a property from parsed untrusted JSON — code execution
  return eval(config.transform);
}

// -------------------------------------------------------------------------
// Finding 3: EJS render with user-controlled template (CVE-2022-29078)
// Attacker can inject options like outputFunctionName to achieve RCE
// -------------------------------------------------------------------------
export function renderEjs(template: string, data: object): string {
  // SAST: ejs.render() with user-controlled template string — SSTI / RCE
  return ejs.render(template, data);
}

// -------------------------------------------------------------------------
// Finding 4: EJS renderFile with user-controlled path — path traversal + RCE
// -------------------------------------------------------------------------
export async function renderEjsFile(filename: string, data: object): Promise<string> {
  // SAST: user-controlled filename in ejs.renderFile() — path traversal
  return ejs.renderFile(filename, data);
}

// -------------------------------------------------------------------------
// Finding 5: Handlebars compile with user-supplied template (CVE-2021-23369)
// -------------------------------------------------------------------------
export function renderHandlebars(templateSrc: string, context: object): string {
  // SAST: handlebars.compile() with untrusted template — prototype pollution / RCE
  const template = handlebars.compile(templateSrc);
  return template(context);
}

// -------------------------------------------------------------------------
// Finding 6: JSON.parse result used as object keys without validation
// (enables prototype pollution via __proto__ key)
// -------------------------------------------------------------------------
export function mergeSettings(base: any, jsonInput: string): any {
  const overrides = JSON.parse(jsonInput);
  // SAST: spreading parsed JSON with __proto__ key pollutes prototype
  return Object.assign(base, overrides);
}
