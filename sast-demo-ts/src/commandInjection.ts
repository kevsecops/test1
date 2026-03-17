/**
 * commandInjection.ts — OS command injection, eval, and prototype pollution
 *
 * SAST findings:
 *   - CWE-77/78: command injection via child_process.exec with shell
 *   - CWE-95:  eval() / Function() with user-controlled input
 *   - CWE-1321: prototype pollution via unsafe object merge
 *   - SonarQube S4721, S2076; Semgrep javascript.lang.security.detect-child-process
 *
 * Dependency: lodash 4.17.15 — CVE-2021-23337 (command injection via template)
 *                              CVE-2020-8203  (prototype pollution)
 */
import { exec, execSync, spawn } from "child_process";
import _ from "lodash";

// -------------------------------------------------------------------------
// Finding 1: child_process.exec with user input — command injection
// -------------------------------------------------------------------------
export function pingHost(host: string): void {
  // SAST: exec with unsanitized user input — arbitrary command execution
  exec("ping -c 1 " + host, (err, stdout) => console.log(stdout));
}

// -------------------------------------------------------------------------
// Finding 2: execSync with template literal — command injection
// -------------------------------------------------------------------------
export function getFileInfo(path: string): string {
  // SAST: execSync with user-controlled path — command injection
  return execSync(`ls -la ${path}`).toString();
}

// -------------------------------------------------------------------------
// Finding 3: spawn with shell:true — command injection
// -------------------------------------------------------------------------
export function compressFile(filename: string): void {
  // SAST: shell:true with user-controlled args — command injection
  spawn("zip", ["archive.zip", filename], { shell: true });
}

// -------------------------------------------------------------------------
// Finding 4: eval() with user-controlled expression
// -------------------------------------------------------------------------
export function calculate(expression: string): any {
  // SAST: eval() with untrusted input — arbitrary code execution (CWE-95)
  return eval(expression);
}

// -------------------------------------------------------------------------
// Finding 5: new Function() with user input — equivalent to eval
// -------------------------------------------------------------------------
export function runDynamic(code: string): any {
  // SAST: Function constructor with user input — arbitrary code execution
  return new Function("return " + code)();
}

// -------------------------------------------------------------------------
// Finding 6: Prototype pollution via unsafe recursive merge (lodash CVE-2020-8203)
// -------------------------------------------------------------------------
export function mergeUserPrefs(defaults: object, userInput: any): object {
  // SAST: _.merge with untrusted nested object can pollute Object.prototype
  // e.g. userInput = { "__proto__": { "isAdmin": true } }
  return _.merge({}, defaults, userInput);
}

// -------------------------------------------------------------------------
// Finding 7: Prototype pollution via manual property assignment
// -------------------------------------------------------------------------
export function assignConfig(config: any, key: string, value: any): void {
  // SAST: dynamic property assignment without key sanitization — prototype pollution
  config[key] = value;
}

// -------------------------------------------------------------------------
// Finding 8: lodash template with user input (CVE-2021-23337)
// -------------------------------------------------------------------------
export function renderTemplate(templateStr: string, data: object): string {
  // SAST: lodash _.template with user-controlled string — RCE via template injection
  const compiled = _.template(templateStr);
  return compiled(data);
}
