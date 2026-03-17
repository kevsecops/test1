# SAST Demo — Java (Maven)

A Maven Java project containing **intentional programming errors and CVE-carrying dependencies** designed to be detected by SAST tools such as SpotBugs, SonarQube, FindSecBugs, Checkmarx, Semgrep, and dependency scanners like OWASP Dependency-Check and Snyk.

## Project Structure

```
sast-demo/
├── pom.xml
└── src/main/java/com/example/sastdemo/
    ├── Main.java                     # Entry point; launches all threads
    ├── SharedCounterDemo.java        # Race condition on static int
    ├── SharedMapDemo.java            # Unsynchronized HashMap access
    ├── VulnerableCode.java           # Additional SAST findings
    └── VulnerableDependencies.java   # CVE-carrying dependency usage
```

## Build

```bash
mvn compile
mvn package
```

Requires Java 11+ and Maven 3.x.

---

## Dependencies with Known CVEs (9 total)

| Package | Version | CVE | Severity | Description |
|---------|---------|-----|----------|-------------|
| log4j-core | 2.14.1 | CVE-2021-44228 | 🔴 Critical (10.0) | **Log4Shell** — RCE via JNDI lookup in log messages |
| spring-webmvc | 5.3.0 | CVE-2022-22965 | 🔴 Critical (9.8) | **Spring4Shell** — RCE via data binding |
| jackson-databind | 2.9.8 | CVE-2019-14379 | 🔴 Critical (9.8) | RCE via unsafe polymorphic deserialization |
| commons-collections | 3.2.1 | CVE-2015-7501 | 🔴 Critical (9.8) | RCE via deserialization gadget chain |
| xstream | 1.4.15 | CVE-2021-29505 | 🔴 High (8.8) | RCE via unsafe XML deserialization |
| struts2-core | 2.3.32 | CVE-2017-5638 | 🔴 Critical (10.0) | RCE via Content-Type header (Equifax breach) |
| bcprov-jdk15on | 1.60 | CVE-2020-28052 | 🟠 High (8.1) | Authentication bypass in OpenBSDBCrypt |
| shiro-core | 1.4.0 | CVE-2019-12422 | 🟠 High (7.4) | Authentication bypass via RememberMe cookie |
| hibernate-core | 5.4.0.Final | CVE-2019-14900 | 🟠 High (6.5) | SQL injection via Criteria API |

### Run Dependency Scan

```bash
# OWASP Dependency-Check (Maven plugin)
mvn org.owasp:dependency-check-maven:check

# Snyk
snyk test --all-projects
```

---

## Expected SAST Findings (11 total)

### 🔴 Concurrency / Data Races

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 1 | `SharedCounterDemo.java` | Two threads read/write `static int counter` without `synchronized`, `volatile`, or `AtomicInteger` | SpotBugs `IS2_INCONSISTENT_SYNC`, SonarQube `S2885` |
| 2 | `SharedMapDemo.java` | Two threads call `put()`/`get()` on a `HashMap` without synchronization | SpotBugs `IS2_INCONSISTENT_SYNC`, SonarQube `S2885` |

### 🔴 Injection

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 3 | `VulnerableCode.java` | **SQL Injection** — user input concatenated directly into SQL query | SpotBugs `SQL_INJECTION`, SonarQube `S3649`, FindSecBugs |

### 🔴 Sensitive Data Exposure

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 4 | `VulnerableCode.java` | **Hardcoded password** (`s3cr3tP@ssw0rd!`) as a `String` constant | SonarQube `S2068`, Semgrep `hardcoded-credentials` |
| 5 | `VulnerableCode.java` | **Hardcoded API key** (`AKIAIOSFODNN7EXAMPLE`) as a `String` constant | SonarQube `S2068`, Semgrep `hardcoded-credentials` |

### 🔴 Path Traversal

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 6 | `VulnerableCode.java` | **Path traversal** — unsanitized user input used directly in `new File(…)` | SpotBugs `PATH_TRAVERSAL_IN`, SonarQube `S2083` |

### 🟠 Reliability / Crash Risk

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 7 | `VulnerableCode.java` | **Null pointer dereference** — `System.getProperty()` used without null check | SpotBugs `NP_NULL_ON_SOME_PATH`, SonarQube `S2259` |
| 8 | `VulnerableCode.java` | **Resource leak** — `FileInputStream` never closed (no try-with-resources) | SpotBugs `OBL_UNSATISFIED_OBLIGATION`, SonarQube `S2095` |
| 9 | `VulnerableCode.java` | **Empty catch block** — exception silently swallowed | SpotBugs `DE_MIGHT_IGNORE`, SonarQube `S1166` |

### 🟡 Code Quality / Logic Errors

| # | File | Issue | SAST Rule |
|---|------|-------|-----------|
| 10 | `VulnerableCode.java` | **Insecure randomness** — `java.util.Random` for security token | SpotBugs `DMI_RANDOM_USED_ONLY_ONCE`, SonarQube `S2245` |
| 11 | `VulnerableCode.java` | **String `==` comparison** — reference equality instead of `.equals()` | SpotBugs `ES_COMPARING_STRINGS_WITH_EQ`, SonarQube `S1698` |
