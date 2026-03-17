package com.example.sastdemo;

import java.io.File;
import java.io.FileInputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.SecureRandom;

/**
 * A collection of additional Java vulnerabilities detectable by SAST tools.
 * Each method is intentionally broken to demonstrate a specific finding.
 */
public class VulnerableCode {

    // -------------------------------------------------------------------------
    // (B) SAST: Hardcoded credentials
    // Tools: SonarQube S2068, SpotBugs HRS_REQUEST_PARAMETER_TO_HTTP_HEADER,
    // Checkmarx, Semgrep java.lang.security.hardcoded-credentials
    // -------------------------------------------------------------------------
    private static final String DB_PASSWORD = "s3cr3tP@ssw0rd!"; // hardcoded password
    private static final String API_KEY = "AKIAIOSFODNN7EXAMPLE"; // hardcoded API key

    // -------------------------------------------------------------------------
    // (A) SAST: SQL Injection
    // User input is concatenated directly into a SQL query string.
    // Tools: SonarQube S3649, SpotBugs SQL_INJECTION, FindSecBugs
    // -------------------------------------------------------------------------
    public void findUserByName(String username) throws Exception {
        Connection conn = DriverManager.getConnection(
                "jdbc:h2:mem:test", "sa", DB_PASSWORD);
        Statement stmt = conn.createStatement();

        // SAST: string concatenation with untrusted input — SQL injection risk
        String query = "SELECT * FROM users WHERE name = '" + username + "'";
        ResultSet rs = stmt.executeQuery(query);

        while (rs.next()) {
            System.out.println("Found user: " + rs.getString("name"));
        }
        // SAST (D): Connection, Statement and ResultSet are never closed — resource
        // leak
    }

    // -------------------------------------------------------------------------
    // (C) SAST: Null pointer dereference
    // The return value of a method that can return null is used without a null
    // check.
    // Tools: SonarQube S2259, SpotBugs NP_NULL_ON_SOME_PATH
    // -------------------------------------------------------------------------
    public void printUpperCase(String input) {
        // SAST: System.getProperty() can return null; calling .length() without null
        // check
        String property = System.getProperty("nonexistent.property");
        System.out.println("Property length: " + property.length()); // potential NPE

        // Also: input itself is never validated for null before use
        System.out.println(input.toUpperCase());
    }

    // -------------------------------------------------------------------------
    // (D) SAST: Resource leak
    // FileInputStream is opened but never closed (no try-with-resources).
    // Tools: SonarQube S2095, SpotBugs OBL_UNSATISFIED_OBLIGATION
    // -------------------------------------------------------------------------
    public void readFile(String path) throws Exception {
        // SAST: resource is never closed; if an exception is thrown it leaks
        FileInputStream fis = new FileInputStream(path);
        int b;
        while ((b = fis.read()) != -1) {
            System.out.print((char) b);
        }
        // fis.close() is missing — resource leak
    }

    // -------------------------------------------------------------------------
    // (E) SAST: Insecure randomness
    // java.util.Random is predictable and must not be used for security tokens.
    // Tools: SonarQube S2245, SpotBugs DMI_RANDOM_USED_ONLY_ONCE,
    // FindSecBugs PREDICTABLE_RANDOM
    // -------------------------------------------------------------------------
    public String generateToken() {
        // SAST: java.util.Random is not cryptographically secure
        SecureRandom random = new SecureRandom();
        long token = random.nextLong();
        return Long.toHexString(token);
    }

    // -------------------------------------------------------------------------
    // (F) SAST: Empty catch block (exception swallowing)
    // Catching an exception and doing nothing hides failures silently.
    // Tools: SonarQube S2221 / S1166, SpotBugs DE_MIGHT_IGNORE
    // -------------------------------------------------------------------------
    public void riskyOperation() {
        try {
            String s = null;
            s.length(); // will throw NullPointerException
        } catch (Exception e) {
            // SAST: exception is caught and silently swallowed — no logging, no rethrow
        }
    }

    // -------------------------------------------------------------------------
    // (G) SAST: Path traversal
    // User-controlled input is used directly to construct a file path,
    // allowing an attacker to escape the intended directory (e.g.
    // "../../etc/passwd").
    // Tools: SonarQube S2083, SpotBugs PATH_TRAVERSAL_IN, FindSecBugs
    // -------------------------------------------------------------------------
    public void openUserFile(String userInput) throws Exception {
        // SAST: path traversal — userInput is not sanitized or validated
        File file = new File("/app/data/" + userInput);
        FileInputStream fis = new FileInputStream(file);
        fis.close();
    }

    // -------------------------------------------------------------------------
    // (H) SAST: String comparison with == instead of .equals()
    // == compares object references, not content; yields unpredictable results
    // for non-interned strings.
    // Tools: SonarQube S1698, SpotBugs ES_COMPARING_STRINGS_WITH_EQ
    // -------------------------------------------------------------------------
    public boolean isAdmin(String role) {
        // SAST: reference equality used instead of value equality for String
        return role == "admin"; // should be role.equals("admin")
    }
}
