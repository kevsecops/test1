package com.example.sastdemo;

import java.util.HashMap;

/**
 * SAST Finding: Unsynchronized access to a non-thread-safe HashMap.
 *
 * Two threads call put() and get() on the same HashMap instance without
 * any locking. HashMap is explicitly documented as not thread-safe;
 * concurrent structural modifications can cause infinite loops or data
 * corruption at runtime.
 * SAST tools (e.g. SpotBugs, SonarQube S2EM) should flag this pattern.
 */
public class SharedMapDemo {

    // SAST: HashMap is not thread-safe; shared across threads without synchronization
    public static HashMap<String, String> sharedMap = new HashMap<>();

    public static Runnable createWriter(String threadName) {
        return () -> {
            for (int i = 0; i < 10_000; i++) {
                // SAST: unsynchronized write to shared HashMap
                sharedMap.put(threadName + "-key-" + i, "value-" + i);
                // SAST: unsynchronized read from shared HashMap
                String val = sharedMap.get(threadName + "-key-" + i);
                System.out.println(threadName + " read: " + val);
            }
        };
    }
}
