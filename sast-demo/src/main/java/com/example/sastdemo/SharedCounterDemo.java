package com.example.sastdemo;

/**
 * SAST Finding: Data race on a shared static integer field.
 *
 * Two threads concurrently read and write `counter` without any synchronization
 * (no `synchronized`, no `volatile`, no `AtomicInteger`).
 * This causes a data race that SAST tools (e.g. SpotBugs IS2_INCONSISTENT_SYNC,
 * SonarQube S2885) should flag.
 */
public class SharedCounterDemo {

    // SAST: shared mutable static field accessed from multiple threads without synchronization
    public static int counter = 0;

    public static Runnable createWorker(String name) {
        return () -> {
            for (int i = 0; i < 10_000; i++) {
                // SAST: non-atomic read-modify-write on unsynchronized field
                int current = counter;
                counter = current + 1;
            }
            System.out.println(name + " finished. counter=" + counter);
        };
    }
}
