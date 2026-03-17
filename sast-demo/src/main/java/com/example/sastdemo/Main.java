package com.example.sastdemo;

/**
 * Entry point for the SAST demo application.
 *
 * Starts all demo threads and calls vulnerable methods so that SAST tools
 * can analyse the complete call graph.
 */
public class Main {

    public static void main(String[] args) throws Exception {

        // --- Demo 1: race condition on static int (threads 1 & 2) ---
        Thread t1 = new Thread(SharedCounterDemo.createWorker("CounterThread-1"));
        Thread t2 = new Thread(SharedCounterDemo.createWorker("CounterThread-2"));
        t1.start();
        t2.start();

        // --- Demo 2: unsynchronized HashMap access (threads 3 & 4) ---
        Thread t3 = new Thread(SharedMapDemo.createWriter("MapThread-1"));
        Thread t4 = new Thread(SharedMapDemo.createWriter("MapThread-2"));
        t3.start();
        t4.start();

        // Wait for all threads to finish
        t1.join();
        t2.join();
        t3.join();
        t4.join();

        System.out.println("Final counter value (racy): " + SharedCounterDemo.counter);

        // --- Demo 3: additional SAST findings ---
        VulnerableCode vc = new VulnerableCode();

        // (E) insecure token generation
        System.out.println("Generated token: " + vc.generateToken());

        // (F) exception swallowing
        vc.riskyOperation();

        // (H) String comparison with ==
        System.out.println("Is admin: " + vc.isAdmin("admin"));

        // (A) SQL injection — requires a DB driver; shown for SAST analysis
        // vc.findUserByName("Alice' OR '1'='1");

        // (C) null pointer dereference
        // vc.printUpperCase("hello");

        // (D) resource leak
        // vc.readFile("/tmp/test.txt");

        // (G) path traversal
        // vc.openUserFile("../../etc/passwd");
    }
}
