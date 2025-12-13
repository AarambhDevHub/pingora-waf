//! Path Traversal Attack Test Suite
//!
//! Run with: cargo run --example path_traversal_test
//!
//! Prerequisites:
//! 1. Start backend: cargo run --example mock_backend_tokio
//! 2. Start WAF: cargo run

use reqwest::blocking::Client;
use std::time::Duration;

fn main() {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("PINGORA_WAF_TEST_SUITE")
        .build()
        .unwrap();

    println!("╔═══════════════════════════════════════════════╗");
    println!("║   Path Traversal Detection Tests              ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: Basic directory traversal
    println!("🛡️  Test 1: Basic Directory Traversal");
    let basic_attacks = vec![
        ("/api/file?path=../../../etc/passwd", "Unix passwd"),
        (
            "/api/file?path=..\\..\\..\\windows\\system32",
            "Windows system32",
        ),
        ("/api/file?path=../../config/database.yml", "Config file"),
        ("/api/download?file=../../../etc/shadow", "Shadow file"),
    ];

    for (path, desc) in &basic_attacks {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!(
                    "   ✓ Blocked: {} ({})",
                    desc,
                    path.chars().take(40).collect::<String>()
                );
                passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ NOT BLOCKED ({}): {}", resp.status(), desc);
                failed += 1;
            }
            Err(e) => {
                println!("   ✗ Error: {} - {}", desc, e);
                failed += 1;
            }
        }
    }

    // Test 2: URL Encoded traversal
    println!("\n🛡️  Test 2: URL Encoded Traversal");
    let encoded_attacks = vec![
        (
            "/api/file?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "URL encoded ../",
        ),
        (
            "/api/file?path=%2e%2e/%2e%2e/etc/passwd",
            "Partial encoding",
        ),
        ("/api/file?path=..%2f..%2f..%2fetc/passwd", "Mixed encoding"),
        (
            "/api/file?path=%2e%2e%5c%2e%2e%5cwindows",
            "Windows encoded",
        ),
    ];

    for (path, desc) in &encoded_attacks {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!("   ✓ Blocked: {}", desc);
                passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ NOT BLOCKED ({}): {}", resp.status(), desc);
                failed += 1;
            }
            Err(_) => {
                println!("   ✗ Error testing: {}", desc);
                failed += 1;
            }
        }
    }

    // Test 3: Double encoding bypass attempts
    println!("\n🛡️  Test 3: Double Encoding Bypass");
    let double_encoded = vec![
        ("/api/file?path=%252e%252e%252f", "Double encoded ../"),
        ("/api/file?path=%252e%252e/", "Double dot, single slash"),
    ];

    for (path, desc) in &double_encoded {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!("   ✓ Blocked: {}", desc);
                passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ NOT BLOCKED ({}): {}", resp.status(), desc);
                failed += 1;
            }
            Err(_) => {
                println!("   ✗ Error testing: {}", desc);
                failed += 1;
            }
        }
    }

    // Test 4: Sensitive file access
    println!("\n🛡️  Test 4: Sensitive File Access");
    let sensitive_files = vec![
        ("/api/.htaccess", ".htaccess"),
        ("/api/config/.env", ".env file"),
        ("/api/.git/config", "Git config"),
        ("/api/wp-config.php", "WordPress config"),
        ("/.ssh/id_rsa", "SSH private key"),
        ("/etc/passwd", "Passwd direct"),
    ];

    for (path, desc) in &sensitive_files {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!("   ✓ Blocked: {}", desc);
                passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ NOT BLOCKED ({}): {}", resp.status(), desc);
                failed += 1;
            }
            Err(_) => {
                println!("   ✗ Error testing: {}", desc);
                failed += 1;
            }
        }
    }

    // Test 5: Null byte injection
    println!("\n🛡️  Test 5: Null Byte Injection");
    let null_byte_attacks = vec![
        ("/api/file.txt%00.jpg", "Null byte extension bypass"),
        ("/api/../etc/passwd%00", "Traversal with null byte"),
    ];

    for (path, desc) in &null_byte_attacks {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!("   ✓ Blocked: {}", desc);
                passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ NOT BLOCKED ({}): {}", resp.status(), desc);
                failed += 1;
            }
            Err(_) => {
                println!("   ✗ Error testing: {}", desc);
                failed += 1;
            }
        }
    }

    // Test 6: Path traversal in request body
    println!("\n🛡️  Test 6: Path Traversal in Body");
    let body_attacks = vec![
        r#"{"path": "../../../etc/passwd"}"#,
        r#"{"file": "..\\..\\windows\\system32\\config\\SAM"}"#,
    ];

    for payload in &body_attacks {
        match client
            .post("http://localhost:6188/api/file")
            .header("Content-Type", "application/json")
            .body(*payload)
            .send()
        {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!(
                    "   ✓ Blocked body traversal: {}",
                    payload.chars().take(40).collect::<String>()
                );
                passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ NOT BLOCKED ({}): {}", resp.status(), payload);
                failed += 1;
            }
            Err(_) => {
                println!("   ✗ Error testing body injection");
                failed += 1;
            }
        }
    }

    // Test 7: Legitimate requests should pass
    println!("\n✅ Test 7: Legitimate Requests (should pass)");
    let legitimate = vec![
        ("/api/users/123/profile", "User profile"),
        ("/api/files/documents/report.pdf", "Normal file path"),
        ("/api/search?q=hello+world", "Normal query"),
    ];

    for (path, desc) in &legitimate {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 200 => {
                println!("   ✓ Allowed: {}", desc);
                passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ BLOCKED LEGITIMATE ({}): {}", resp.status(), desc);
                failed += 1;
            }
            Err(_) => {
                println!("   ✗ Error testing: {}", desc);
                failed += 1;
            }
        }
    }

    // Summary
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║   Path Traversal Test Summary                 ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!("Total Tests: {}", passed + failed);
    println!("✅ Passed: {}", passed);
    println!("❌ Failed: {}", failed);
    println!(
        "Success Rate: {:.1}%\n",
        (passed as f64 / (passed + failed) as f64) * 100.0
    );

    if failed == 0 {
        println!("🎉 All path traversal tests passed!");
    } else {
        println!("⚠️  Some tests failed. Review path traversal configuration.");
    }
}
