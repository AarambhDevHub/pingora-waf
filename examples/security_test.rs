use reqwest::blocking::Client;
use std::time::Duration;

fn main() {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    println!("╔═══════════════════════════════════════════════╗");
    println!("║   WAF Security Verification Tests            ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: Normal requests should pass
    println!("✅ Test 1: Legitimate requests");
    match client.get("http://localhost:6188/api/users?id=123").send() {
        Ok(resp) if resp.status().as_u16() == 200 => {
            println!("   ✓ Normal request allowed (200 OK)");
            passed += 1;
        }
        _ => {
            println!("   ✗ Normal request blocked (FAIL)");
            failed += 1;
        }
    }

    // Test 2: SQL Injection - URI
    println!("\n🛡️  Test 2: SQL Injection in URI");
    let sql_attacks = vec![
        "/api/users?id=1 OR 1=1",
        "/api/users?id=1' UNION SELECT * FROM passwords--",
        "/api/users?id=1; DROP TABLE users",
        "/api/login?user=admin'--&pass=x",
    ];

    for attack in &sql_attacks {
        match client
            .get(&format!("http://localhost:6188{}", attack))
            .send()
        {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!("   ✓ Blocked: {}", attack);
                passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ NOT BLOCKED ({}): {}", resp.status(), attack);
                failed += 1;
            }
            Err(_) => {
                println!("   ✗ Error testing: {}", attack);
                failed += 1;
            }
        }
    }

    // Test 3: XSS Attacks
    println!("\n🛡️  Test 3: XSS Attacks in Body");
    let xss_payloads = vec![
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
    ];

    for payload in &xss_payloads {
        match client
            .post("http://localhost:6188/api/comment")
            .body(*payload)
            .send()
        {
            Ok(resp) if resp.status().as_u16() == 403 => {
                println!(
                    "   ✓ Blocked XSS: {}",
                    payload.chars().take(30).collect::<String>()
                );
                passed += 1;
            }
            Ok(resp) => {
                println!("   ✗ NOT BLOCKED ({}): {}", resp.status(), payload);
                failed += 1;
            }
            Err(_) => {
                println!("   ✗ Error testing XSS");
                failed += 1;
            }
        }
    }

    // Test 4: SQL Injection in Headers
    println!("\n🛡️  Test 4: SQL Injection in Custom Headers");
    match client
        .get("http://localhost:6188/api/users")
        .header("X-Custom-Header", "1' OR '1'='1")
        .send()
    {
        Ok(resp) if resp.status().as_u16() == 403 => {
            println!("   ✓ Blocked SQL injection in header");
            passed += 1;
        }
        _ => {
            println!("   ✗ Header injection not blocked");
            failed += 1;
        }
    }

    // Test 5: Rate Limiting
    println!("\n🛡️  Test 5: Rate Limiting (sending 110 rapid requests)");
    let mut rate_limited = false;
    for i in 1..=110 {
        if let Ok(resp) = client.get("http://localhost:6188/api/test").send() {
            if resp.status().as_u16() == 429 {
                println!("   ✓ Rate limited at request #{}", i);
                rate_limited = true;
                passed += 1;
                break;
            }
        }
    }
    if !rate_limited {
        println!("   ✗ Rate limiting not working");
        failed += 1;
    }

    // Test 6: Large Body
    println!("\n🛡️  Test 6: Large Request Body (2MB)");
    let large_body = "x".repeat(2 * 1024 * 1024);
    match client
        .post("http://localhost:6188/api/upload")
        .body(large_body)
        .send()
    {
        Ok(resp) if resp.status().as_u16() == 403 || resp.status().as_u16() == 413 => {
            println!("   ✓ Large body rejected");
            passed += 1;
        }
        Ok(resp) => {
            println!("   ✗ Large body NOT rejected (got {})", resp.status());
            failed += 1;
        }
        Err(e) => {
            // Connection might be closed early, which is also acceptable
            println!("   ✓ Large body rejected (connection closed: {})", e);
            passed += 1;
        }
    }

    // Summary
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║   Test Summary                                ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!("Total Tests: {}", passed + failed);
    println!("✅ Passed: {}", passed);
    println!("❌ Failed: {}", failed);
    println!(
        "Success Rate: {:.1}%\n",
        (passed as f64 / (passed + failed) as f64) * 100.0
    );

    if failed == 0 {
        println!("🎉 All security tests passed! WAF is working correctly.");
    } else {
        println!("⚠️  Some tests failed. Review WAF configuration.");
    }

    println!("\n📊 Check metrics: http://localhost:6190/metrics");
}
