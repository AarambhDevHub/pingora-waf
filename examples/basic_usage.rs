use reqwest::blocking::Client;
use std::time::Duration;

fn main() {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    println!("Testing WAF Proxy...\n");

    // Test 1: Normal request
    println!("1. Normal request:");
    let resp = client.get("http://localhost:6188/api/users").send();
    println!("Response: {:?}\n", resp.map(|r| r.status()));

    // Test 2: SQL injection attempt
    println!("2. SQL injection attempt:");
    let resp = client
        .get("http://localhost:6188/api/users?id=1 OR 1=1")
        .send();
    println!("Response: {:?}\n", resp.map(|r| r.status()));

    // Test 3: XSS attempt
    println!("3. XSS attempt:");
    let resp = client
        .post("http://localhost:6188/api/comment")
        .body("<script>alert('XSS')</script>")
        .send();
    println!("Response: {:?}\n", resp.map(|r| r.status()));

    // Test 4: Rate limiting
    println!("4. Rate limiting test (sending 105 requests):");
    for i in 1..=105 {
        let resp = client.get("http://localhost:6188/api/test").send();
        if resp.is_err() || resp.as_ref().unwrap().status().as_u16() == 429 {
            println!("Request {} - Rate limited!", i);
            break;
        }
        if i % 25 == 0 {
            println!("Sent {} requests...", i);
        }
    }

    println!("\nCheck metrics at: http://localhost:6190/metrics");
}
