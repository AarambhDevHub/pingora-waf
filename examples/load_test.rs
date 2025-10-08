use reqwest::blocking::Client;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    println!("WAF Load Testing Tool\n");

    // Simulate multiple clients to avoid single-IP rate limiting
    let threads = 10;
    let requests_per_thread = 100;  // Total: 1000 requests
    let delay_between_requests_ms = 10; // Throttle to ~100 req/sec per thread
    let total_requests = threads * requests_per_thread;

    let success_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));
    let blocked_count = Arc::new(AtomicU64::new(0));
    let total_latency = Arc::new(AtomicU64::new(0));

    println!("Configuration:");
    println!("  Threads: {}", threads);
    println!("  Requests per thread: {}", requests_per_thread);
    println!("  Delay between requests: {}ms", delay_between_requests_ms);
    println!("  Total requests: {}\n", total_requests);

    let start = Instant::now();

    let handles: Vec<_> = (0..threads)
        .map(|thread_id| {
            let success = Arc::clone(&success_count);
            let errors = Arc::clone(&error_count);
            let blocked = Arc::clone(&blocked_count);
            let latency = Arc::clone(&total_latency);

            thread::spawn(move || {
                let client = Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .unwrap();

                for i in 0..requests_per_thread {
                    let req_start = Instant::now();

                    match client
                        .get(&format!("http://localhost:6188/api/test?id={}&thread={}", i, thread_id))
                        .send()
                    {
                        Ok(resp) => {
                            let req_duration = req_start.elapsed().as_millis() as u64;
                            latency.fetch_add(req_duration, Ordering::Relaxed);

                            match resp.status().as_u16() {
                                200..=299 => success.fetch_add(1, Ordering::Relaxed),
                                403 | 429 => blocked.fetch_add(1, Ordering::Relaxed),
                                _ => errors.fetch_add(1, Ordering::Relaxed),
                            };
                        }
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    // Throttle requests to avoid rate limiting
                    if delay_between_requests_ms > 0 {
                        thread::sleep(Duration::from_millis(delay_between_requests_ms));
                    }

                    if (i + 1) % 25 == 0 {
                        println!("Thread {} completed {} requests", thread_id, i + 1);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let duration = start.elapsed();
    let success = success_count.load(Ordering::Relaxed);
    let errors = error_count.load(Ordering::Relaxed);
    let blocked = blocked_count.load(Ordering::Relaxed);
    let avg_latency = if success > 0 {
        total_latency.load(Ordering::Relaxed) / success
    } else {
        0
    };

    println!("\n=== Load Test Results ===");
    println!("Total time: {:.2}s", duration.as_secs_f64());
    println!("Requests per second: {:.2}", total_requests as f64 / duration.as_secs_f64());
    println!("Average latency: {}ms", avg_latency);
    println!("\nResults:");
    println!("  ✓ Successful: {} ({:.1}%)", success, (success as f64 / total_requests as f64) * 100.0);
    println!("  ✗ Errors: {} ({:.1}%)", errors, (errors as f64 / total_requests as f64) * 100.0);
    println!("  ⛔ Blocked by WAF: {} ({:.1}%)", blocked, (blocked as f64 / total_requests as f64) * 100.0);

    if success > 0 {
        println!("\n✅ Success! WAF is allowing legitimate traffic");
    } else if blocked == total_requests {
        println!("\n⚠️  All requests blocked - rate limit too strict or backend unreachable");
        println!("   Try: cargo run -- -c config/waf_rules_testing.yaml");
    }
}
