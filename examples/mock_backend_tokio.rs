use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn handle_client(
    mut stream: TcpStream,
    request_count: &'static std::sync::atomic::AtomicU64,
) {
    let start = Instant::now();
    let mut buffer = vec![0; 4096];

    // Read request
    match stream.read(&mut buffer).await {
        Ok(n) if n > 0 => {
            let request = String::from_utf8_lossy(&buffer[..n]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");

            let count = request_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // Log request
            // if count % 100 == 0 {
            //     println!(
            //         "[{}] Handled {} requests - Latest: {}",
            //         chrono::Local::now().format("%H:%M:%S"),
            //         count,
            //         path
            //     );
            // }

            // Send response
            let response_body = format!(
                r#"{{"status":"ok","request_id":{},"path":"{}","latency_ms":{}}}"#,
                count,
                path,
                start.elapsed().as_millis()
            );

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                Content-Type: application/json\r\n\
                Content-Length: {}\r\n\
                Connection: close\r\n\
                X-Request-ID: {}\r\n\
                \r\n\
                {}",
                response_body.len(),
                count,
                response_body
            );

            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        }
        _ => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::atomic::AtomicU64;

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    let request_count: &'static AtomicU64 = Box::leak(Box::new(AtomicU64::new(0)));

    println!("╔═══════════════════════════════════════════════╗");
    println!("║   Mock Backend Server (Tokio)                ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!("📡 Listening on: http://127.0.0.1:8080");
    println!("🔥 Ready to handle WAF proxy requests\n");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(async move {
                    handle_client(stream, request_count).await;
                });
            }
            Err(e) => {
                eprintln!("❌ Connection error: {}", e);
            }
        }
    }
}
