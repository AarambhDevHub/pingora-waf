
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0; 1024];

    // Read the request
    let _ = stream.read(&mut buffer);

    // Simple HTTP response
    let response = "HTTP/1.1 200 OK\r\n\
                   Content-Type: application/json\r\n\
                   Content-Length: 27\r\n\
                   Connection: close\r\n\
                   \r\n\
                   {\"status\":\"ok\",\"data\":\"test\"}";

    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port 8080");
    println!("Mock backend server running on http://127.0.0.1:8080");
    println!("Ready to receive requests from WAF proxy\n");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
}
