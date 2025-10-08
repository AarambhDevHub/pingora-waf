use bytes::Bytes;
use parking_lot::Mutex;
use pingora::{Error, ErrorType};
use std::sync::Arc;

pub struct BodyInspector {
    pub max_body_size: usize,
    pub buffer: Arc<Mutex<Vec<u8>>>,
    pub enabled: bool,
}

impl BodyInspector {
    pub fn new(max_body_size: usize, enabled: bool) -> Self {
        Self {
            max_body_size,
            buffer: Arc::new(Mutex::new(Vec::new())),
            enabled,
        }
    }

    pub fn append_chunk(&self, chunk: &Bytes) -> Result<(), Box<Error>> {
        if !self.enabled {
            return Ok(());
        }

        let mut buffer = self.buffer.lock();

        if buffer.len() + chunk.len() > self.max_body_size {
            return Err(Error::because(
                ErrorType::InvalidHTTPHeader,
                format!(
                    "Request body exceeds maximum size of {} bytes",
                    self.max_body_size
                ),
                Error::new(ErrorType::InvalidHTTPHeader),
            ));
        }

        buffer.extend_from_slice(chunk);
        Ok(())
    }

    pub fn get_body(&self) -> Vec<u8> {
        self.buffer.lock().clone()
    }

    pub fn clear(&self) {
        self.buffer.lock().clear();
    }
}
