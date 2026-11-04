//! CLI-side IPC client: JSON-line exchanges with the daemon, plus the
//! two-step stdin streaming flow for `ap send -`.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::config;

pub struct Ipc {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

#[derive(Debug)]
pub enum IpcError {
    NotRunning,
    Io(std::io::Error),
    Protocol(String),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcError::NotRunning => write!(f, "daemon 未运行"),
            IpcError::Io(e) => write!(f, "{e}"),
            IpcError::Protocol(s) => write!(f, "{s}"),
        }
    }
}

impl Ipc {
    pub fn connect() -> Result<Self, IpcError> {
        let path = config::sock_path();
        let stream = UnixStream::connect(&path).map_err(|_| IpcError::NotRunning)?;
        let reader = BufReader::new(stream.try_clone().map_err(IpcError::Io)?);
        Ok(Self { stream, reader })
    }

    pub fn send_raw(&mut self, line: &str) -> Result<(), IpcError> {
        self.stream
            .write_all(line.as_bytes())
            .and_then(|_| self.stream.write_all(b"\n"))
            .and_then(|_| self.stream.flush())
            .map_err(IpcError::Io)
    }

    /// Read one JSON reply line.
    pub fn recv(&mut self) -> Result<serde_json::Value, IpcError> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Err(IpcError::Protocol("daemon closed the connection".into())),
            Ok(_) => serde_json::from_str(line.trim())
                .map_err(|e| IpcError::Protocol(format!("bad reply: {e}"))),
            Err(e) => Err(IpcError::Io(e)),
        }
    }

    pub fn request(&mut self, v: serde_json::Value) -> Result<serde_json::Value, IpcError> {
        self.send_raw(&v.to_string())?;
        self.recv()
    }

    /// `ap send -`: stream stdin over the same connection after the token
    /// handshake.
    pub fn stream_stdin(&mut self) -> Result<serde_json::Value, IpcError> {
        let first = self.request(serde_json::json!({"cmd": "send", "stdin": true}))?;
        if first.get("ok").and_then(|o| o.as_bool()) != Some(true) {
            return Ok(first);
        }
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 64 * 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => self.stream.write_all(&buf[..k]).map_err(IpcError::Io)?,
                Err(e) => return Err(IpcError::Io(e)),
            }
        }
        // half-close so the daemon sees EOF, then read the final reply
        let _ = self.stream.shutdown(std::net::Shutdown::Write);
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Err(IpcError::Protocol("no final reply".into())),
            Ok(_) => serde_json::from_str(line.trim())
                .map_err(|e| IpcError::Protocol(format!("bad reply: {e}"))),
            Err(e) => Err(IpcError::Io(e)),
        }
    }
}

/// Resolve user paths to absolute form for the daemon (different cwd).
pub fn absolutize(p: &str) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|c| c.join(&path))
            .unwrap_or(path)
    }
}
