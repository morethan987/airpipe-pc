//! TLS/TCP connection primitives.

use std::collections::HashMap;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use rustls::ServerConnection;

use crate::proto::{Frame, FrameError};

pub struct Conn {
    /// rustls session state. Never held across a blocking socket read: the
    /// feeder thread blocks on the read half and locks this only to feed
    /// records / drain plaintext in short bursts. (The previous single
    /// stream design blocked inside read_frame() while holding the lock,
    /// starving ping/pump/clipboard writers whenever the phone went
    /// silent — protocol.md §6.)
    pub(super) tls: Mutex<Option<ServerConnection>>,
    /// Read half — locked only by the feeder thread (uncontended; the
    /// blocking read lives inside this lock, which no writer ever wants).
    pub(super) sock_rd: Mutex<TcpStream>,
    /// Write half — short critical sections; 60 s write timeout set after
    /// the handshake.
    pub(super) sock_wr: Mutex<TcpStream>,
    /// Original socket, kept for watchdog shutdowns; unblocks the feeder.
    pub(super) tcp: TcpStream,
    pub(super) alive: AtomicBool,
    pub(super) last_read: Mutex<Instant>,
    /// FILE_RESULT answers for our outbound ids: (status, sha256).
    pub(super) results: Mutex<HashMap<u32, (u8, [u8; 32])>>,
    pub(super) results_cv: Condvar,
}

impl Conn {
    pub fn send(&self, f: &Frame) -> std::io::Result<()> {
        let bytes = f.encode();
        let res = self.send_locked(&bytes);
        if res.is_err() {
            // A failed write may have flushed a partial TLS record: the
            // stream is untrustworthy from here on. Tear the link down.
            self.close();
        }
        res
    }

    fn send_locked(&self, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let mut tls = self.tls.lock().unwrap();
        let Some(c) = tls.as_mut() else {
            return Err(std::io::Error::other("connection closed"));
        };
        // rustls caps its outgoing record buffer: Writer::write accepts only
        // what fits and returns Ok(0) beyond that (write_all would abort with
        // WriteZero mid-frame). So: queue a slice, flush complete records to
        // the socket, repeat until the whole frame is on the wire.
        let mut off = 0;
        let mut stalled = 0;
        while off < bytes.len() {
            let mut wr = self.sock_wr.lock().unwrap();
            let n = c.writer().write(&bytes[off..])?;
            while c.wants_write() {
                c.write_tls(&mut *wr)?;
            }
            drop(wr);
            off += n;
            if n == 0 {
                stalled += 1;
                if stalled > 3 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "tls send buffer not draining",
                    ));
                }
            } else {
                stalled = 0;
            }
        }
        Ok(())
    }

    /// Blocking read on the socket read half + TLS record processing; the
    /// decrypted plaintext is appended to `plain`. No conn lock is held
    /// while blocked on the socket, so writers stay live while the peer is
    /// silent.
    pub fn read_into(&self, plain: &mut Vec<u8>) -> Result<(), FrameError> {
        use std::io::Read;
        let mut raw = [0u8; 16 * 1024];
        let n = self.sock_rd.lock().unwrap().read(&mut raw)?;
        if n == 0 {
            return Err(FrameError::Eof);
        }
        *self.last_read.lock().unwrap() = Instant::now();
        let mut tls = self.tls.lock().unwrap();
        let Some(c) = tls.as_mut() else {
            return Err(FrameError::Eof);
        };
        // Feed record by record, running process_new_packets after each:
        // rustls's deframer caps its raw buffer at one record's wire size
        // ("message buffer full" beyond that), and received_plaintext caps
        // at 16 KiB — both drained by interleaving here.
        let mut rd: &[u8] = &raw[..n];
        let mut tmp = [0u8; 16 * 1024];
        while !rd.is_empty() {
            if c.read_tls(&mut rd)? == 0 {
                break;
            }
            c.process_new_packets()
                .map_err(|e| FrameError::Io(std::io::Error::other(e.to_string())))?;
            loop {
                match c.reader().read(&mut tmp) {
                    Ok(0) => break,
                    Ok(k) => plain.extend_from_slice(&tmp[..k]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(FrameError::Io(e)),
                }
            }
        }
        if c.wants_write() {
            let mut wr = self.sock_wr.lock().unwrap();
            while c.wants_write() {
                c.write_tls(&mut *wr)?;
            }
        }
        // EOF detection: after close_notify/FIN the next raw read returns 0,
        // which the feeder surfaces as FrameError::Eof.
        Ok(())
    }

    pub fn close(&self) {
        {
            let mut tls = self.tls.lock().unwrap();
            if let Some(c) = tls.as_mut() {
                c.send_close_notify();
                if let Ok(mut wr) = self.sock_wr.lock() {
                    while c.wants_write() {
                        if c.write_tls(&mut *wr).is_err() {
                            break;
                        }
                    }
                }
            }
            *tls = None;
        }
        let _ = self.tcp.shutdown(Shutdown::Both);
    }

    /// Wait for any pending FILE_RESULT (windowed sends, protocol §6):
    /// returns the answered id with its result, or None on deadline or
    /// link death. `wait_result` semantics, but for any outstanding id.
    pub fn wait_any_result(&self, deadline: Instant) -> Option<(u32, (u8, [u8; 32]))> {
        let mut r = self.results.lock().unwrap();
        loop {
            if let Some(k) = r.keys().next().copied() {
                return Some((k, r.remove(&k).unwrap()));
            }
            let now = Instant::now();
            if now >= deadline || !self.alive.load(Ordering::Relaxed) {
                return None;
            }
            let slice = (deadline - now).min(Duration::from_secs(1));
            let (g, _) = self.results_cv.wait_timeout(r, slice).unwrap();
            r = g;
        }
    }

    /// Deposit a FILE_RESULT / cancellation answer for an outbound id.
    pub fn deposit_result(&self, id: u32, v: (u8, [u8; 32])) {
        self.results.lock().unwrap().insert(id, v);
        self.results_cv.notify_all();
    }
}
