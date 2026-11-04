//! Daemon core: TLS listener, session threads (reader/writer/ping/watchdog),
//! inbound file state machine, outbound queue pump, pairing admission.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection};

use crate::clipboard::{self, ClipboardBackend, classify};
use crate::config::Config;
use crate::net::{self, Identity};
use crate::pairing::PairState;
use crate::proto::{self, CAP_FILES, CAP_IMAGE, CAP_TEXT, Frame, FrameError};
use crate::queue::{Item, OutQueue};
use crate::store::{self, PairedDevice};
use crate::transfer::{self, FileChunks, Inbound, SendEntry};

pub struct Conn {
    /// rustls session state. Never held across a blocking socket read: the
    /// feeder thread blocks on the read half and locks this only to feed
    /// records / drain plaintext in short bursts. (The previous single
    /// stream design blocked inside read_frame() while holding the lock,
    /// starving ping/pump/clipboard writers whenever the phone went
    /// silent — protocol.md §6.)
    tls: Mutex<Option<ServerConnection>>,
    /// Read half — locked only by the feeder thread (uncontended; the
    /// blocking read lives inside this lock, which no writer ever wants).
    sock_rd: Mutex<TcpStream>,
    /// Write half — short critical sections; 60 s write timeout set after
    /// the handshake.
    sock_wr: Mutex<TcpStream>,
    /// Original socket, kept for watchdog shutdowns; unblocks the feeder.
    pub tcp: TcpStream,
    pub alive: AtomicBool,
    pub last_read: Mutex<Instant>,
    /// FILE_RESULT answers for our outbound ids: (status, sha256).
    results: Mutex<HashMap<u32, (u8, [u8; 32])>>,
    results_cv: Condvar,
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

    /// Wait for the peer's FILE_RESULT for `id` (reliability anchor, §6).
    pub fn wait_result(&self, id: u32, timeout: Duration) -> Option<(u8, [u8; 32])> {
        let mut r = self.results.lock().unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(v) = r.remove(&id) {
                return Some(v);
            }
            let now = Instant::now();
            if now >= deadline || !self.alive.load(Ordering::Relaxed) {
                return None;
            }
            let (g, _) = self.results_cv.wait_timeout(r, deadline - now).unwrap();
            r = g;
        }
    }

    /// Deposit a FILE_RESULT / cancellation answer for an outbound id.
    pub fn deposit_result(&self, id: u32, v: (u8, [u8; 32])) {
        self.results.lock().unwrap().insert(id, v);
        self.results_cv.notify_all();
    }
}

pub struct SessionHandle {
    pub name: Mutex<String>,
    pub ip: String,
    pub since: Instant,
    pub conn: Arc<Conn>,
}

pub struct EchoGuard {
    seen: HashSet<u64>,
    order: VecDeque<u64>,
}

impl EchoGuard {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }
    pub fn remember(&mut self, h: u64) {
        if self.seen.insert(h) {
            self.order.push_back(h);
            if self.order.len() > 32 {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }
    pub fn contains(&self, h: u64) -> bool {
        self.seen.contains(&h)
    }
}

/// State the TLS cert verifier needs; shared with the daemon via Arc so the
/// ServerConfig can be built before `Shared` exists.
pub struct PinState {
    pub devices: Mutex<Vec<PairedDevice>>,
    pub pair: Mutex<PairState>,
}

impl Default for PinState {
    fn default() -> Self {
        Self {
            devices: Mutex::new(Vec::new()),
            pair: Mutex::new(PairState::closed()),
        }
    }
}

impl PinState {
    pub fn is_paired(&self, fp: &str) -> bool {
        self.devices
            .lock()
            .unwrap()
            .iter()
            .any(|d| d.fingerprint == fp)
    }
    pub fn pair_window_open(&self) -> bool {
        self.pair.lock().unwrap().is_open()
    }
}

pub struct Shared {
    pub cfg: Config,
    pub identity: Identity,
    pub tls: Arc<ServerConfig>,
    pub started: Instant,
    pub pin: Arc<PinState>,
    pub queue: OutQueue,
    pub session: Mutex<Option<Arc<SessionHandle>>>,
    /// Notified whenever the pairing window state changes (IPC waiters).
    pub pair_cond: Condvar,
    pub echo: Mutex<EchoGuard>,
    pub clip: Option<Arc<dyn ClipboardBackend>>,
    pub stop: AtomicBool,
    pump_running: AtomicBool,
    next_id: AtomicU32,
    /// Tray refresh callback, installed by tray.rs (avoids naming ksni's
    /// crate-private Handle type here).
    pub tray: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl Shared {
    pub fn devices(&self) -> MutexGuardDevices<'_> {
        MutexGuardDevices {
            g: self.pin.devices.lock().unwrap(),
        }
    }
    pub fn pair(&self) -> std::sync::MutexGuard<'_, PairState> {
        self.pin.pair.lock().unwrap()
    }
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
    fn next_file_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
    pub fn tray_refresh(&self) {
        if let Some(f) = self.tray.lock().unwrap().as_ref() {
            f();
        }
    }
    /// Desktop notification, best effort (headless systems just log).
    pub fn notify(&self, summary: &str, body: &str) {
        if let Err(e) = notify_rust::Notification::new()
            .appname("Airpipe")
            .summary(summary)
            .body(body)
            .show()
        {
            alog!(Debug, "notification failed: {e}");
        }
    }
    /// Open the pairing window (IPC or tray). Returns the code.
    pub fn open_pair_window(&self, timeout: Duration) -> String {
        let mut p = self.pair();
        *p = PairState::open(timeout);
        let code = p.code.clone().unwrap_or_default();
        drop(p);
        self.pair_cond.notify_all();
        self.tray_refresh();
        code
    }
    /// Read file references from the clipboard as local paths.
    pub fn collect_clip_files(&self) -> Result<Vec<PathBuf>, String> {
        let clip = self.clip.as_ref().ok_or("no clipboard backend")?;
        for mime in ["x-special/gnome-copied-files", "text/uri-list"] {
            if let Ok(Some(bytes)) = clip.read(mime) {
                let (_, uris) = classify::parse_file_refs(mime, &bytes);
                let paths: Vec<PathBuf> = uris.iter().filter_map(|u| uri_to_path(u)).collect();
                if !paths.is_empty() {
                    return Ok(paths);
                }
            }
        }
        Err("剪贴板中没有文件引用".into())
    }
    /// Inbound T/I frame: write the PC clipboard + echo suppression.
    pub fn apply_inbound_clip(&self, mime: &str, data: Vec<u8>, is_image: bool) {
        let h = content_hash(mime, &data);
        self.echo.lock().unwrap().remember(h);
        let Some(clip) = self.clip.as_ref() else {
            alog!(Debug, "no clipboard backend; dropping inbound clip");
            return;
        };
        if let Err(e) = clip.set_selection(mime, data) {
            alog!(Warn, "{e}");
            return;
        }
        alog!(
            Info,
            "phone → clipboard: {} ({mime})",
            if is_image { "image" } else { "text" }
        );
    }
}

/// Small helper so callers can do `shared.devices().iter()` ergonomically.
pub struct MutexGuardDevices<'a> {
    g: std::sync::MutexGuard<'a, Vec<PairedDevice>>,
}
impl std::ops::Deref for MutexGuardDevices<'_> {
    type Target = Vec<PairedDevice>;
    fn deref(&self) -> &Self::Target {
        &self.g
    }
}
impl std::ops::DerefMut for MutexGuardDevices<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.g
    }
}

pub fn content_hash(mime: &str, data: &[u8]) -> u64 {
    let mut hh = DefaultHasher::new();
    mime.hash(&mut hh);
    data.hash(&mut hh);
    hh.finish()
}

/// Percent-encode a filesystem path into a `file://` URI.
pub fn path_to_uri(p: &std::path::Path) -> String {
    let mut s = String::from("file://");
    for &b in p.to_string_lossy().as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                s.push(b as char);
            }
            _ => s.push_str(&format!("%{b:02X}")),
        }
    }
    s
}

/// Decode a `file://` URI to a local path (None for other schemes).
pub fn uri_to_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let b = rest.as_bytes();
    let mut bytes = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok()?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            bytes.push(b[i]);
            i += 1;
        }
    }
    Some(PathBuf::from(String::from_utf8_lossy(&bytes).into_owned()))
}

// ---------------------------------------------------------------- daemon ---

pub fn run(cfg: Config, _verbose: bool, no_tray: bool) -> i32 {
    let name = cfg.device_name();
    let identity = match net::load_or_create_identity(&name) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("ap: {e}");
            return 1;
        }
    };
    let _ = std::fs::create_dir_all(cfg.inbound_dir());
    let _ = std::fs::create_dir_all(crate::config::state_dir().join("out"));

    // single-instance IPC socket first: fail fast if a daemon already runs
    let ipc_listener = match crate::ipc::bind_sock() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ap: {e}");
            return 1;
        }
    };
    let port = cfg.port();
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ap: TCP :{port} bind failed: {e}");
            return 1;
        }
    };

    // clipboard (graceful degradation without a compositor)
    let clip_backend: Option<Arc<dyn ClipboardBackend>> = match clipboard::connect() {
        Ok(b) => {
            alog!(Info, "clipboard: connected");
            Some(Arc::from(b))
        }
        Err(e) => {
            eprintln!("ap: {e} — 剪贴板同步已停用（无 Wayland 合成器？）");
            None
        }
    };

    let pin = Arc::new(PinState::default());
    *pin.devices.lock().unwrap() = store::load_devices().devices;

    let tls = match net::server_config(&identity, pin.clone()) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            eprintln!("ap: {e}");
            return 1;
        }
    };

    let shared = Arc::new(Shared {
        cfg,
        identity,
        tls,
        started: Instant::now(),
        pin: pin.clone(),
        queue: OutQueue::new(),
        session: Mutex::new(None),
        pair_cond: Condvar::new(),
        echo: Mutex::new(EchoGuard::new()),
        clip: clip_backend.clone(),
        stop: AtomicBool::new(false),
        pump_running: AtomicBool::new(false),
        next_id: AtomicU32::new(1),
        tray: Mutex::new(None),
    });

    alog!(
        Info,
        "airpipe daemon: {name} on :{port}, fingerprint {}",
        shared.identity.fingerprint
    );

    crate::ipc::spawn(shared.clone(), ipc_listener);
    crate::discovery::spawn(shared.clone());
    if let Some(clip) = &clip_backend {
        spawn_clipboard_watcher(shared.clone(), clip.clone());
    }
    if !no_tray {
        if let Err(e) = crate::tray::spawn(shared.clone()) {
            alog!(Warn, "tray: {e} (continuing without)");
        }
    }

    // non-blocking accept loop so `stop` is honored promptly
    let _ = listener.set_nonblocking(true);
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }
        match listener.accept() {
            Ok((tcp, addr)) => {
                alog!(Info, "connection from {addr}");
                let shared = shared.clone();
                let _ = std::thread::Builder::new()
                    .name("session".into())
                    .spawn(move || handle_conn(shared, tcp, addr));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => alog!(Warn, "accept: {e}"),
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // graceful stop: BYE the phone, remove the runtime socket
    if let Some(s) = shared.session.lock().unwrap().as_ref() {
        let _ = s.conn.send(&Frame::Bye {
            reason: "daemon stopping".into(),
        });
    }
    let _ = std::fs::remove_file(crate::config::sock_path());
    alog!(Info, "daemon stopped");
    0
}

// --------------------------------------------------------------- sessions ---

fn handle_conn(shared: Arc<Shared>, tcp: TcpStream, addr: SocketAddr) {
    let _ = tcp.set_nodelay(true);
    let ip = addr.ip().to_string();
    let (mut rd, mut wr) = match (tcp.try_clone(), tcp.try_clone()) {
        (Ok(r), Ok(w)) => (r, w),
        _ => {
            alog!(Warn, "tcp clone failed for {ip}");
            return;
        }
    };
    let mut state = match ServerConnection::new(shared.tls.clone()) {
        Ok(c) => c,
        Err(e) => {
            alog!(Warn, "tls setup: {e}");
            return;
        }
    };
    // Bounded manual handshake on the raw halves; the read timeout is
    // cleared right after (a timeout mid-record would corrupt TLS state).
    // Past this point liveness belongs to the application watchdog (§6).
    let _ = rd.set_read_timeout(Some(Duration::from_secs(30)));
    let hs = (|| -> std::io::Result<()> {
        while state.is_handshaking() {
            if state.wants_read() {
                if state.read_tls(&mut rd)? == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer closed during handshake",
                    ));
                }
            }
            state
                .process_new_packets()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            while state.wants_write() {
                state.write_tls(&mut wr)?;
            }
        }
        Ok(())
    })();
    let _ = rd.set_read_timeout(None);
    if let Err(e) = hs {
        let timed_out = matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        );
        if timed_out {
            alog!(Info, "TLS handshake with {ip} timed out");
        } else {
            alog!(Info, "TLS handshake with {ip} failed: {e}");
        }
        return;
    }
    // A stalled peer must not wedge the session forever: writes give up
    // after 60 s and the failed send tears the connection down.
    let _ = wr.set_write_timeout(Some(Duration::from_secs(60)));
    let peer_fp = state
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| net::fingerprint_hex(c.as_ref()))
        .unwrap_or_default();
    alog!(Info, "TLS 1.3 established with {ip}, peer fp {peer_fp}");

    let conn = Arc::new(Conn {
        tls: Mutex::new(Some(state)),
        sock_rd: Mutex::new(rd),
        sock_wr: Mutex::new(wr),
        tcp,
        alive: AtomicBool::new(true),
        last_read: Mutex::new(Instant::now()),
        results: Mutex::new(HashMap::new()),
        results_cv: Condvar::new(),
    });

    if let Err(e) = conn.send(&Frame::Hello {
        ver: proto::PROTO_VER,
        name: shared.cfg.device_name(),
        caps: CAP_TEXT | CAP_IMAGE | CAP_FILES,
    }) {
        alog!(Warn, "send HELLO: {e}");
        return;
    }

    spawn_ping(conn.clone());
    spawn_watchdog(conn.clone());

    let res = reader_loop(&shared, &conn, &ip, &peer_fp);

    conn.alive.store(false, Ordering::Relaxed);
    conn.close();
    let was_session = shared
        .session
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| Arc::ptr_eq(&s.conn, &conn))
        .unwrap_or(false);
    if was_session {
        *shared.session.lock().unwrap() = None;
        alog!(Info, "phone disconnected");
        shared.tray_refresh();
    }
    if let Err(e) = res {
        alog!(Info, "session with {ip} ended: {e}");
    }
}

fn reader_loop(
    shared: &Arc<Shared>,
    conn: &Arc<Conn>,
    ip: &str,
    peer_fp: &str,
) -> Result<(), FrameError> {
    let mut inbound: HashMap<u32, Inbound> = HashMap::new();

    // Feeder thread: owns the blocking socket read and the TLS record
    // plumbing, handing complete frames over a channel. Blocking reads no
    // longer hold any session lock, so ping/pump/clipboard writers stay
    // live while the phone is silent — replacing the deadlock where a
    // silent peer starved every writer for the duration of one read (§6).
    let (tx, rx) = std::sync::mpsc::channel::<Frame>();
    {
        let conn = Arc::clone(conn);
        let _ = std::thread::Builder::new()
            .name("feeder".into())
            .spawn(move || {
                let mut plain: Vec<u8> = Vec::new();
                let res = (|| -> Result<(), FrameError> {
                    loop {
                        conn.read_into(&mut plain)?;
                        while let Some(f) = proto::take_frame(&mut plain) {
                            if tx.send(f?).is_err() {
                                return Ok(()); // dispatch side went away
                            }
                        }
                    }
                })();
                match res {
                    Ok(()) | Err(FrameError::Eof) => alog!(Debug, "feeder: session over"),
                    Err(e) => alog!(Info, "feeder: {e}"),
                }
                conn.close();
            });
    }

    loop {
        if shared.stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let frame = match rx.recv() {
            Ok(f) => f,
            Err(_) => return Ok(()), // feeder ended: EOF, error or shutdown
        };
        match frame {
            Frame::Hello { ver, name, caps } => {
                if ver != proto::PROTO_VER {
                    let _ = conn.send(&Frame::Bye {
                        reason: "version mismatch".into(),
                    });
                    return Err(FrameError::Malformed("peer version mismatch"));
                }
                alog!(Info, "HELLO from {name} (caps {caps:#x})");
                let fresh = shared
                    .session
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|s| !Arc::ptr_eq(&s.conn, conn))
                    .unwrap_or(true);
                if fresh {
                    *shared.session.lock().unwrap() = Some(Arc::new(SessionHandle {
                        name: Mutex::new(name.clone()),
                        ip: ip.to_owned(),
                        since: Instant::now(),
                        conn: conn.clone(),
                    }));
                    touch_device(shared, peer_fp, &name, ip);
                    shared.tray_refresh();
                    spawn_pump_if_idle(shared.clone(), conn.clone());
                }
            }
            Frame::Ping => conn.send(&Frame::Pong)?,
            Frame::Pong => {}
            Frame::ClipText { mime, data } => {
                if data.len() > proto::MAX_TEXT {
                    let _ = conn.send(&Frame::Bye {
                        reason: "clip text too large".into(),
                    });
                    return Err(FrameError::Malformed("clip text too large"));
                }
                shared.apply_inbound_clip(&mime, data, false);
            }
            Frame::ClipImage { mime, data } => {
                if data.len() > proto::MAX_IMAGE {
                    let _ = conn.send(&Frame::Bye {
                        reason: "clip image too large".into(),
                    });
                    return Err(FrameError::Malformed("clip image too large"));
                }
                shared.apply_inbound_clip(&mime, data, true);
            }
            Frame::FileBegin {
                id,
                flags,
                rel_path,
                ..
            } => {
                let rel = transfer::sanitize_rel(&rel_path);
                if rel.is_empty() {
                    alog!(Warn, "B id {id}: unusable relPath {rel_path:?}, rejected");
                    conn.send(&Frame::FileResult {
                        id,
                        status: 2,
                        sha256: [0; 32],
                    })?;
                    continue;
                }
                let root = shared.cfg.inbound_dir();
                let target = transfer::unique_path(
                    &transfer::resolve_under(&root, &rel).unwrap_or_else(|_| root.join("file")),
                );
                if flags & proto::BF_DIR != 0 {
                    if let Err(e) = std::fs::create_dir_all(&target) {
                        alog!(Warn, "mkdir {}: {e}", target.display());
                        conn.send(&Frame::FileResult {
                            id,
                            status: 2,
                            sha256: [0; 32],
                        })?;
                        continue;
                    }
                    alog!(Info, "dir  {}", target.display());
                } else {
                    match Inbound::new_file(target) {
                        Ok(ib) => {
                            alog!(Info, "recv {}", ib.final_path.display());
                            inbound.insert(id, ib);
                        }
                        Err(e) => {
                            alog!(Warn, "create part file: {e}");
                            conn.send(&Frame::FileResult {
                                id,
                                status: 2,
                                sha256: [0; 32],
                            })?;
                        }
                    }
                }
            }
            Frame::FileData { id, data } => {
                if let Some(ib) = inbound.get_mut(&id) {
                    match ib.data(&data) {
                        Ok(Some(bytes)) => {
                            conn.send(&Frame::FileProgress { id, bytes })?;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            alog!(Warn, "write {}: {e}", ib.final_path.display());
                            ib.abort();
                            inbound.remove(&id);
                            conn.send(&Frame::Cancel { id })?;
                            conn.send(&Frame::FileResult {
                                id,
                                status: 2,
                                sha256: [0; 32],
                            })?;
                        }
                    }
                }
            }
            Frame::FileEnd { id } => {
                if let Some(mut ib) = inbound.remove(&id) {
                    match ib.finish() {
                        Ok(sha) => {
                            let size = ib.received;
                            let path = ib.final_path.clone();
                            conn.send(&Frame::FileResult {
                                id,
                                status: 0,
                                sha256: sha,
                            })?;
                            let fname = path
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            alog!(Info, "done {fname} ({})", human_size(size));
                            shared.notify(
                                "Airpipe 收到文件",
                                &format!("{fname} ({})", human_size(size)),
                            );
                            write_received_files_clip(shared, &[path]);
                        }
                        Err(e) => {
                            alog!(Warn, "finalize: {e}");
                            ib.abort();
                            conn.send(&Frame::FileResult {
                                id,
                                status: 2,
                                sha256: [0; 32],
                            })?;
                        }
                    }
                }
            }
            Frame::FileProgress { id, bytes } => {
                alog!(Debug, "progress id {id}: {bytes} bytes acked");
            }
            Frame::FileResult { id, status, sha256 } => {
                // answer for one of OUR outbound transfers
                conn.deposit_result(id, (status, sha256));
            }
            Frame::Cancel { id } => {
                if let Some(mut ib) = inbound.remove(&id) {
                    ib.abort();
                }
                conn.deposit_result(id, (3, [0; 32]));
            }
            Frame::PairRequest { code, name } => {
                if !handle_pair_request(shared, conn, peer_fp, ip, &code, &name)? {
                    return Ok(()); // pairing failed, connection closed
                }
            }
            Frame::PairAccept { .. } => {}
            Frame::Bye { reason } => {
                alog!(Info, "peer BYE: {reason}");
                return Ok(());
            }
        }
    }
}

/// Returns Ok(true) to continue the session, Ok(false) if it must end.
fn handle_pair_request(
    shared: &Arc<Shared>,
    conn: &Arc<Conn>,
    peer_fp: &str,
    ip: &str,
    code: &str,
    name: &str,
) -> Result<bool, FrameError> {
    let ok = shared.pair().check(code);
    if !ok {
        alog!(Warn, "pairing attempt from {ip} failed");
        conn.send(&Frame::Bye {
            reason: "pairing failed".into(),
        })?;
        shared.pair_cond.notify_all();
        return Ok(false);
    }
    {
        let mut p = shared.pair();
        p.code = None; // window consumed by success
        p.paired_name = Some(name.to_owned());
    }
    let ts = store::now_ts();
    {
        let mut devs = shared.devices();
        devs.retain(|d| d.fingerprint != peer_fp);
        devs.push(PairedDevice {
            name: name.to_owned(),
            fingerprint: peer_fp.to_owned(),
            paired_at: ts.clone(),
            last_ip: Some(ip.to_owned()),
            last_seen: Some(ts),
        });
        if let Err(e) = store::save_devices(&store::DeviceList {
            devices: devs.to_vec(),
        }) {
            alog!(Warn, "save paired.json: {e}");
        }
    }
    conn.send(&Frame::PairAccept {
        name: shared.cfg.device_name(),
    })?;
    alog!(Info, "paired with {name} ({peer_fp})");
    shared.notify("Airpipe 配对成功", name);
    shared.pair_cond.notify_all();
    // the connection continues as a normal session; expect HELLO next
    *shared.session.lock().unwrap() = Some(Arc::new(SessionHandle {
        name: Mutex::new(name.to_owned()),
        ip: ip.to_owned(),
        since: Instant::now(),
        conn: conn.clone(),
    }));
    shared.tray_refresh();
    spawn_pump_if_idle(shared.clone(), conn.clone());
    Ok(true)
}

fn touch_device(shared: &Arc<Shared>, fp: &str, name: &str, ip: &str) {
    let ts = store::now_ts();
    let mut devs = shared.devices();
    if let Some(d) = devs.iter_mut().find(|d| d.fingerprint == fp) {
        d.last_seen = Some(ts);
        d.last_ip = Some(ip.to_owned());
        d.name = name.to_owned();
    }
    let _ = store::save_devices(&store::DeviceList {
        devices: devs.to_vec(),
    });
}

/// After a completed inbound file, put a file-manager-pasteable reference on
/// the clipboard (x-special/gnome-copied-files, first line "copy").
fn write_received_files_clip(shared: &Arc<Shared>, paths: &[PathBuf]) {
    let Some(clip) = shared.clip.as_ref() else {
        return;
    };
    let mut payload = String::from("copy\n");
    for p in paths {
        payload.push_str(&path_to_uri(p));
        payload.push('\n');
    }
    let h = content_hash("x-special/gnome-copied-files", payload.as_bytes());
    shared.echo.lock().unwrap().remember(h);
    if let Err(e) = clip.set_selection("x-special/gnome-copied-files", payload.into_bytes()) {
        alog!(Warn, "{e}");
    }
}

fn spawn_ping(conn: Arc<Conn>) {
    std::thread::Builder::new()
        .name("ping".into())
        .spawn(move || {
            loop {
                for _ in 0..proto::PING_EVERY.as_secs() {
                    if !conn.alive.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                if !conn.alive.load(Ordering::Relaxed) {
                    return;
                }
                if conn.send(&Frame::Ping).is_err() {
                    return;
                }
            }
        })
        .ok();
}

fn spawn_watchdog(conn: Arc<Conn>) {
    std::thread::Builder::new()
        .name("watchdog".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                if !conn.alive.load(Ordering::Relaxed) {
                    return;
                }
                let idle = conn.last_read.lock().unwrap().elapsed();
                if idle > proto::SILENCE_DEAD {
                    alog!(Warn, "peer silent for {idle:?}, dropping link");
                    // shutdown() unblocks the reader thread's read_exact
                    let _ = conn.tcp.shutdown(Shutdown::Both);
                    return;
                }
            }
        })
        .ok();
}

// ------------------------------------------------------------------ pump ---

fn spawn_pump_if_idle(shared: Arc<Shared>, conn: Arc<Conn>) {
    if shared.pump_running.swap(true, Ordering::SeqCst) {
        return; // already pumping
    }
    let _ = std::thread::Builder::new()
        .name("pump".into())
        .spawn(move || {
            pump(&shared, &conn);
            shared.pump_running.store(false, Ordering::SeqCst);
            // the queue may have grown while we were finishing
            if !shared.queue.is_empty() && conn.alive.load(Ordering::Relaxed) {
                shared.pump_running.store(true, Ordering::SeqCst);
                pump(&shared, &conn);
                shared.pump_running.store(false, Ordering::SeqCst);
            }
        });
}

fn pump(shared: &Arc<Shared>, conn: &Arc<Conn>) {
    loop {
        let items = shared.queue.drain();
        if items.is_empty() {
            return;
        }
        let mut failed: Vec<Item> = Vec::new();
        for item in items {
            if !conn.alive.load(Ordering::Relaxed) {
                failed.push(item);
                break;
            }
            match &item {
                Item::Clip { image, mime, data } => {
                    let f = if *image {
                        Frame::ClipImage {
                            mime: mime.clone(),
                            data: data.clone(),
                        }
                    } else {
                        Frame::ClipText {
                            mime: mime.clone(),
                            data: data.clone(),
                        }
                    };
                    if let Err(e) = conn.send(&f) {
                        alog!(Warn, "pump clip: {e}");
                        failed.push(item);
                        break;
                    }
                }
                Item::Files(paths) => {
                    if let Err(remain) = send_paths(shared, conn, paths) {
                        failed.push(Item::Files(remain));
                        break;
                    }
                }
            }
        }
        if !failed.is_empty() {
            shared.queue.requeue_front(failed);
            return;
        }
    }
}

/// Send files/dirs sequentially; on failure returns the paths not yet sent.
fn send_paths(
    shared: &Arc<Shared>,
    conn: &Arc<Conn>,
    paths: &[PathBuf],
) -> Result<(), Vec<PathBuf>> {
    for p in paths {
        if let Err(e) = std::fs::metadata(p) {
            alog!(Warn, "send: {} unavailable: {e}", p.display());
            return Err(paths.to_vec());
        }
    }
    let entries = match transfer::plan(paths) {
        Ok(e) => e,
        Err(e) => {
            alog!(Warn, "plan: {e}");
            return Err(paths.to_vec());
        }
    };
    let mut sent_tops: HashSet<PathBuf> = HashSet::new();
    for entry in &entries {
        let failed = match entry {
            SendEntry::Dir { rel } => {
                let id = shared.next_file_id();
                conn.send(&Frame::FileBegin {
                    id,
                    flags: proto::BF_DIR,
                    rel_path: rel.clone(),
                    size: 0,
                })
                .is_err()
            }
            SendEntry::File { abs, rel, size } => {
                let stdin_src = abs.starts_with(crate::config::state_dir().join("out"));
                let r = send_one_file(shared, conn, abs, rel.clone(), *size, stdin_src);
                if let Err(e) = &r {
                    alog!(Warn, "send {}: {e}", abs.display());
                }
                r.is_err()
            }
        };
        if failed {
            let remaining: Vec<PathBuf> = paths
                .iter()
                .filter(|p| !sent_tops.contains(*p))
                .cloned()
                .collect();
            return Err(remaining);
        }
        if let SendEntry::File { abs, .. } = entry {
            sent_tops.insert(top_of(paths, abs));
        }
    }
    Ok(())
}

fn top_of(paths: &[PathBuf], abs: &PathBuf) -> PathBuf {
    for p in paths {
        if abs.starts_with(p) {
            return p.clone();
        }
    }
    abs.clone()
}

/// Stream one file; on sha256 mismatch resend once, then report (§6).
fn send_one_file(
    shared: &Arc<Shared>,
    conn: &Arc<Conn>,
    abs: &PathBuf,
    rel: String,
    size: u64,
    stdin_src: bool,
) -> Result<(), String> {
    // stdin-sourced sends keep the contract's "size unknown" flag
    let (flags, size) = if stdin_src {
        (proto::BF_SIZE_UNKNOWN, 0)
    } else {
        (0, size)
    };
    for attempt in 0..2 {
        let id = shared.next_file_id();
        let mut fc = FileChunks::open(abs).map_err(|e| e.to_string())?;
        conn.send(&Frame::FileBegin {
            id,
            flags,
            rel_path: rel.clone(),
            size,
        })
        .map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        while let Some(chunk) = fc.next(&mut buf).map_err(|e| e.to_string())? {
            conn.send(&Frame::FileData {
                id,
                data: chunk.to_vec(),
            })
            .map_err(|e| e.to_string())?;
        }
        conn.send(&Frame::FileEnd { id })
            .map_err(|e| e.to_string())?;
        let expect = fc.digest();
        match conn.wait_result(id, Duration::from_secs(600)) {
            Some((0, got)) if got == expect => {
                alog!(Info, "sent {} ({})", rel, human_size(size));
                // stdin temporaries are removed after verified delivery
                if abs.starts_with(crate::config::state_dir().join("out")) {
                    let _ = std::fs::remove_file(abs);
                }
                return Ok(());
            }
            Some((0, got)) => {
                alog!(
                    Warn,
                    "sha mismatch for {rel} (attempt {}): {}",
                    attempt + 1,
                    net::hex(&got)
                );
                continue; // resend once
            }
            Some((status, _)) => return Err(format!("receiver reported status {status}")),
            None => return Err("no FILE_RESULT (link died or timed out)".into()),
        }
    }
    Err("sha256 mismatch after retry".into())
}

pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

// ---------------------------------------------------- clipboard watcher ---

fn spawn_clipboard_watcher(shared: Arc<Shared>, clip: Arc<dyn ClipboardBackend>) {
    // The lamco callback runs on the crate's internal Wayland thread and
    // must not block (read() round-trips through that same thread), so the
    // actual read moves to a fresh thread, exactly like the probe.
    clip.on_change(Box::new(move |mimes| {
        let shared = shared.clone();
        std::thread::spawn(move || on_selection(&shared, mimes));
    }));
}

fn on_selection(shared: &Arc<Shared>, mimes: Vec<String>) {
    if mimes.is_empty() {
        return;
    }
    let kind = classify::classify(&mimes);
    let clip = match shared.clip.as_ref() {
        Some(c) => c,
        None => return,
    };
    let cc = &shared.cfg.clipboard;
    match kind {
        classify::SelectionKind::Sensitive => {
            alog!(
                Info,
                "clipboard: sensitive (password-manager hint), skipped"
            );
        }
        classify::SelectionKind::Files { .. } => {
            alog!(
                Debug,
                "clipboard: file refs, not auto-synced (use tray/IPC)"
            );
        }
        classify::SelectionKind::Image { mime } => {
            if !cc.auto_image {
                return;
            }
            let Ok(Some(bytes)) = clip.read(&mime) else {
                return;
            };
            let cap = (cc.max_image_mb * 1024 * 1024).min(proto::MAX_IMAGE as u64) as usize;
            if bytes.len() > cap {
                alog!(
                    Info,
                    "clipboard image {} > {} MiB cap, skipped",
                    human_size(bytes.len() as u64),
                    cc.max_image_mb
                );
                return;
            }
            if shared
                .echo
                .lock()
                .unwrap()
                .contains(content_hash(&mime, &bytes))
            {
                return;
            }
            alog!(
                Info,
                "clipboard → queue: image {mime} ({})",
                human_size(bytes.len() as u64)
            );
            shared.queue.push_clip(true, mime, bytes);
        }
        classify::SelectionKind::RichText { plain, .. } => {
            if !cc.auto_text {
                return;
            }
            let Some(mime) = plain else { return };
            let Ok(Some(bytes)) = clip.read(&mime) else {
                return;
            };
            if shared
                .echo
                .lock()
                .unwrap()
                .contains(content_hash(&mime, &bytes))
            {
                return;
            }
            shared.queue.push_clip(false, mime, bytes);
        }
        classify::SelectionKind::PlainText { mime } => {
            if !cc.auto_text {
                return;
            }
            let Ok(Some(bytes)) = clip.read(&mime) else {
                return;
            };
            if shared
                .echo
                .lock()
                .unwrap()
                .contains(content_hash(&mime, &bytes))
            {
                return;
            }
            shared.queue.push_clip(false, mime, bytes);
        }
        classify::SelectionKind::Passthrough { mimes } => {
            if !cc.auto_text {
                return;
            }
            if let Some(tm) = mimes.iter().find(|m| m.starts_with("text/")) {
                if let Ok(Some(bytes)) = clip.read(tm) {
                    if !shared
                        .echo
                        .lock()
                        .unwrap()
                        .contains(content_hash(tm, &bytes))
                    {
                        shared.queue.push_clip(false, tm.clone(), bytes);
                        return;
                    }
                }
            }
            alog!(
                Info,
                "clipboard: no syncable rendition among {mimes:?}, skipped"
            );
        }
    }
}
