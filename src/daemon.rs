//! Daemon orchestration.
//!
//! Subsystems are split by responsibility: connection transport, shared state,
//! session/protocol handling, file transfer, clipboard synchronization, and
//! stateless helpers.

mod clipboard_sync;
mod conn;
mod file_transfer;
mod session;
mod state;
mod util;

pub use state::{ClipSend, EchoGuard, PinState, Shared};
pub use util::human_size;

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::clipboard::{self, ClipboardBackend};
use crate::config::Config;
use crate::net;
use crate::proto::Frame;
use crate::queue::OutQueue;
use crate::store;

use self::clipboard_sync::spawn_clipboard_watcher;
use self::session::handle_conn;

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
    if !no_tray && let Err(e) = crate::tray::spawn(shared.clone()) {
        alog!(Warn, "tray: {e} (continuing without)");
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
