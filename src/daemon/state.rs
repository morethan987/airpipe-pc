//! Shared daemon state and session metadata.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rustls::ServerConfig;

use crate::clipboard::{ClipboardBackend, classify};
use crate::config::Config;
use crate::net::Identity;
use crate::pairing::PairState;
use crate::queue::OutQueue;
use crate::store::PairedDevice;

use super::conn::Conn;
use super::util::{content_hash, uri_to_path};

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
    pub(super) fn new() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }
    pub fn remember(&mut self, h: u64) {
        if self.seen.insert(h) {
            self.order.push_back(h);
            if self.order.len() > 32
                && let Some(old) = self.order.pop_front()
            {
                self.seen.remove(&old);
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
    pub(super) pump_running: AtomicBool,
    pub(super) next_id: AtomicU32,
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
    /// True when a phone session exists and its link is still alive —
    /// used by IPC replies so the CLI can hint accurately.
    pub fn phone_online(&self) -> bool {
        self.session
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|s| s.conn.alive.load(Ordering::Relaxed))
    }
    pub(super) fn next_file_id(&self) -> u32 {
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
        Err("No file references found in clipboard".into())
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
