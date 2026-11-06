//! Outbound queue pump and windowed file transfer implementation.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::net;
use crate::proto::{self, Frame};
use crate::queue::Item;
use crate::transfer::{self, FileChunks, SendEntry};

use super::conn::Conn;
use super::state::Shared;
use super::util::human_size;

pub(super) fn spawn_pump_if_idle(shared: Arc<Shared>, conn: Arc<Conn>) {
    if shared.pump_running.swap(true, Ordering::SeqCst) {
        return; // already pumping
    }
    let _ = std::thread::Builder::new()
        .name("pump".into())
        .spawn(move || {
            pump(&shared, &conn);
            shared.pump_running.store(false, Ordering::SeqCst);
            // The session may have been replaced while we pumped; hand the
            // queue over to the current session's pump if items are waiting.
            if !shared.queue.is_empty() {
                let cur = {
                    let g = shared.session.lock().unwrap();
                    g.as_ref().map(|s| s.conn.clone())
                };
                if let Some(cur_conn) = cur
                    && !Arc::ptr_eq(&cur_conn, &conn)
                    && cur_conn.alive.load(Ordering::Relaxed)
                {
                    spawn_pump_if_idle(shared, cur_conn);
                }
            }
        });
}

fn pump(shared: &Arc<Shared>, conn: &Arc<Conn>) {
    loop {
        if !conn.alive.load(Ordering::Relaxed) {
            return;
        }
        let items = shared.queue.drain();
        if items.is_empty() {
            // Idle: sleep until new items arrive (pushed queues notify) or
            // the connection dies — the 1 s bound makes the alive check
            // timely without a dedicated wake on disconnect.
            shared
                .queue
                .wait_until(Instant::now() + Duration::from_secs(1));
            continue;
        }
        let mut it = items.into_iter();
        let mut failed: Vec<Item> = Vec::new();
        while let Some(item) = it.next() {
            if !conn.alive.load(Ordering::Relaxed) {
                // Link gone: this item and every drained-but-unprocessed
                // one behind it go back to the queue (a bare `break` here
                // used to silently drop the rest of the batch).
                failed.push(item);
                failed.extend(it);
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
                        failed.extend(it);
                        break;
                    }
                }
                Item::Files(paths) => {
                    if let Err(remain) = send_paths(shared, conn, paths) {
                        failed.push(Item::Files(remain));
                        failed.extend(it);
                        break;
                    }
                }
            }
        }
        if !failed.is_empty() {
            shared.queue.requeue_front(failed);
            // A failed send usually means the link is gone; back off and
            // let the alive check end us once reader_loop notices.
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

/// Per-file wait for FILE_RESULT before giving up on it (§6).
const RESULT_WAIT: Duration = Duration::from_secs(600);

/// One outbound transfer whose E frame is on the wire, F still pending.
struct Inflight {
    id: u32,
    rel: String,
    abs: PathBuf,
    size: u64,
    expect: [u8; 32],
    attempt: u32,
    expires: Instant,
    stdin_src: bool,
}

/// Send files/dirs with a window of in-flight files (§6): B/D/E for up to
/// `window` files go out before the first FILE_RESULT is awaited, so the
/// per-file RTT+finalize gap stops serializing (transfer-perf.md §4).
/// On failure returns the top-level paths not yet delivered.
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
    let window = shared.cfg.transfer.window();
    let mode = shared.cfg.transfer.comp_mode();
    let mut sent_tops: HashSet<PathBuf> = HashSet::new();
    let remaining = |sent: &HashSet<PathBuf>| -> Vec<PathBuf> {
        paths
            .iter()
            .filter(|p| !sent.contains(*p))
            .cloned()
            .collect()
    };
    let mut entries = entries.into_iter().peekable();
    let mut inflight: Vec<Inflight> = Vec::new();
    loop {
        // Dispatch dirs inline (no result expected) and files until the
        // window is full.
        while inflight.len() < window {
            match entries.next() {
                Some(SendEntry::Dir { rel }) => {
                    let id = shared.next_file_id();
                    if conn
                        .send(&Frame::FileBegin {
                            id,
                            flags: proto::BF_DIR,
                            rel_path: rel,
                            size: 0,
                        })
                        .is_err()
                    {
                        return Err(remaining(&sent_tops));
                    }
                }
                Some(SendEntry::File { abs, rel, size }) => {
                    let stdin_src = abs.starts_with(crate::config::state_dir().join("out"));
                    let id = shared.next_file_id();
                    match start_file(conn, &abs, &rel, size, stdin_src, id, mode) {
                        Ok(info) => inflight.push(info),
                        Err(e) => {
                            alog!(Warn, "send {}: {e}", abs.display());
                            return Err(remaining(&sent_tops));
                        }
                    }
                }
                None => break,
            }
        }
        if inflight.is_empty() {
            return Ok(()); // everything dispatched and answered
        }
        // Wait for any FILE_RESULT, bounded by the earliest deadline.
        let earliest = inflight.iter().map(|i| i.expires).min().unwrap();
        if Instant::now() >= earliest {
            alog!(Warn, "FILE_RESULT wait timed out");
            return Err(remaining(&sent_tops));
        }
        let Some((id, (status, sha))) = conn.wait_any_result(earliest) else {
            if !conn.alive.load(Ordering::Relaxed) {
                alog!(Warn, "link lost, {} file(s) in flight", inflight.len());
            } else {
                alog!(Warn, "FILE_RESULT wait timed out");
            }
            return Err(remaining(&sent_tops));
        };
        let Some(pos) = inflight.iter().position(|i| i.id == id) else {
            continue; // answer for an already-retried/abandoned id
        };
        let info = inflight.remove(pos);
        if status == 0 && sha == info.expect {
            alog!(Info, "sent {} ({})", info.rel, human_size(info.size));
            // stdin temporaries are removed after verified delivery
            if info.stdin_src {
                let _ = std::fs::remove_file(&info.abs);
            }
            sent_tops.insert(top_of(paths, &info.abs));
        } else if status == 0 && info.attempt == 0 {
            // sha mismatch: resend once with a fresh id (§6)
            alog!(
                Warn,
                "sha mismatch for {} (attempt 1): {}",
                info.rel,
                net::hex(&sha)
            );
            let id = shared.next_file_id();
            match start_file(
                conn,
                &info.abs,
                &info.rel,
                info.size,
                info.stdin_src,
                id,
                mode,
            ) {
                Ok(mut again) => {
                    again.attempt = 1;
                    inflight.push(again);
                }
                Err(e) => {
                    alog!(Warn, "resend {}: {e}", info.abs.display());
                    return Err(remaining(&sent_tops));
                }
            }
        } else {
            alog!(Warn, "transfer of {} failed (status {status})", info.rel);
            return Err(remaining(&sent_tops));
        }
    }
}

fn top_of(paths: &[PathBuf], abs: &Path) -> PathBuf {
    for p in paths {
        if abs.starts_with(p) {
            return p.clone();
        }
    }
    abs.to_path_buf()
}

/// Stream one file's B/D/E frames without waiting for FILE_RESULT —
/// the windowed caller matches the eventual F against `expect`.
/// Chunk bodies are zstd-compressed per chunk when `mode` says so and the
/// chunk actually shrinks (raw fallback is a borrow, no copy).
fn start_file(
    conn: &Arc<Conn>,
    abs: &Path,
    rel: &str,
    size: u64,
    stdin_src: bool,
    id: u32,
    mode: transfer::CompMode,
) -> Result<Inflight, String> {
    // stdin-sourced sends keep the contract's "size unknown" flag
    let (flags, size) = if stdin_src {
        (proto::BF_SIZE_UNKNOWN, 0)
    } else {
        (0, size)
    };
    let mut fc = FileChunks::open(abs).map_err(|e| e.to_string())?;
    conn.send(&Frame::FileBegin {
        id,
        flags,
        rel_path: rel.to_owned(),
        size,
    })
    .map_err(|e| e.to_string())?;
    let mut enc = transfer::ChunkEncoder::new(transfer::should_compress(rel, mode));
    let mut raw = Vec::new();
    let mut zbuf = Vec::new();
    while let Some(chunk) = fc.next(&mut raw).map_err(|e| e.to_string())? {
        let (z, wire) = enc.encode(chunk, &mut zbuf);
        conn.send(&Frame::FileData {
            id,
            zstd: z,
            data: wire.to_vec(),
        })
        .map_err(|e| e.to_string())?;
    }
    conn.send(&Frame::FileEnd { id })
        .map_err(|e| e.to_string())?;
    Ok(Inflight {
        id,
        rel: rel.to_owned(),
        abs: abs.to_path_buf(),
        size,
        expect: fc.digest(),
        attempt: 0,
        expires: Instant::now() + RESULT_WAIT,
        stdin_src,
    })
}
