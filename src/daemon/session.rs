//! TCP admission, TLS handshake, session dispatch, and pairing.

use std::collections::HashMap;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustls::ServerConnection;
use std::sync::{Condvar, Mutex};

use crate::net;
use crate::proto::{self, CAP_FILES, CAP_IMAGE, CAP_TEXT, Frame, FrameError};
use crate::store::{self, PairedDevice};
use crate::transfer::{self, Inbound};

use super::conn::Conn;
use super::file_transfer::spawn_pump_if_idle;
use super::state::{SessionHandle, Shared};
use super::util::{content_hash, human_size, path_to_uri};

pub(super) fn handle_conn(shared: Arc<Shared>, tcp: TcpStream, addr: SocketAddr) {
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
            if state.wants_read() && state.read_tls(&mut rd)? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed during handshake",
                ));
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
    let mut zdec = transfer::ChunkDecoder::new();

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
            Frame::FileData { id, zstd, data } => {
                if let Some(ib) = inbound.get_mut(&id) {
                    let plain: &[u8] = if zstd {
                        match zdec.decode(&data) {
                            Ok(p) => p,
                            Err(e) => {
                                alog!(Warn, "zstd decode id {id}: {e}");
                                ib.abort();
                                inbound.remove(&id);
                                conn.send(&Frame::Cancel { id })?;
                                conn.send(&Frame::FileResult {
                                    id,
                                    status: 2,
                                    sha256: [0; 32],
                                })?;
                                continue;
                            }
                        }
                    } else {
                        &data
                    };
                    match ib.data(plain) {
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
            // Batch framing is PC→phone only today; a phone never sends
            // it, ignore defensively.
            Frame::BatchBegin { .. } => {}
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
