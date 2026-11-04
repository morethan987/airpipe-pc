//! IPC server: Unix-domain socket, JSON-line protocol (protocol.md §10).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config;
use crate::daemon::Shared;

pub fn bind_sock() -> Result<UnixListener, String> {
    let path = config::sock_path();
    if path.exists() {
        // live daemon, or a stale socket?
        if UnixStream::connect(&path).is_ok() {
            return Err(format!(
                "daemon 已在运行（socket {}）— 请先 `ap stop`",
                path.display()
            ));
        }
        let _ = std::fs::remove_file(&path);
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    UnixListener::bind(&path).map_err(|e| format!("bind {}: {e}", path.display()))
}

pub fn spawn(shared: Arc<Shared>, listener: UnixListener) {
    let _ = std::thread::Builder::new()
        .name("ipc".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        let shared = shared.clone();
                        let _ = std::thread::Builder::new()
                            .name("ipc-conn".into())
                            .spawn(move || handle_conn(shared, s));
                    }
                    Err(e) => alog!(Warn, "ipc accept: {e}"),
                }
            }
        });
}

fn handle_conn(shared: Arc<Shared>, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3600)));
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let msg: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let _ = reply(
                    &mut writer,
                    serde_json::json!({"ok": false, "error": format!("bad json: {e}")}),
                );
                continue;
            }
        };
        let cmd = msg.get("cmd").and_then(|c| c.as_str()).unwrap_or("");
        match cmd {
            "status" => {
                let _ = reply(&mut writer, status_json(&shared));
            }
            "send" => {
                if msg.get("stdin").and_then(|v| v.as_bool()) == Some(true) {
                    handle_stdin_send(&shared, &mut writer, &mut reader);
                } else {
                    handle_send(&shared, &mut writer, &msg);
                }
            }
            "text" => {
                let data = msg.get("data").and_then(|d| d.as_str()).unwrap_or("");
                shared.queue.push_clip(
                    false,
                    "text/plain;charset=utf-8".into(),
                    data.as_bytes().to_vec(),
                );
                let _ = reply(&mut writer, serde_json::json!({"ok": true}));
            }
            "send_clip_files" => match shared.collect_clip_files() {
                Ok(paths) => {
                    let n = paths.len();
                    shared.queue.push_files(paths);
                    let _ = reply(&mut writer, serde_json::json!({"ok": true, "queued": n}));
                }
                Err(e) => {
                    let _ = reply(&mut writer, serde_json::json!({"ok": false, "error": e}));
                }
            },
            "pair" => handle_pair(&shared, &mut writer, &msg),
            "unpair" => handle_unpair(&shared, &mut writer, &msg),
            "stop" => {
                let _ = reply(&mut writer, serde_json::json!({"ok": true}));
                shared.request_stop();
                return;
            }
            other => {
                let _ = reply(
                    &mut writer,
                    serde_json::json!({"ok": false, "error": format!("unknown cmd {other:?}")}),
                );
            }
        }
    }
}

fn reply(w: &mut UnixStream, v: serde_json::Value) -> std::io::Result<()> {
    let mut s = v.to_string();
    s.push('\n');
    w.write_all(s.as_bytes())?;
    w.flush()
}

fn status_json(shared: &Arc<Shared>) -> serde_json::Value {
    let phone = shared.session.lock().unwrap().as_ref().map(|s| {
        serde_json::json!({
            "name": *s.name.lock().unwrap(),
            "ip": s.ip,
            "connected": true,
            "since_s": s.since.elapsed().as_secs(),
        })
    });
    let (texts, files, bytes) = shared.queue.stats();
    let paired: Vec<serde_json::Value> = shared
        .devices()
        .iter()
        .map(|d| {
            serde_json::json!({
                "name": d.name,
                "fingerprint": d.fingerprint,
                "last_ip": d.last_ip,
                "last_seen": d.last_seen,
                "paired_at": d.paired_at,
            })
        })
        .collect();
    serde_json::json!({
        "ok": true,
        "proto": crate::proto::PROTO_VER,
        "uptime_s": shared.started.elapsed().as_secs(),
        "phone": phone,
        "queue": {"texts": texts, "files": files, "bytes": bytes},
        "paired": paired,
        "recv_dir": crate::config::display(&shared.cfg.inbound_dir()),
        "port": shared.cfg.port(),
    })
}

fn handle_send(shared: &Arc<Shared>, w: &mut UnixStream, msg: &serde_json::Value) {
    let Some(paths) = msg.get("paths").and_then(|p| p.as_array()) else {
        let _ = reply(
            w,
            serde_json::json!({"ok": false, "error": "missing paths"}),
        );
        return;
    };
    let paths: Vec<PathBuf> = paths
        .iter()
        .filter_map(|p| p.as_str().map(PathBuf::from))
        .collect();
    // fail fast: any unreadable path rejects the whole batch (cli.md)
    for p in &paths {
        if let Err(e) = std::fs::metadata(p) {
            let _ = reply(
                w,
                serde_json::json!({"ok": false, "error": format!("{}: {e}", p.display())}),
            );
            return;
        }
    }
    let n = paths.len();
    shared.queue.push_files(paths);
    let _ = reply(w, serde_json::json!({"ok": true, "queued": n}));
}

/// Two-step stdin flow: {"cmd":"send","stdin":true} → {"ok","token"} →
/// raw bytes until EOF → spooled to the out dir → queued → {"ok"}.
fn handle_stdin_send<R: Read>(shared: &Arc<Shared>, w: &mut UnixStream, reader: &mut R) {
    let token = crate::net::hex(&crate::net::urandom(8));
    if reply(w, serde_json::json!({"ok": true, "token": token})).is_err() {
        return;
    }
    let ts = crate::store::now_ts();
    let stamp = ts.get(0..19).unwrap_or("stamp").replace(['-', ':'], "");
    let dir = config::state_dir().join("out");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("stdin-{stamp}.bin"));
    let mut tmp = path.with_extension("part");
    let mut n = 1u32;
    while tmp.exists() {
        tmp = path.with_extension(format!("part.{n}"));
        n += 1;
    }
    let mut file = match std::fs::File::create(&tmp) {
        Ok(f) => f,
        Err(e) => {
            let _ = reply(
                w,
                serde_json::json!({"ok": false, "error": format!("spool: {e}")}),
            );
            return;
        }
    };
    let mut buf = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => {
                if let Err(e) = std::io::Write::write_all(&mut file, &buf[..k]) {
                    let _ = std::fs::remove_file(&tmp);
                    let _ = reply(
                        w,
                        serde_json::json!({"ok": false, "error": format!("spool: {e}")}),
                    );
                    return;
                }
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                let _ = reply(
                    w,
                    serde_json::json!({"ok": false, "error": format!("stdin: {e}")}),
                );
                return;
            }
        }
    }
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = reply(
            w,
            serde_json::json!({"ok": false, "error": format!("spool: {e}")}),
        );
        return;
    }
    shared.queue.push_files(vec![path]);
    let _ = reply(w, serde_json::json!({"ok": true, "queued": 1}));
}

fn handle_pair(shared: &Arc<Shared>, w: &mut UnixStream, msg: &serde_json::Value) {
    let timeout = Duration::from_secs(
        msg.get("timeout")
            .and_then(|t| t.as_u64())
            .unwrap_or(60)
            .min(600),
    );
    let code = shared.open_pair_window(timeout);
    alog!(Info, "pairing window open, code {code}");
    if reply(
        w,
        serde_json::json!({"event": "code", "code": code, "timeout": timeout.as_secs()}),
    )
    .is_err()
    {
        return;
    }
    // wait for a successful PAIR_REQUEST or window expiry
    let deadline = Instant::now() + timeout;
    let mut p = shared.pair();
    loop {
        if let Some(name) = p.paired_name.clone() {
            let _ = reply(w, serde_json::json!({"event": "paired", "name": name}));
            return;
        }
        if !p.is_open() {
            let _ = reply(
                w,
                serde_json::json!({"ok": false, "error": "配对窗口已关闭（失败次数过多）"}),
            );
            return;
        }
        let now = Instant::now();
        if now >= deadline {
            let _ = reply(w, serde_json::json!({"ok": false, "error": "timeout"}));
            return;
        }
        let (g, _) = shared.pair_cond.wait_timeout(p, deadline - now).unwrap();
        p = g;
    }
}

fn handle_unpair(shared: &Arc<Shared>, w: &mut UnixStream, msg: &serde_json::Value) {
    let name = msg.get("name").and_then(|n| n.as_str()).unwrap_or("");
    if name == "all" {
        shared.devices().clear();
    } else {
        shared.devices().retain(|d| d.name != name);
    }
    let devs = shared.devices().to_vec();
    if let Err(e) = crate::store::save_devices(&crate::store::DeviceList { devices: devs }) {
        let _ = reply(w, serde_json::json!({"ok": false, "error": format!("{e}")}));
        return;
    }
    // a live session from an unpaired device is no longer trusted: BYE it
    let fp_of = |n: &str| {
        shared
            .devices()
            .iter()
            .find(|d| d.name == n)
            .map(|d| d.fingerprint.clone())
    };
    let _ = fp_of;
    if let Some(s) = shared.session.lock().unwrap().as_ref() {
        let sname = s.name.lock().unwrap().clone();
        if name == "all" || sname == name {
            let _ = s.conn.send(&crate::proto::Frame::Bye {
                reason: "unpaired".into(),
            });
            s.conn.close();
        }
    }
    shared.tray_refresh();
    let _ = reply(w, serde_json::json!({"ok": true}));
}
