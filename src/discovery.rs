//! UDP discovery responder (protocol.md §2): phones broadcast
//! `AIRPIPE_DISCOVER <ver>`; we unicast `AIRPIPE_PC <ver> <port> <fp16>` back.

use std::net::UdpSocket;
use std::sync::Arc;

use crate::daemon::Shared;

pub fn spawn(shared: Arc<Shared>) {
    std::thread::Builder::new()
        .name("discover".into())
        .spawn(move || run(shared))
        .expect("spawn discovery thread");
}

fn run(shared: Arc<Shared>) {
    let port = shared.cfg.port();
    let sock = match UdpSocket::bind(("0.0.0.0", port)) {
        Ok(s) => s,
        Err(e) => {
            alog!(
                Warn,
                "discovery: UDP bind :{port} failed: {e} (continuing without)"
            );
            return;
        }
    };
    let _ = sock.set_broadcast(true);
    let fp16 = &shared.identity.fingerprint[..16];
    alog!(Info, "discovery: answering on UDP :{port} (fp16 {fp16})");
    let mut buf = [0u8; 128];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                alog!(Warn, "discovery: recv: {e}");
                return;
            }
        };
        let msg = String::from_utf8_lossy(&buf[..n]);
        let mut parts = msg.split_whitespace();
        if parts.next() == Some("AIRPIPE_DISCOVER") {
            match parts.next().and_then(|v| v.parse::<u16>().ok()) {
                Some(v) if v == crate::proto::PROTO_VER => {}
                _ => continue,
            }
            let reply = format!("AIRPIPE_PC {} {} {}", crate::proto::PROTO_VER, port, fp16);
            alog!(Debug, "discovery: {msg} from {src}, replying");
            let _ = sock.send_to(reply.as_bytes(), src);
        }
    }
}
