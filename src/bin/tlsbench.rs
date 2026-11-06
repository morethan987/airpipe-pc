//! tlsbench — loopback transfer-stack benchmark (docs/transfer-perf.md).
//!
//! Replicates the daemon's frame write path (`1B type + 4B BE len + payload`
//! through rustls `Connection::writer()` + record flush loop, see
//! daemon::Conn::send_locked) against a draining receiver, both on
//! 127.0.0.1, so the network drops out and only the userspace stack cost
//! (frame size, TLS records, syscalls, allocs) remains.
//!
//! Usage: tlsbench [--mib N] [--streams N] [--chunks "a,b,c"] [--tls|--plain]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Barrier};
use std::time::Instant;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, StreamOwned};

/// One send-side "frame" write, mirroring daemon::Conn::send_locked:
/// rustls caps the outgoing record buffer; queue a slice, flush complete
/// records to the socket, repeat until the whole frame is on the wire.
fn send_frame<W: Write>(
    frame: &[u8],
    tls: &mut rustls::ClientConnection,
    sock: &mut W,
) -> std::io::Result<()> {
    let mut off = 0;
    while off < frame.len() {
        let n = tls.writer().write(&frame[off..])?;
        while tls.wants_write() {
            tls.write_tls(sock)?;
        }
        off += n;
    }
    Ok(())
}

/// Receiver: drain until EOF, return total bytes.
fn drain(mut rd: impl Read) -> std::io::Result<u64> {
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = match rd.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return Ok(total),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(total);
        }
        total += n as u64;
    }
}

#[derive(Clone)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);
impl std::fmt::Debug for NoVerify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoVerify")
    }
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

enum Mode {
    Plain,
    Tls,
}

fn run_once(mode: Mode, chunk: usize, streams: usize, total: u64) -> f64 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();

    let (server_cfg, client_cfg) = match mode {
        Mode::Plain => (None, None),
        Mode::Tls => {
            let ck = rcgen::generate_simple_self_signed(vec!["bench".into()]).unwrap();
            let mut sc = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![ck.cert.der().clone()],
                    rustls_pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())
                        .into(),
                )
                .unwrap();
            sc.alpn_protocols = vec![b"bench".to_vec()];
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut cc = ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(protocol_versions())
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
                .with_no_client_auth();
            cc.alpn_protocols = vec![b"bench".to_vec()];
            (Some(Arc::new(sc)), Some(Arc::new(cc)))
        }
    };

    // Server threads: one per expected connection.
    let barrier = Arc::new(Barrier::new(streams * 2));
    let mut srv_handles = Vec::new();
    for _ in 0..streams {
        let l = listener.try_clone().unwrap();
        let cfg = server_cfg.clone();
        let b = barrier.clone();
        srv_handles.push(std::thread::spawn(move || {
            let (sock, _) = l.accept().unwrap();
            match cfg {
                None => {
                    b.wait();
                    drain(sock).unwrap();
                }
                Some(cfg) => {
                    let conn = rustls::ServerConnection::new(cfg).unwrap();
                    let mut s = StreamOwned::new(conn, sock);
                    while s.conn.is_handshaking() {
                        s.conn.complete_io(&mut s.sock).unwrap();
                    }
                    b.wait();
                    drain(&mut s).unwrap();
                }
            }
        }));
    }

    // Client threads.
    let per_stream = total / streams as u64;
    let mut cli_handles = Vec::new();
    for _ in 0..streams {
        let cfg = client_cfg.clone();
        let b = barrier.clone();
        cli_handles.push(std::thread::spawn(move || {
            let sock = TcpStream::connect(addr).unwrap();
            sock.set_nodelay(true).unwrap();
            let started: Box<dyn FnOnce() -> Instant> = {
                let b = b.clone();
                Box::new(move || {
                    b.wait();
                    Instant::now()
                })
            };
            match cfg {
                None => {
                    let started = started();
                    let mut sock = sock;
                    // v2 FILE_DATA body: id u32 + flags u8 + data
                    let mut frame = vec![0u8; 5 + 4 + 1 + chunk];
                    frame[0] = b'D';
                    frame[1..5].copy_from_slice(&((4 + 1 + chunk) as u32).to_be_bytes());
                    frame[5..9].copy_from_slice(&1u32.to_be_bytes());
                    frame[9] = 0; // flags: raw
                    let mut left = per_stream;
                    while left > 0 {
                        let n = chunk.min(left as usize);
                        sock.write_all(&frame[..5 + 4 + 1 + n]).unwrap();
                        left -= n as u64;
                    }
                    sock.shutdown(std::net::Shutdown::Write).unwrap();
                    (started.elapsed(), per_stream)
                }
                Some(cfg) => {
                    let server_name = ServerName::try_from("localhost").unwrap();
                    let mut conn = rustls::ClientConnection::new(cfg, server_name).unwrap();
                    let mut sock = sock;
                    while conn.wants_write() {
                        conn.write_tls(&mut sock).unwrap();
                    }
                    while conn.is_handshaking() {
                        conn.complete_io(&mut sock).unwrap();
                    }
                    let started = started();
                    let mut frame = vec![0u8; 5 + 4 + 1 + chunk];
                    frame[0] = b'D';
                    frame[1..5].copy_from_slice(&((4 + 1 + chunk) as u32).to_be_bytes());
                    frame[5..9].copy_from_slice(&1u32.to_be_bytes());
                    frame[9] = 0; // flags: raw
                    let mut left = per_stream;
                    while left > 0 {
                        let n = chunk.min(left as usize);
                        send_frame(&frame[..5 + 4 + 1 + n], &mut conn, &mut sock).unwrap();
                        left -= n as u64;
                    }
                    conn.send_close_notify();
                    while conn.wants_write() {
                        conn.write_tls(&mut sock).unwrap();
                    }
                    sock.shutdown(std::net::Shutdown::Write).unwrap();
                    (started.elapsed(), per_stream)
                }
            }
        }));
    }

    let mut mbs = 0.0f64;
    for h in cli_handles {
        let (el, bytes) = h.join().unwrap();
        mbs += bytes as f64 / el.as_secs_f64() / 1024.0 / 1024.0;
    }
    for h in srv_handles {
        h.join().unwrap();
    }
    mbs
}

fn protocol_versions() -> &'static [&'static rustls::SupportedProtocolVersion] {
    static V: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    V
}

fn main() {
    let mut mib: u64 = 2048;
    let mut streams = 1usize;
    let mut chunks: Vec<usize> = vec![16, 32, 64, 128, 256, 512, 1024];
    let mut modes = vec!["tls", "plain"];
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--mib" => mib = args.next().unwrap().parse().unwrap(),
            "--streams" => streams = args.next().unwrap().parse().unwrap(),
            "--chunks" => {
                chunks = args
                    .next()
                    .unwrap()
                    .split(',')
                    .map(|s| s.parse().unwrap())
                    .collect()
            }
            "--tls" => modes = vec!["tls"],
            "--plain" => modes = vec!["plain"],
            _ => panic!("unknown arg {a}"),
        }
    }
    let total = mib * 1024 * 1024;
    println!("mode  chunk_KiB  streams  MB/s");
    for m in &modes {
        for c in &chunks {
            let mbs = run_once(
                if *m == "tls" { Mode::Tls } else { Mode::Plain },
                c * 1024,
                streams,
                total,
            );
            println!("{m:<5} {:>10} {:>8} {:>8.1}", c, streams, mbs);
        }
    }
}
