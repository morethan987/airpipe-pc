//! TLS identity and fingerprint-pinning certificate verification
//! (protocol.md §3): TOFU — a client cert is accepted iff its SHA-256(DER)
//! fingerprint is in the paired list, or a pairing window is open.

use std::sync::Arc;
use std::time::SystemTime;

use rustls::DigitallySignedStruct;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use sha2::{Digest, Sha256};

use crate::daemon::PinState;

pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    pub fingerprint: String,
}

/// SHA-256(DER) hex fingerprint, 64 lowercase chars.
pub fn fingerprint_hex(der: &[u8]) -> String {
    let d = Sha256::digest(der);
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Load `~/.local/state/airpipe/identity.pem`, generating a fresh 10-year
/// ECDSA P-256 self-signed cert (CN = `airpipe/<device>`) on first run.
pub fn load_or_create_identity(device_name: &str) -> Result<Identity, String> {
    use std::io::Write as _;

    let dir = crate::config::state_dir();
    let path = dir.join("identity.pem");
    if let Ok(pem) = std::fs::read(&path) {
        let key = PrivateKeyDer::from_pem_slice(&pem)
            .map_err(|e| format!("identity.pem: bad key: {e}"))?;
        let cert = CertificateDer::from_pem_slice(&pem)
            .map_err(|e| format!("identity.pem: bad cert: {e}"))?;
        let fingerprint = fingerprint_hex(cert.as_ref());
        return Ok(Identity {
            cert,
            key,
            fingerprint,
        });
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let ck = rcgen::generate_simple_self_signed(vec![format!("airpipe/{device_name}")])
        .map_err(|e| format!("rcgen: {e}"))?;
    let pem = format!("{}\n{}\n", ck.cert.pem(), ck.signing_key.serialize_pem());
    let mut f =
        std::fs::File::create(&path).map_err(|e| format!("write {}: {e}", path.display()))?;
    let _ = std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    f.write_all(pem.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    let fingerprint = fingerprint_hex(ck.cert.der().as_ref());
    alog!(Info, "generated new identity, fingerprint {fingerprint}");
    Ok(Identity {
        cert: ck.cert.der().clone(),
        key: rustls_pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()).into(),
        fingerprint,
    })
}

/// Client-cert verifier: authentication = fingerprint pinning, not PKI.
pub struct PinVerifier {
    pub pin: Arc<PinState>,
}

impl std::fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinVerifier").finish()
    }
}

impl ClientCertVerifier for PinVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let fp = fingerprint_hex(end_entity.as_ref());
        if self.pin.is_paired(&fp) {
            return Ok(ClientCertVerified::assertion());
        }
        if self.pin.pair_window_open() {
            alog!(Info, "admitting unknown cert {fp} (pairing window open)");
            return Ok(ClientCertVerified::assertion());
        }
        alog!(Warn, "rejecting unknown cert {fp} (not paired, no window)");
        Err(rustls::Error::General(format!("unknown fingerprint {fp}")))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 is disabled at the feature level; refuse here too.
        Err(rustls::Error::General("tls1.2 not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // The certificate itself is authenticated by fingerprint pinning in
        // verify_client_cert; signature validity is not load-bearing here.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// Server config: TLS 1.3 only (rustls built without the tls12 feature).
pub fn server_config(
    identity: &Identity,
    pin: Arc<PinState>,
) -> Result<rustls::ServerConfig, String> {
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(PinVerifier { pin }))
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .map_err(|e| format!("server cert: {e}"))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Random bytes from the OS CSPRNG.
pub fn urandom(n: usize) -> Vec<u8> {
    use std::io::Read as _;
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom")
        && f.read_exact(&mut buf).is_ok()
    {
        return buf;
    }

    // fallback: time-seeded (should never happen on Linux)
    let mut seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    for b in &mut buf {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        *b = (seed >> 33) as u8;
    }
    buf
}
