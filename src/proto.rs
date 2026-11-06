//! Wire protocol (protocol.md §5): frames are `1B type + 4B big-endian
//! payload length + payload`, inside TLS 1.3.

use std::time::Duration;

pub const PROTO_VER: u16 = 2;
pub const TCP_PORT: u16 = 17580;
pub const CHUNK: usize = 131_072;
pub const MAX_TEXT: usize = 4 * 1024 * 1024;
pub const MAX_IMAGE: usize = 24 * 1024 * 1024;
/// Any frame whose declared payload exceeds this is a protocol error.
pub const MAX_FRAME: usize = MAX_IMAGE + 64;
pub const PROGRESS_EVERY: u64 = 4 * 1024 * 1024;
pub const PING_EVERY: Duration = Duration::from_secs(15);
pub const SILENCE_DEAD: Duration = Duration::from_secs(45);
pub const PAIR_WINDOW: Duration = Duration::from_secs(60);
pub const PAIR_MAX_TRIES: u32 = 5;

/// HELLO caps bits.
pub const CAP_TEXT: u32 = 1;
pub const CAP_IMAGE: u32 = 2;
pub const CAP_FILES: u32 = 4;

/// FILE_BEGIN flags.
pub const BF_SIZE_UNKNOWN: u8 = 1;
pub const BF_DIR: u8 = 2;

/// FILE_DATA flags (v2): bit0 = chunk is zstd-compressed.
pub const DF_ZSTD: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello {
        ver: u16,
        name: String,
        caps: u32,
    },
    Ping,
    Pong,
    ClipText {
        mime: String,
        data: Vec<u8>,
    },
    ClipImage {
        mime: String,
        data: Vec<u8>,
    },
    FileBegin {
        id: u32,
        flags: u8,
        rel_path: String,
        size: u64,
    },
    FileData {
        id: u32,
        /// payload flag bit0: the chunk body is zstd-compressed (v2)
        zstd: bool,
        data: Vec<u8>,
    },
    FileEnd {
        id: u32,
    },
    /// Batch begin (§6): one user send action; announces the batch totals
    /// so the receiver aggregates progress and reports one event.
    BatchBegin {
        items: u32,
        files: u32,
        bytes: u64,
    },
    FileProgress {
        id: u32,
        bytes: u64,
    },
    FileResult {
        id: u32,
        status: u8,
        sha256: [u8; 32],
    },
    Cancel {
        id: u32,
    },
    PairRequest {
        code: String,
        name: String,
    },
    PairAccept {
        name: String,
    },
    Bye {
        reason: String,
    },
}

#[derive(Debug)]
pub enum FrameError {
    Eof,
    Io(std::io::Error),
    TooLong(usize),
    BadType(u8),
    Malformed(&'static str),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Eof => write!(f, "connection closed"),
            FrameError::Io(e) => write!(f, "io error: {e}"),
            FrameError::TooLong(n) => write!(f, "frame length {n} exceeds limit"),
            FrameError::BadType(b) => write!(f, "unknown frame type {:#04x}", b),
            FrameError::Malformed(s) => write!(f, "malformed frame: {s}"),
        }
    }
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Eof
        } else {
            FrameError::Io(e)
        }
    }
}

impl std::error::Error for FrameError {}

fn put_u16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_be_bytes());
}
fn put_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_be_bytes());
}

fn get_u16(p: &[u8], off: &mut usize) -> Result<u16, FrameError> {
    let s = *off;
    if s + 2 > p.len() {
        return Err(FrameError::Malformed("truncated u16"));
    }
    *off += 2;
    Ok(u16::from_be_bytes([p[s], p[s + 1]]))
}
fn get_u32(p: &[u8], off: &mut usize) -> Result<u32, FrameError> {
    let s = *off;
    if s + 4 > p.len() {
        return Err(FrameError::Malformed("truncated u32"));
    }
    *off += 4;
    Ok(u32::from_be_bytes([p[s], p[s + 1], p[s + 2], p[s + 3]]))
}
fn get_u64(p: &[u8], off: &mut usize) -> Result<u64, FrameError> {
    let s = *off;
    if s + 8 > p.len() {
        return Err(FrameError::Malformed("truncated u64"));
    }
    *off += 8;
    Ok(u64::from_be_bytes(p[s..s + 8].try_into().unwrap()))
}
fn get_bytes<'a>(p: &'a [u8], off: &mut usize, n: usize) -> Result<&'a [u8], FrameError> {
    let s = *off;
    if s + n > p.len() {
        return Err(FrameError::Malformed("truncated bytes"));
    }
    *off += n;
    Ok(&p[s..s + n])
}
fn get_str(p: &[u8], off: &mut usize, n: usize) -> Result<String, FrameError> {
    let b = get_bytes(p, off, n)?;
    String::from_utf8(b.to_vec()).map_err(|_| FrameError::Malformed("invalid utf-8"))
}
/// Trailing garbage check helper.
fn end(p: &[u8], off: &mut usize) -> Result<(), FrameError> {
    if *off != p.len() {
        return Err(FrameError::Malformed("trailing bytes"));
    }
    Ok(())
}

impl Frame {
    pub fn kind(&self) -> u8 {
        match self {
            Frame::Hello { .. } => b'H',
            Frame::Ping => b'P',
            Frame::Pong => b'p',
            Frame::ClipText { .. } => b'T',
            Frame::ClipImage { .. } => b'I',
            Frame::FileBegin { .. } => b'B',
            Frame::FileData { .. } => b'D',
            Frame::FileEnd { .. } => b'E',
            Frame::FileProgress { .. } => b'R',
            Frame::FileResult { .. } => b'F',
            Frame::Cancel { .. } => b'X',
            Frame::PairRequest { .. } => b'Q',
            Frame::PairAccept { .. } => b'A',
            Frame::Bye { .. } => b'Y',
            Frame::BatchBegin { .. } => b'G',
        }
    }

    fn payload(&self) -> Vec<u8> {
        let mut p = Vec::new();
        match self {
            Frame::Hello { ver, name, caps } => {
                put_u16(&mut p, *ver);
                p.push(name.len().clamp(0, 255) as u8);
                p.extend_from_slice(name.as_bytes());
                put_u32(&mut p, *caps);
            }
            Frame::Ping | Frame::Pong => {}
            Frame::ClipText { mime, data } | Frame::ClipImage { mime, data } => {
                p.push(mime.len().clamp(0, 255) as u8);
                p.extend_from_slice(mime.as_bytes());
                p.extend_from_slice(data);
            }
            Frame::FileBegin {
                id,
                flags,
                rel_path,
                size,
            } => {
                put_u32(&mut p, *id);
                p.push(*flags);
                let n = rel_path.len().min(u16::MAX as usize);
                put_u16(&mut p, n as u16);
                p.extend_from_slice(&rel_path.as_bytes()[..n]);
                put_u64(&mut p, *size);
            }
            Frame::FileData { id, zstd, data } => {
                put_u32(&mut p, *id);
                p.push(if *zstd { DF_ZSTD } else { 0 });
                p.extend_from_slice(data);
            }
            Frame::FileEnd { id } | Frame::Cancel { id } => {
                put_u32(&mut p, *id);
            }
            Frame::FileProgress { id, bytes } => {
                put_u32(&mut p, *id);
                put_u64(&mut p, *bytes);
            }
            Frame::FileResult { id, status, sha256 } => {
                put_u32(&mut p, *id);
                p.push(*status);
                p.extend_from_slice(sha256);
            }
            Frame::PairRequest { code, name } => {
                p.push(code.len().clamp(0, 255) as u8);
                p.extend_from_slice(code.as_bytes());
                p.push(name.len().clamp(0, 255) as u8);
                p.extend_from_slice(name.as_bytes());
            }
            Frame::PairAccept { name } => {
                p.push(name.len().clamp(0, 255) as u8);
                p.extend_from_slice(name.as_bytes());
            }
            Frame::Bye { reason } => {
                p.push(reason.len().clamp(0, 255) as u8);
                p.extend_from_slice(reason.as_bytes());
            }
            Frame::BatchBegin {
                items,
                files,
                bytes,
            } => {
                put_u32(&mut p, *items);
                put_u32(&mut p, *files);
                put_u64(&mut p, *bytes);
            }
        }
        p
    }

    pub fn encode(&self) -> Vec<u8> {
        let p = self.payload();
        let mut buf = Vec::with_capacity(5 + p.len());
        buf.push(self.kind());
        buf.extend_from_slice(&(p.len() as u32).to_be_bytes());
        buf.extend_from_slice(&p);
        buf
    }

    pub fn decode(kind: u8, p: &[u8]) -> Result<Frame, FrameError> {
        let mut o = 0usize;
        let f = match kind {
            b'H' => {
                let ver = get_u16(p, &mut o)?;
                let n = get_bytes(p, &mut o, 1)?[0] as usize;
                let name = get_str(p, &mut o, n)?;
                let caps = get_u32(p, &mut o)?;
                Frame::Hello { ver, name, caps }
            }
            b'P' => Frame::Ping,
            b'p' => Frame::Pong,
            b'T' | b'I' => {
                let n = get_bytes(p, &mut o, 1)?[0] as usize;
                let mime = get_str(p, &mut o, n)?;
                let rest = p.len() - o;
                let data = get_bytes(p, &mut o, rest)?.to_vec();
                if kind == b'T' {
                    Frame::ClipText { mime, data }
                } else {
                    Frame::ClipImage { mime, data }
                }
            }
            b'B' => {
                let id = get_u32(p, &mut o)?;
                let flags = get_bytes(p, &mut o, 1)?[0];
                let n = get_u16(p, &mut o)? as usize;
                let rel_path = get_str(p, &mut o, n)?;
                let size = get_u64(p, &mut o)?;
                Frame::FileBegin {
                    id,
                    flags,
                    rel_path,
                    size,
                }
            }
            b'D' => {
                let id = get_u32(p, &mut o)?;
                let flags = get_bytes(p, &mut o, 1)?[0];
                if flags & !DF_ZSTD != 0 {
                    return Err(FrameError::Malformed("unknown FILE_DATA flags"));
                }
                let rest = p.len() - o;
                let data = get_bytes(p, &mut o, rest)?.to_vec();
                Frame::FileData {
                    id,
                    zstd: flags & DF_ZSTD != 0,
                    data,
                }
            }
            b'E' => Frame::FileEnd {
                id: get_u32(p, &mut o)?,
            },
            b'R' => {
                let id = get_u32(p, &mut o)?;
                let bytes = get_u64(p, &mut o)?;
                Frame::FileProgress { id, bytes }
            }
            b'F' => {
                let id = get_u32(p, &mut o)?;
                let status = get_bytes(p, &mut o, 1)?[0];
                let sha256: [u8; 32] = get_bytes(p, &mut o, 32)?.try_into().unwrap();
                Frame::FileResult { id, status, sha256 }
            }
            b'X' => Frame::Cancel {
                id: get_u32(p, &mut o)?,
            },
            b'G' => {
                let items = get_u32(p, &mut o)?;
                let files = get_u32(p, &mut o)?;
                let bytes = get_u64(p, &mut o)?;
                Frame::BatchBegin {
                    items,
                    files,
                    bytes,
                }
            }
            b'Q' => {
                let n = get_bytes(p, &mut o, 1)?[0] as usize;
                let code = get_str(p, &mut o, n)?;
                let n = get_bytes(p, &mut o, 1)?[0] as usize;
                let name = get_str(p, &mut o, n)?;
                Frame::PairRequest { code, name }
            }
            b'A' => {
                let n = get_bytes(p, &mut o, 1)?[0] as usize;
                let name = get_str(p, &mut o, n)?;
                Frame::PairAccept { name }
            }
            b'Y' => {
                let n = get_bytes(p, &mut o, 1)?[0] as usize;
                let reason = get_str(p, &mut o, n)?;
                Frame::Bye { reason }
            }
            b => return Err(FrameError::BadType(b)),
        };
        end(p, &mut o)?;
        Ok(f)
    }
}

/// Try to decode one complete frame from the head of `buf`, consuming it.
/// Returns `None` when more bytes are needed (incremental decoding of
/// buffered plaintext, e.g. fed by a dedicated reader thread).
pub fn take_frame(buf: &mut Vec<u8>) -> Option<Result<Frame, FrameError>> {
    if buf.len() < 5 {
        return None;
    }
    let kind = buf[0];
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > MAX_FRAME {
        return Some(Err(FrameError::TooLong(len)));
    }
    if buf.len() < 5 + len {
        return None;
    }
    let frame = Frame::decode(kind, &buf[5..5 + len]);
    buf.drain(..5 + len);
    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(f: Frame) {
        let bytes = f.encode();
        assert_eq!(bytes[0], f.kind());
        let back = Frame::decode(f.kind(), &bytes[5..]).expect("decode");
        assert_eq!(back, f);
    }

    #[test]
    fn round_trip_all_types() {
        rt(Frame::Hello {
            ver: 1,
            name: "workstation".into(),
            caps: 7,
        });
        rt(Frame::Ping);
        rt(Frame::Pong);
        rt(Frame::ClipText {
            mime: "text/plain;charset=utf-8".into(),
            data: b"hello".to_vec(),
        });
        rt(Frame::ClipImage {
            mime: "image/png".into(),
            data: vec![1, 2, 3, 250],
        });
        rt(Frame::FileBegin {
            id: 42,
            flags: BF_DIR,
            rel_path: "docs/子 目录/a b.txt".into(),
            size: 1 << 40,
        });
        rt(Frame::FileData {
            id: 42,
            zstd: false,
            data: vec![9; CHUNK],
        });
        rt(Frame::FileData {
            id: 43,
            zstd: true,
            data: vec![1, 2, 3],
        });
        rt(Frame::FileEnd { id: 42 });
        rt(Frame::FileProgress {
            id: 42,
            bytes: PROGRESS_EVERY,
        });
        rt(Frame::FileResult {
            id: 42,
            status: 0,
            sha256: [7; 32],
        });
        rt(Frame::Cancel { id: 7 });
        rt(Frame::BatchBegin {
            items: 3,
            files: 17,
            bytes: 47_244_640_256,
        });
        rt(Frame::PairRequest {
            code: "483920".into(),
            name: "mi-13p".into(),
        });
        rt(Frame::PairAccept {
            name: "workstation".into(),
        });
        rt(Frame::Bye {
            reason: "version mismatch".into(),
        });
    }

    #[test]
    fn bad_type_and_malformed() {
        assert!(matches!(
            Frame::decode(b'Z', b""),
            Err(FrameError::BadType(b'Z'))
        ));
        // HELLO without caps field.
        let p = [0, 1, 3, b'a', b'b', b'c'];
        assert!(matches!(
            Frame::decode(b'H', &p),
            Err(FrameError::Malformed(_))
        ));
        // Trailing garbage.
        assert!(matches!(
            Frame::decode(b'P', &[0]),
            Err(FrameError::Malformed(_))
        ));
    }

    #[test]
    fn take_frame_reassembles_and_drains() {
        let first = Frame::ClipText {
            mime: "text/plain".into(),
            data: b"hi".to_vec(),
        }
        .encode();
        let second = Frame::Ping.encode();
        let mut buf = Vec::new();
        buf.extend_from_slice(&first[..3]);
        assert!(take_frame(&mut buf).is_none());
        buf.extend_from_slice(&first[3..7]);
        assert!(take_frame(&mut buf).is_none());
        buf.extend_from_slice(&first[7..]);
        buf.extend_from_slice(&second);
        match take_frame(&mut buf) {
            Some(Ok(f)) => assert_eq!(
                f,
                Frame::ClipText {
                    mime: "text/plain".into(),
                    data: b"hi".to_vec()
                }
            ),
            other => panic!("first frame mismatch: {other:?}"),
        }
        match take_frame(&mut buf) {
            Some(Ok(f)) => assert_eq!(f, Frame::Ping),
            other => panic!("second frame mismatch: {other:?}"),
        }
        assert!(take_frame(&mut buf).is_none());
        assert!(buf.is_empty());
    }

    #[test]
    fn take_frame_rejects_oversize_and_bad_type() {
        let mut buf = vec![b'D'];
        buf.extend_from_slice(&((MAX_FRAME as u32) + 1).to_be_bytes());
        assert!(matches!(
            take_frame(&mut buf),
            Some(Err(FrameError::TooLong(n))) if n == MAX_FRAME + 1
        ));
        let mut buf = vec![b'Z', 0, 0, 0, 0];
        assert!(matches!(
            take_frame(&mut buf),
            Some(Err(FrameError::BadType(b'Z')))
        ));
    }
}
