//! File send planning and inbound receive state (protocol.md §5/§7).

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::proto::PROGRESS_EVERY;

/// Sanitize an inbound relPath: strip leading `/`, drop `..` and empty
/// segments, keep everything else (Chinese, spaces) verbatim.
#[must_use]
pub fn sanitize_rel(rel: &str) -> String {
    rel.split('/')
        .filter(|seg| !seg.is_empty() && *seg != ".." && *seg != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// Resolve `rel` under `root`, creating intermediate directories.
pub fn resolve_under(root: &Path, rel: &str) -> std::io::Result<PathBuf> {
    let mut p = root.to_path_buf();
    for seg in rel.split('/').filter(|s| !s.is_empty()) {
        p.push(seg);
    }
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(p)
}

/// If `path` exists, append ` (1)`, ` (2)`, ... before the extension until
/// free. Never overwrites.
#[must_use]
pub fn unique_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()));
    for n in 1u32.. {
        let cand = path.with_file_name(format!("{stem} ({n}){}", ext.clone().unwrap_or_default()));
        if !cand.exists() {
            return cand;
        }
    }
    unreachable!()
}

/// One planned outbound entry.
#[derive(Debug, Clone, PartialEq)]
pub enum SendEntry {
    /// Empty directory skeleton entry (B frame with BF_DIR).
    Dir { rel: String },
    /// Regular file.
    File {
        abs: PathBuf,
        rel: String,
        size: u64,
    },
}

/// Expand user-supplied paths into a deterministic, sorted send plan.
/// Top-level names only: a file arg lands at the receive root as its own
/// file name; a dir arg keeps its own top dir name and recurses inside.
/// Never cwd-relative — a copied file must not drag its parent dirs along.
pub fn plan(paths: &[PathBuf]) -> std::io::Result<Vec<SendEntry>> {
    let mut out = Vec::new();
    for p in paths {
        let meta = std::fs::metadata(p)
            .map_err(|e| std::io::Error::other(format!("{}: {e}", p.display())))?;
        if !meta.is_dir() && !meta.is_file() {
            return Err(std::io::Error::other(format!(
                "{}: not a regular file or dir",
                p.display()
            )));
        }
        let top_rel = top_name(p)?;
        if meta.is_dir() {
            walk_dir(p, &top_rel, &mut out)?;
        } else {
            out.push(SendEntry::File {
                abs: p.clone(),
                rel: top_rel,
                size: meta.len(),
            });
        }
    }
    Ok(out)
}

/// The top-level rel name is always the argument's own file name —
/// `/home/x/Airpipe/from_phone/test.pdf` sends as just `test.pdf`, and
/// `/home/x/Airpipe/from_phone` sends as `from_phone/...`.
fn top_name(p: &Path) -> std::io::Result<String> {
    let name = sanitize_rel(
        &p.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
    );
    if name.is_empty() {
        return Err(std::io::Error::other(format!(
            "{}: no usable file name",
            p.display()
        )));
    }
    Ok(name)
}

fn walk_dir(dir: &Path, top_rel: &str, out: &mut Vec<SendEntry>) -> std::io::Result<()> {
    out.push(SendEntry::Dir {
        rel: top_rel.to_owned(),
    });
    // sorted entries per directory level for deterministic transfer order
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for e in entries {
        let name = e
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let rel = if top_rel.is_empty() {
            name
        } else {
            format!("{top_rel}/{name}")
        };
        let meta = std::fs::symlink_metadata(&e)?;
        if meta.is_dir() {
            walk_dir(&e, &rel, out)?;
        } else if meta.is_file() {
            out.push(SendEntry::File {
                abs: e,
                rel,
                size: meta.len(),
            });
        }
        // symlinks and specials are skipped
    }
    Ok(())
}

/// Inbound file being received (B/D/E state machine, one per id).
pub struct Inbound {
    pub final_path: PathBuf,
    pub part_path: PathBuf,
    writer: Option<BufWriter<File>>,
    hasher: Sha256,
    since_progress: u64,
    pub received: u64,
}

impl Inbound {
    pub fn new_file(final_path: PathBuf) -> std::io::Result<Self> {
        let part_path = final_path.with_extension(format!(
            "{}part",
            final_path
                .extension()
                .map(|e| format!("{}.", e.to_string_lossy()))
                .unwrap_or_default()
        ));
        let f = File::create(&part_path)?;
        Ok(Self {
            final_path,
            part_path,
            writer: Some(BufWriter::new(f)),
            hasher: Sha256::new(),
            since_progress: 0,
            received: 0,
        })
    }

    /// Append a chunk. Returns Some(bytes_total) each PROGRESS_EVERY boundary.
    pub fn data(&mut self, bytes: &[u8]) -> std::io::Result<Option<u64>> {
        let w = self
            .writer
            .as_mut()
            .ok_or_else(|| std::io::Error::other("already finished"))?;
        w.write_all(bytes)?;
        self.hasher.update(bytes);
        self.received += bytes.len() as u64;
        self.since_progress += bytes.len() as u64;
        if self.since_progress >= PROGRESS_EVERY {
            self.since_progress = 0;
            return Ok(Some(self.received));
        }
        Ok(None)
    }

    /// Finalize: flush, rename .part → final. Returns the file sha256.
    pub fn finish(&mut self) -> std::io::Result<[u8; 32]> {
        let mut w = self
            .writer
            .take()
            .ok_or_else(|| std::io::Error::other("already finished"))?;
        w.flush()?;
        drop(w);
        std::fs::rename(&self.part_path, &self.final_path)?;
        let digest: [u8; 32] = self.hasher.clone().finalize().into();
        Ok(digest)
    }

    /// Abort: drop the .part file.
    pub fn abort(&mut self) {
        self.writer = None;
        let _ = std::fs::remove_file(&self.part_path);
    }
}

/// Read a file in <=CHUNK pieces, feeding caller both chunk and running hash.
pub struct FileChunks {
    f: File,
    pub hash: Sha256,
}

impl FileChunks {
    pub fn open(p: &Path) -> std::io::Result<Self> {
        Ok(Self {
            f: File::open(p)?,
            hash: Sha256::new(),
        })
    }

    /// Next chunk (None at EOF). Updates the running hash.
    pub fn next<'a>(&mut self, buf: &'a mut Vec<u8>) -> std::io::Result<Option<&'a [u8]>> {
        buf.resize(crate::proto::CHUNK, 0);
        let mut filled = 0usize;
        while filled < buf.len() {
            match self.f.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        if filled == 0 {
            return Ok(None);
        }
        buf.truncate(filled);
        self.hash.update(&buf[..filled]);
        Ok(Some(&buf[..filled]))
    }

    pub fn digest(&self) -> [u8; 32] {
        self.hash.clone().finalize().into()
    }
}

// -------------------------------------------------------------- compression
// (protocol v2, transfer-perf.md §3.4/§6): per-chunk zstd level 1, chosen
// because the wire (1.3–4.2 MB/s WLAN / 36 MB/s USB) is two orders of
// magnitude slower than both codecs, so ratio is the only thing that moves
// end-to-end time.

/// Compression policy from `[transfer] compression`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompMode {
    /// zstd everything except known-compressed extensions.
    Auto,
    /// zstd everything (per-chunk fallback keeps incompressible data raw).
    Always,
    /// v1 behavior: never compress.
    Never,
}

impl CompMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "always" => Some(Self::Always),
            "never" => Some(Self::Never),
            _ => None,
        }
    }
}

/// Extensions whose payloads are already entropy-coded; zstd on them is
/// pure CPU burn (measured ratio 1.000). Lowercase compare.
const INCOMPRESSIBLE: &[&str] = &[
    // archives
    "zip", "rar", "7z", "gz", "xz", "zst", "bz2", "br", "lz4", "sz", "tgz", "tbz2", "txz", "crx",
    // images
    "png", "jpg", "jpeg", "webp", "gif", "heic", "heif", "avif", "jxl", // video
    "mp4", "mov", "mkv", "webm", "avi", "m4v", "3gp", "mpeg", "mpg", "ts", "flv", "wmv",
    // audio
    "mp3", "m4a", "aac", "flac", "ogg", "opus", "wma", "ape", "mka",
    // apps / packages (zip-based containers included)
    "apk", "aab", "jar", "dex", "docx", "xlsx", "pptx", "epub", "cbz", "iso", "dmg", "deb", "rpm",
];

/// Whether outbound `name` should be compressed under `mode`.
#[must_use]
pub fn should_compress(name: &str, mode: CompMode) -> bool {
    match mode {
        CompMode::Never => false,
        CompMode::Always => true,
        CompMode::Auto => {
            let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
            match ext {
                Some(e) => !INCOMPRESSIBLE.contains(&e.as_str()),
                None => true,
            }
        }
    }
}

/// Per-file zstd compressor for outbound chunks. Chunks are compressed
/// independently (random access, D-frame boundaries); one context is
/// reused across the file's chunks.
pub struct ChunkEncoder {
    c: Option<zstd::bulk::Compressor<'static>>,
}

impl ChunkEncoder {
    pub fn new(enabled: bool) -> Self {
        Self {
            c: if enabled {
                zstd::bulk::Compressor::new(1).ok()
            } else {
                None
            },
        }
    }

    /// Compress `chunk` into `zbuf` if that is strictly smaller; returns
    /// (was_compressed, wire_bytes). Never copies in the raw fallback.
    pub fn encode<'a>(&mut self, chunk: &'a [u8], zbuf: &'a mut Vec<u8>) -> (bool, &'a [u8]) {
        let Some(c) = self.c.as_mut() else {
            return (false, chunk);
        };
        zbuf.clear();
        // covers zstd's worst-case bound (src + src/256 + 64) for any chunk
        let bound = chunk.len() + chunk.len() / 64 + 1024;
        if zbuf.capacity() < bound {
            zbuf.reserve(bound - zbuf.capacity());
        }
        match c.compress_to_buffer(chunk, zbuf) {
            Ok(n) if n < chunk.len() => (true, &zbuf[..n]),
            _ => (false, chunk),
        }
    }
}

/// Reusable zstd decompressor for inbound chunks. Output is bounded by
/// CHUNK (the sender never compresses a chunk larger than that).
pub struct ChunkDecoder {
    d: zstd::bulk::Decompressor<'static>,
    pub buf: Vec<u8>,
}

impl ChunkDecoder {
    pub fn new() -> Self {
        Self {
            d: zstd::bulk::Decompressor::new().expect("zstd context"),
            buf: vec![0; crate::proto::CHUNK],
        }
    }

    /// Decompress a zstd D-frame body. Errors (bad frame, oversize output)
    /// surface as io errors so the existing inbound-abort path handles them.
    pub fn decode(&mut self, z: &[u8]) -> std::io::Result<&[u8]> {
        self.buf.clear();
        let n = self
            .d
            .decompress_to_buffer(z, &mut self.buf)
            .map_err(|e| std::io::Error::other(format!("zstd: {e}")))?;
        Ok(&self.buf[..n])
    }
}

impl Default for ChunkDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_and_drops() {
        assert_eq!(sanitize_rel("/a/b/c.txt"), "a/b/c.txt");
        assert_eq!(sanitize_rel("../../etc/passwd"), "etc/passwd");
        assert_eq!(sanitize_rel("a//b/./c"), "a/b/c");
        assert_eq!(sanitize_rel("文 档/子 目/a b.txt"), "文 档/子 目/a b.txt");
        assert_eq!(sanitize_rel(".."), "");
        assert_eq!(sanitize_rel("/../.."), "");
    }

    #[test]
    fn unique_appends_numbers_before_extension() {
        let dir = std::env::temp_dir().join(format!("airpipe-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("photo.png");
        std::fs::write(&a, b"1").unwrap();
        assert_eq!(unique_path(&a), dir.join("photo (1).png"));
        std::fs::write(dir.join("photo (1).png"), b"2").unwrap();
        assert_eq!(unique_path(&a), dir.join("photo (2).png"));
        let noext = dir.join("data");
        std::fs::write(&noext, b"3").unwrap();
        assert_eq!(unique_path(&noext), dir.join("data (1)"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compress_policy_by_extension_and_mode() {
        assert!(should_compress("notes.txt", CompMode::Auto));
        assert!(should_compress("noext", CompMode::Auto));
        assert!(!should_compress("photo.PNG", CompMode::Auto));
        assert!(!should_compress("a.tar.zst", CompMode::Auto));
        assert!(!should_compress("video.mp4", CompMode::Never));
        assert!(should_compress("video.mp4", CompMode::Always));
        assert_eq!(CompMode::parse(" Auto "), Some(CompMode::Auto));
        assert_eq!(CompMode::parse("bogus"), None);
    }

    #[test]
    fn chunk_codec_roundtrip_and_fallback() {
        let mut enc = ChunkEncoder::new(true);
        let mut dec = ChunkDecoder::new();
        let mut zbuf = Vec::new();
        // compressible chunk → zstd wins
        let text: Vec<u8> = "airpipe ".repeat(16 * 1024).into_bytes();
        let (z, wire) = enc.encode(&text, &mut zbuf);
        assert!(z);
        assert!(wire.len() < text.len());
        assert_eq!(dec.decode(wire).unwrap(), &text[..]);
        // incompressible chunk → raw fallback, no copy
        let mut rs = 0x9e3779b9u32;
        let rnd: Vec<u8> = (0..crate::proto::CHUNK)
            .map(|_| {
                rs ^= rs << 13;
                rs ^= rs >> 17;
                rs ^= rs << 5;
                rs as u8
            })
            .collect();
        let (z, wire) = enc.encode(&rnd, &mut zbuf);
        assert!(!z);
        assert!(std::ptr::eq(wire.as_ptr(), rnd.as_ptr()));
        // disabled encoder is a passthrough
        let mut off = ChunkEncoder::new(false);
        let (z, wire) = off.encode(&text, &mut zbuf);
        assert!(!z);
        assert!(std::ptr::eq(wire.as_ptr(), text.as_ptr()));
        // oversize/garbage input is an error, not a panic
        assert!(dec.decode(b"not-a-zstd-frame").is_err());
    }

    #[test]
    fn inbound_roundtrip_hash_and_progress() {
        let dir = std::env::temp_dir().join(format!("airpipe-in-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ib = Inbound::new_file(dir.join("f.bin")).unwrap();
        let chunk = vec![7u8; 1024 * 1024]; // 1 MiB per D frame, progress at 4 MiB
        assert!(ib.data(&chunk).unwrap().is_none());
        assert!(ib.data(&chunk).unwrap().is_none());
        assert!(ib.data(&chunk).unwrap().is_none());
        assert_eq!(ib.data(&chunk).unwrap(), Some(4 * 1024 * 1024));
        let d = ib.finish().unwrap();
        let mut want_hasher = Sha256::new();
        for _ in 0..4 {
            want_hasher.update(&chunk);
        }
        let want: [u8; 32] = want_hasher.finalize().into();
        assert_eq!(d, want);
        assert!(ib.final_path.exists());
        assert!(!ib.part_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_chunks_hash_matches() {
        let dir = std::env::temp_dir().join(format!("airpipe-chunks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.bin");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &data).unwrap();
        let mut fc = FileChunks::open(&p).unwrap();
        let mut buf = Vec::new();
        let mut n = 0;
        while let Some(c) = fc.next(&mut buf).unwrap() {
            n += c.len();
        }
        assert_eq!(n, data.len());
        let want: [u8; 32] = Sha256::digest(&data).into();
        assert_eq!(fc.digest(), want);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_walks_sorted_with_dir_skeleton() {
        let dir = std::env::temp_dir().join(format!("airpipe-plan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("d/sub")).unwrap();
        std::fs::create_dir_all(dir.join("d/empty")).unwrap();
        std::fs::write(dir.join("d/b.txt"), b"b").unwrap();
        std::fs::write(dir.join("d/a.txt"), b"a").unwrap();
        std::fs::write(dir.join("d/sub/c.txt"), b"c").unwrap();
        let old = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let plan = plan(&[PathBuf::from("d")]).unwrap();
        std::env::set_current_dir(old).unwrap();
        let rels: Vec<(String, bool)> = plan
            .iter()
            .map(|e| match e {
                SendEntry::Dir { rel } => (rel.clone(), true),
                SendEntry::File { rel, .. } => (rel.clone(), false),
            })
            .collect();
        assert_eq!(
            rels,
            vec![
                ("d".into(), true),
                ("d/a.txt".into(), false),
                ("d/b.txt".into(), false),
                ("d/empty".into(), true),
                ("d/sub".into(), true),
                ("d/sub/c.txt".into(), false),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_uses_top_level_names_only() {
        let dir = std::env::temp_dir().join(format!("airpipe-top-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Airpipe/from_phone")).unwrap();
        std::fs::write(dir.join("Airpipe/from_phone/test.pdf"), b"pdf").unwrap();
        std::fs::write(dir.join("loose.txt"), b"t").unwrap();

        // absolute file arg → basename only, regardless of daemon cwd
        let file = dir.join("Airpipe/from_phone/test.pdf");
        let entries = plan(&[file.clone()]).unwrap();
        assert_eq!(
            entries,
            vec![SendEntry::File {
                abs: file,
                rel: "test.pdf".into(),
                size: 3,
            }]
        );

        // absolute dir arg → its own top dir name, structure inside
        let d = dir.join("Airpipe/from_phone");
        let entries = plan(&[d]).unwrap();
        let rels: Vec<String> = entries
            .into_iter()
            .map(|e| match e {
                SendEntry::Dir { rel } => rel,
                SendEntry::File { rel, .. } => rel,
            })
            .collect();
        assert_eq!(
            rels,
            vec!["from_phone".to_string(), "from_phone/test.pdf".to_string()]
        );

        // relative arg with directories in it → still basename only
        let old = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let entries = plan(&[PathBuf::from("Airpipe/from_phone/test.pdf")]).unwrap();
        std::env::set_current_dir(old).unwrap();
        assert!(matches!(&entries[0], SendEntry::File { rel, .. } if rel == "test.pdf"));

        // args without a usable file name fail fast
        assert!(plan(&[dir.join("..")]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod wire_chain {
    use super::*;
    use crate::proto::Frame;
    use sha2::{Digest, Sha256};

    /// 全链路往返：FileChunks → ChunkEncoder → Frame 编码/解码 → ChunkDecoder → sha。
    /// 不可压语料走 raw 回退路径，防 D 帧头/落盘偏移类回归（真机曾因偏移翻车）。
    #[test]
    fn full_wire_chain_incompressible() {
        let dir = std::env::temp_dir().join("ap-wire-tmp");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("r.bin");
        let mut rs = 0x12345678u32;
        let body: Vec<u8> = (0..300_000)
            .map(|_| {
                rs ^= rs << 13;
                rs ^= rs >> 17;
                rs ^= rs << 5;
                rs as u8
            })
            .collect();
        std::fs::write(&p, &body).unwrap();
        let mut expect = Sha256::new();
        expect.update(&body);

        let mut fc = FileChunks::open(&p).unwrap();
        let mut enc = ChunkEncoder::new(true);
        let mut dec = ChunkDecoder::new();
        let mut got = Sha256::new();
        let mut raw = Vec::new();
        let mut zbuf = Vec::new();
        let mut n_zstd = 0;
        let mut n_raw = 0;
        while let Some(chunk) = fc.next(&mut raw).unwrap() {
            let (z, wire) = enc.encode(chunk, &mut zbuf);
            if z {
                n_zstd += 1
            } else {
                n_raw += 1
            }
            let frame = Frame::FileData {
                id: 1,
                zstd: z,
                data: wire.to_vec(),
            };
            // 全帧编码（帧头+载荷）再解码，模拟线上往返
            let buf = frame.encode();
            let hdr = crate::proto::Frame::decode(b'D', &buf[5..]).unwrap();
            match hdr {
                Frame::FileData { data, zstd, .. } => {
                    let plain = if zstd {
                        dec.decode(&data).unwrap()
                    } else {
                        &data
                    };
                    got.update(plain);
                }
                _ => panic!("wrong frame"),
            }
        }
        println!("zstd chunks={n_zstd} raw chunks={n_raw}");
        let g: [u8; 32] = got.finalize().into();
        let e: [u8; 32] = expect.finalize().into();
        assert_eq!(g, e);
        std::fs::remove_file(&p).unwrap();
    }
}
