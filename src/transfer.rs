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
#[derive(Debug, Clone)]
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
/// rel paths preserve the top-level name (relative args keep their form;
/// absolute args are made relative to cwd when possible, else file_name).
pub fn plan(paths: &[PathBuf]) -> std::io::Result<Vec<SendEntry>> {
    let mut out = Vec::new();
    let cwd = std::env::current_dir().ok();
    for p in paths {
        let meta = std::fs::metadata(p)
            .map_err(|e| std::io::Error::other(format!("{}: {e}", p.display())))?;
        if !meta.is_dir() && !meta.is_file() {
            return Err(std::io::Error::other(format!(
                "{}: not a regular file or dir",
                p.display()
            )));
        }
        let top_rel = rel_of(p, cwd.as_deref());
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

fn rel_of(p: &Path, cwd: Option<&Path>) -> String {
    let rel: PathBuf = if p.is_absolute() {
        match cwd.and_then(|c| p.strip_prefix(c).ok()) {
            Some(r) => r.to_path_buf(),
            None => p
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| p.to_path_buf()),
        }
    } else {
        p.components().collect()
    };
    sanitize_rel(&rel.to_string_lossy())
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
}
