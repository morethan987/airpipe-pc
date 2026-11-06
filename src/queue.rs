//! Outbound reference queue (protocol.md §8): entries hold only references
//! (text/image bytes are small enough to carry; files are local paths),
//! clipboard entries merge to the newest, never persisted. Every
//! `push_files` call is one FIFO entry — re-sending a path must deliver
//! another copy, so paths dedupe only within a single push, never across
//! entries.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A clipboard payload (text or image) as raw bytes.
    Clip {
        image: bool,
        mime: String,
        data: Vec<u8>,
    },
    Files(Vec<PathBuf>),
}

#[derive(Default)]
pub struct OutQueue {
    items: Mutex<VecDeque<Item>>,
    /// Woken on every push/requeue so an idle pump picks items up at once
    /// (a pump that drained to empty sleeps on this instead of exiting).
    cv: Condvar,
}

impl OutQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clipboard entries merge: only the newest survives (clipboard
    /// semantics, §8 — repeated text syncs keep just the latest).
    pub fn push_clip(&self, image: bool, mime: String, data: Vec<u8>) {
        {
            let mut q = self.items.lock().unwrap();
            q.retain(|i| !matches!(i, Item::Clip { .. }));
            q.push_back(Item::Clip { image, mime, data });
        }
        self.cv.notify_all();
    }

    /// FIFO append; duplicate paths within one push collapse (one user
    /// action = one set), but a path already queued by an earlier push is
    /// kept — re-sending must deliver another copy (receiver renames, §7).
    /// Returns the number of paths actually enqueued.
    pub fn push_files(&self, paths: Vec<PathBuf>) -> usize {
        let mut seen: HashSet<PathBuf> = HashSet::new();
        let fresh: Vec<PathBuf> = paths
            .into_iter()
            .filter(|p| seen.insert(p.clone()))
            .collect();
        let n = fresh.len();
        if n == 0 {
            return 0;
        }
        {
            let mut q = self.items.lock().unwrap();
            q.push_back(Item::Files(fresh));
        }
        self.cv.notify_all();
        n
    }

    /// Take the whole queue for pumping (called when the phone is online).
    pub fn drain(&self) -> Vec<Item> {
        let mut q = self.items.lock().unwrap();
        q.drain(..).collect()
    }

    /// Put items back (front, in order) after a send failure.
    pub fn requeue_front(&self, mut items: Vec<Item>) {
        {
            let mut q = self.items.lock().unwrap();
            items.reverse();
            for it in items {
                q.push_front(it);
            }
        }
        self.cv.notify_all();
    }

    /// Block until an item arrives or `until` passes (idle pump wait).
    pub fn wait_until(&self, until: std::time::Instant) {
        let mut q = self.items.lock().unwrap();
        while q.is_empty() {
            let now = std::time::Instant::now();
            if now >= until {
                return;
            }
            let (g, _) = self.cv.wait_timeout(q, until - now).unwrap();
            q = g;
        }
    }

    /// (clips, files, bytes) for IPC status.
    pub fn stats(&self) -> (usize, usize, u64) {
        let q = self.items.lock().unwrap();
        let mut clips = 0usize;
        let mut files = 0usize;
        let mut bytes = 0u64;
        for i in q.iter() {
            match i {
                Item::Clip { data, .. } => {
                    clips += 1;
                    bytes += data.len() as u64;
                }
                Item::Files(ps) => {
                    files += ps.len();
                    for p in ps {
                        if let Ok(m) = std::fs::metadata(p) {
                            bytes += m.len();
                        }
                    }
                }
            }
        }
        (clips, files, bytes)
    }

    pub fn is_empty(&self) -> bool {
        self.items.lock().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clips_merge_to_newest() {
        let q = OutQueue::new();
        q.push_clip(false, "text/plain".into(), b"one".to_vec());
        q.push_clip(false, "text/plain".into(), b"two".to_vec());
        q.push_clip(false, "text/plain".into(), b"three".to_vec());
        // an image supersedes pending text too (one clipboard, one payload)
        q.push_clip(true, "image/png".into(), vec![1, 2]);
        let drained = q.drain();
        assert_eq!(
            drained,
            vec![Item::Clip {
                image: true,
                mime: "image/png".into(),
                data: vec![1, 2]
            }]
        );
    }

    #[test]
    fn same_push_duplicates_collapse() {
        let q = OutQueue::new();
        let a = PathBuf::from("/tmp/a.jpg");
        let n = q.push_files(vec![a.clone(), a, PathBuf::from("/tmp/b/")]);
        assert_eq!(
            n, 2,
            "duplicate within one push collapsed, count reflects it"
        );
        assert_eq!(
            q.drain(),
            vec![Item::Files(vec![
                PathBuf::from("/tmp/a.jpg"),
                PathBuf::from("/tmp/b/")
            ])]
        );
    }

    #[test]
    fn resend_same_path_queues_again() {
        // Regression: 5 × `ap send same.pdf` while a copy is queued or in
        // flight must enqueue 5 entries — cross-entry dedup silently
        // dropped re-sends (receiver renames duplicates, §7).
        let q = OutQueue::new();
        let a = PathBuf::from("/tmp/2511.pdf");
        for _ in 0..5 {
            assert_eq!(q.push_files(vec![a.clone()]), 1);
        }
        let drained = q.drain();
        assert_eq!(drained.len(), 5);
        assert!(drained.iter().all(|i| *i == Item::Files(vec![a.clone()])));
    }

    #[test]
    fn requeue_preserves_order() {
        let q = OutQueue::new();
        q.push_clip(false, "text/plain".into(), b"x".to_vec());
        q.push_files(vec![PathBuf::from("/f")]);
        let items = q.drain();
        q.requeue_front(items);
        let again = q.drain();
        assert_eq!(again.len(), 2);
        assert!(matches!(again[0], Item::Clip { .. }));
    }

    #[test]
    fn clip_survives_between_files() {
        let q = OutQueue::new();
        q.push_files(vec![PathBuf::from("/f1")]);
        q.push_clip(false, "text/plain".into(), b"t1".to_vec());
        q.push_clip(false, "text/plain".into(), b"t2".to_vec());
        q.push_files(vec![PathBuf::from("/f2")]);
        let d = q.drain();
        assert_eq!(d.len(), 3);
        assert!(matches!(d[1], Item::Clip { .. }));
    }
}
