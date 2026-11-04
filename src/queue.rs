//! Outbound reference queue (protocol.md §8): entries hold only references
//! (text/image bytes are small enough to carry; files are local paths),
//! clipboard entries merge to the newest, file paths dedupe, never persisted.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;

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
}

impl OutQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clipboard entries merge: only the newest survives (clipboard
    /// semantics, §8 — repeated text syncs keep just the latest).
    pub fn push_clip(&self, image: bool, mime: String, data: Vec<u8>) {
        let mut q = self.items.lock().unwrap();
        q.retain(|i| !matches!(i, Item::Clip { .. }));
        q.push_back(Item::Clip { image, mime, data });
    }

    /// FIFO append; paths already queued are dropped (dedup across items).
    pub fn push_files(&self, paths: Vec<PathBuf>) {
        let mut q = self.items.lock().unwrap();
        let mut existing: Vec<PathBuf> = q
            .iter()
            .flat_map(|i| match i {
                Item::Files(ps) => ps.clone(),
                _ => Vec::new(),
            })
            .collect();
        let fresh: Vec<PathBuf> = paths
            .into_iter()
            .filter(|p| {
                if existing.contains(p) {
                    false
                } else {
                    existing.push(p.clone());
                    true
                }
            })
            .collect();
        if !fresh.is_empty() {
            q.push_back(Item::Files(fresh));
        }
    }

    /// Take the whole queue for pumping (called when the phone is online).
    pub fn drain(&self) -> Vec<Item> {
        let mut q = self.items.lock().unwrap();
        q.drain(..).collect()
    }

    /// Put items back (front, in order) after a send failure.
    pub fn requeue_front(&self, mut items: Vec<Item>) {
        let mut q = self.items.lock().unwrap();
        items.reverse();
        for it in items {
            q.push_front(it);
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
    fn duplicate_paths_dropped() {
        let q = OutQueue::new();
        let a = PathBuf::from("/tmp/a.jpg");
        q.push_files(vec![a.clone(), PathBuf::from("/tmp/b/")]);
        q.push_files(vec![a.clone(), PathBuf::from("/tmp/c.txt")]);
        assert_eq!(
            q.drain(),
            vec![
                Item::Files(vec![PathBuf::from("/tmp/a.jpg"), PathBuf::from("/tmp/b/")]),
                Item::Files(vec![PathBuf::from("/tmp/c.txt")]),
            ],
            "duplicate /tmp/a.jpg dropped, new /tmp/c.txt forms its own FIFO item"
        );
    }

    #[test]
    fn partially_new_paths_form_new_item() {
        let q = OutQueue::new();
        q.push_files(vec![PathBuf::from("/f1")]);
        q.push_files(vec![PathBuf::from("/f1"), PathBuf::from("/f2")]);
        let d = q.drain();
        assert_eq!(d.len(), 2);
        assert_eq!(d[1], Item::Files(vec![PathBuf::from("/f2")]));
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
