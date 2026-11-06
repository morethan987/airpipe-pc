//! Clipboard change monitoring and automatic synchronization.

use std::sync::Arc;

use crate::clipboard::{ClipboardBackend, classify};

use super::state::Shared;
use super::util::{content_hash, human_size, image_cap};

pub(super) fn spawn_clipboard_watcher(shared: Arc<Shared>, clip: Arc<dyn ClipboardBackend>) {
    // The lamco callback runs on the crate's internal Wayland thread and
    // must not block (read() round-trips through that same thread), so the
    // actual read moves to a fresh thread, exactly like the probe.
    clip.on_change(Box::new(move |mimes| {
        let shared = shared.clone();
        std::thread::spawn(move || on_selection(&shared, mimes));
    }));
}

fn on_selection(shared: &Arc<Shared>, mimes: Vec<String>) {
    if mimes.is_empty() {
        return;
    }
    alog!(Debug, "clipboard event: {mimes:?}");
    let kind = classify::classify(&mimes);
    let clip = match shared.clip.as_ref() {
        Some(c) => c,
        None => return,
    };
    let cc = &shared.cfg.clipboard;
    match kind {
        classify::SelectionKind::Sensitive => {
            alog!(
                Info,
                "clipboard: sensitive (password-manager hint), skipped"
            );
        }
        classify::SelectionKind::Files { .. } => {
            alog!(
                Debug,
                "clipboard: file refs, not auto-synced (use tray/IPC)"
            );
        }
        classify::SelectionKind::Image { mime } => {
            if !cc.auto_image {
                return;
            }
            let Ok(Some(bytes)) = clip.read(&mime) else {
                return;
            };
            let cap = image_cap(cc.max_image_mb);
            if bytes.len() > cap {
                alog!(
                    Info,
                    "clipboard image {} > {} MiB cap, skipped",
                    human_size(bytes.len() as u64),
                    cc.max_image_mb
                );
                return;
            }
            if shared
                .echo
                .lock()
                .unwrap()
                .contains(content_hash(&mime, &bytes))
            {
                return;
            }
            alog!(
                Info,
                "clipboard → queue: image {mime} ({})",
                human_size(bytes.len() as u64)
            );
            shared.queue.push_clip(true, mime, bytes);
        }
        classify::SelectionKind::RichText { plain, .. } => {
            if !cc.auto_text {
                return;
            }
            let Some(mime) = plain else { return };
            let Ok(Some(bytes)) = clip.read(&mime) else {
                return;
            };
            if shared
                .echo
                .lock()
                .unwrap()
                .contains(content_hash(&mime, &bytes))
            {
                return;
            }
            shared.queue.push_clip(false, mime, bytes);
        }
        classify::SelectionKind::PlainText { mime } => {
            if !cc.auto_text {
                return;
            }
            let bytes = match clip.read(&mime) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    alog!(Debug, "clipboard: text offer gone, skipped");
                    return;
                }
                Err(e) => {
                    alog!(Debug, "clipboard: text read failed: {e}");
                    return;
                }
            };
            if shared
                .echo
                .lock()
                .unwrap()
                .contains(content_hash(&mime, &bytes))
            {
                return;
            }
            alog!(
                Info,
                "clipboard → phone: text ({})",
                human_size(bytes.len() as u64)
            );
            shared.queue.push_clip(false, mime, bytes);
        }
        classify::SelectionKind::Passthrough { mimes } => {
            if !cc.auto_text {
                return;
            }
            if let Some(tm) = mimes.iter().find(|m| m.starts_with("text/"))
                && let Ok(Some(bytes)) = clip.read(tm)
                && !shared
                    .echo
                    .lock()
                    .unwrap()
                    .contains(content_hash(tm, &bytes))
            {
                shared.queue.push_clip(false, tm.clone(), bytes);
                return;
            }

            alog!(
                Info,
                "clipboard: no syncable rendition among {mimes:?}, skipped"
            );
        }
    }
}
