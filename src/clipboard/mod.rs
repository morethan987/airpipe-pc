//! Clipboard backend abstraction. Only the Wayland (wlr-data-control)

pub mod classify;
pub mod wayland;

pub trait ClipboardBackend: Send + Sync {
    /// Read one MIME rendition of the current selection.
    fn read(&self, mime: &str) -> Result<Option<Vec<u8>>, String>;
    /// Take the selection with a single (mime, bytes) rendition.
    fn set_selection(&self, mime: &str, data: Vec<u8>) -> Result<(), String>;
    /// Register a callback fired with the offered MIME list whenever another
    /// client becomes the selection owner. Callbacks must not block; the
    /// wayland backend already dispatches them on its internal thread, the
    /// watcher moves the actual read to a fresh thread.
    fn on_change(&self, f: Box<dyn Fn(Vec<String>) + Send + Sync + 'static>);
}

/// Connect to the session clipboard; errors gracefully on headless systems.
pub fn connect() -> Result<Box<dyn ClipboardBackend>, String> {
    wayland::WaylandClipboard::connect().map(|c| Box::new(c) as Box<dyn ClipboardBackend>)
}
