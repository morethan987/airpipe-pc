//! wlr-data-control clipboard via lamco-data-control (probe-verified usage).

use std::sync::Arc;

use lamco_data_control::{Content, DataControl};

use super::ClipboardBackend;

pub struct WaylandClipboard {
    dc: Arc<DataControl>,
}

impl WaylandClipboard {
    pub fn connect() -> Result<Self, String> {
        let dc = DataControl::connect().map_err(|e| format!("wayland clipboard: {e}"))?;
        Ok(Self { dc: Arc::new(dc) })
    }
}

impl ClipboardBackend for WaylandClipboard {
    fn read(&self, mime: &str) -> Result<Option<Vec<u8>>, String> {
        self.dc
            .read(mime)
            .map_err(|e| format!("clipboard read {mime}: {e}"))
    }

    fn set_selection(&self, mime: &str, data: Vec<u8>) -> Result<(), String> {
        self.dc
            .set_selection(Content::new().data(mime.to_owned(), data))
            .map_err(|e| format!("clipboard write: {e}"))
    }

    fn on_change(&self, f: Box<dyn Fn(Vec<String>) + Send + Sync + 'static>) {
        self.dc.on_change(f);
    }
}
