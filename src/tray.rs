//! System tray (ksni / StatusNotifierItem). Icon pixmaps are baked from
//! assets/tray_icon.png by build.rs into ARGB32 (network byte order).

use ksni::blocking::TrayMethods;
use ksni::menu::StandardItem;
use ksni::{MenuItem, Tray};
use std::sync::Arc;

use crate::daemon::Shared;

pub struct AirTray {
    pub shared: Arc<Shared>,
}

/// 32x32 ARGB32 (network byte order) pixmap baked from assets/tray_icon.png.
fn icon_32() -> ksni::Icon {
    ksni::Icon {
        width: 32,
        height: 32,
        data: include_bytes!(concat!(env!("OUT_DIR"), "/tray_icon_32.argb")).to_vec(),
    }
}

/// 64x64 ARGB32 (network byte order) pixmap baked from assets/tray_icon.png.
fn icon_64() -> ksni::Icon {
    ksni::Icon {
        width: 64,
        height: 64,
        data: include_bytes!(concat!(env!("OUT_DIR"), "/tray_icon_64.argb")).to_vec(),
    }
}

impl Tray for AirTray {
    fn id(&self) -> String {
        "airpipe".into()
    }
    fn title(&self) -> String {
        "Airpipe".into()
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![icon_32(), icon_64()]
    }

    fn watcher_online(&self) {
        alog!(Info, "tray: registered to the StatusNotifierWatcher");
    }

    /// true = keep the service and (re)register once the watcher (the status
    /// bar) shows up — it may start after us (boot race) or restart at any
    /// time.
    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        alog!(
            Warn,
            "tray: StatusNotifierWatcher offline ({reason:?}), waiting for the bar"
        );
        true
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            MenuItem::Standard(StandardItem {
                label: self.status_line(),
                enabled: false,
                ..StandardItem::default()
            }),
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "发送剪贴板文件".into(),
                activate: Box::new(|t: &mut Self| match t.shared.collect_clip_files() {
                    Ok(paths) => {
                        let n = paths.len();
                        t.shared.queue.push_files(paths);
                        t.shared.notify("Airpipe", &format!("已入队 {n} 个文件"));
                    }
                    Err(e) => t.shared.notify("Airpipe", &e),
                }),
                ..StandardItem::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "配对新设备".into(),
                activate: Box::new(|t: &mut Self| {
                    let shared = t.shared.clone();
                    let code = shared.open_pair_window(crate::pairing::default_window());
                    shared.notify("Airpipe 配对", &format!("在手机上输入配对码：{code}"));
                }),
                ..StandardItem::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "打开收件目录".into(),
                activate: Box::new(|t: &mut Self| {
                    let dir = t.shared.cfg.inbound_dir();
                    let _ = std::fs::create_dir_all(&dir);
                    let _ = std::process::Command::new("xdg-open").arg(&dir).spawn();
                }),
                ..StandardItem::default()
            }),
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "退出".into(),
                activate: Box::new(|t: &mut Self| t.shared.request_stop()),
                ..StandardItem::default()
            }),
        ]
    }
}

impl AirTray {
    fn status_line(&self) -> String {
        if self.shared.pair().is_open() {
            return "📡 Airpipe — 配对窗口中".into();
        }
        match self.shared.session.lock().unwrap().as_ref() {
            Some(s) => format!("📡 Airpipe — 已连接 {}", s.name.lock().unwrap()),
            None => "📡 Airpipe — 离线".into(),
        }
    }
}

pub fn spawn(shared: Arc<Shared>) -> Result<(), String> {
    let tray = AirTray {
        shared: shared.clone(),
    };

    // We may start before the bar registers its StatusNotifierWatcher (boot
    // race: niri spawns the bar around the moment graphical-session.target
    // fires). Plain spawn() fails permanently in that case, so treat a missing
    // watcher as soft-offline and let ksni (re)register whenever it appears.
    let handle = tray
        .assume_sni_available(true)
        .spawn()
        .map_err(|e| e.to_string())?;

    // Wire Shared::tray_refresh: re-read Tray properties and emit the update
    // signals hosts listen for (menu status line).
    let h = handle.clone();
    shared
        .tray
        .lock()
        .unwrap()
        .replace(Box::new(move || match h.update(|_t: &mut AirTray| ()) {
            Some(()) => alog!(Debug, "tray: refreshed"),
            None => alog!(Warn, "tray: refresh skipped (service down?)"),
        }));

    Ok(())
}
