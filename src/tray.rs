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

    // Spawns the tray service in the background and returns a handle (currently unused)
    // for potential future UI updates. Converts spawn errors to a String and returns early.
    let _handle = tray.spawn().map_err(|e| e.to_string())?;

    Ok(())
}
