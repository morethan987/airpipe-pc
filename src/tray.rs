//! System tray (ksni / StatusNotifierItem). Icon is a generated 32x32 ARGB32
//! placeholder pixmap until a proper icon lands.

use std::sync::Arc;

use ksni::menu::StandardItem;
use ksni::{MenuItem, Tray, TrayService};

use crate::daemon::Shared;

pub struct AirTray {
    pub shared: Arc<Shared>,
}

/// 32x32 ARGB32 (network byte order) placeholder: blue circle on dark slate.
fn placeholder_icon() -> ksni::Icon {
    const W: i32 = 32;
    const H: i32 = 32;
    let mut data = Vec::with_capacity((W * H * 4) as usize);
    for y in 0..H {
        for x in 0..W {
            let dx = x - 16;
            let dy = y - 16;
            let inside = dx * dx + dy * dy <= 81;
            let (r, g, b) = if inside {
                (0x2d, 0x96, 0xcf)
            } else {
                (0x1e, 0x1e, 0x28)
            };
            data.extend_from_slice(&[0xff, r, g, b]);
        }
    }
    ksni::Icon {
        width: W,
        height: H,
        data,
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
        vec![placeholder_icon()]
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
    let service = TrayService::new(AirTray {
        shared: shared.clone(),
    });
    let handle = service.handle();
    *shared.tray.lock().unwrap() = Some(Box::new(move || handle.update(|_t: &mut AirTray| {})));
    service.spawn();
    Ok(())
}
