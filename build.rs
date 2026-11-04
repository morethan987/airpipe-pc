//! Bakes `assets/tray_icon.png` into 32/64 px ARGB32 (network byte order)
//! pixmaps for the ksni tray icon. See src/tray.rs.

use image::imageops::{resize, FilterType};
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=assets/tray_icon.png");
    let src = image::open("assets/tray_icon.png")
        .expect("open assets/tray_icon.png")
        .to_rgba8();
    for px in [32u32, 64] {
        let scaled = resize(&src, px, px, FilterType::Lanczos3);
        let mut argb = Vec::with_capacity((px * px * 4) as usize);
        for p in scaled.pixels() {
            argb.extend_from_slice(&[p[3], p[0], p[1], p[2]]);
        }
        let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join(format!("tray_icon_{px}.argb"));
        fs::write(&out, argb).expect("write tray icon pixmap");
    }
}
