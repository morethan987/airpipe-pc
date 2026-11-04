//! Configuration (`~/.config/airpipe/config.toml`), all-fields-optional with
//! the defaults from cli.md.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ClipboardCfg {
    pub auto_text: bool,
    pub auto_image: bool,
    pub max_image_mb: u64,
}

impl Default for ClipboardCfg {
    fn default() -> Self {
        Self {
            auto_text: true,
            // off by default: pushing a copied screenshot/image to the
            // phone unprompted is surprising; opt in via config
            auto_image: false,
            max_image_mb: 20,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Config {
    pub port: Option<u16>,
    pub device_name: Option<String>,
    pub recv_dir: Option<String>,
    pub clipboard: ClipboardCfg,
}

impl Config {
    /// Effective values after defaults are applied.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(crate::proto::TCP_PORT)
    }
    pub fn device_name(&self) -> String {
        self.device_name.clone().unwrap_or_else(|| {
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|s| s.trim().to_owned())
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "pc".to_owned())
        })
    }
    pub fn recv_dir(&self) -> PathBuf {
        expand_tilde(self.recv_dir.as_deref().unwrap_or("~/Airpipe"))
    }
    pub fn inbound_dir(&self) -> PathBuf {
        self.recv_dir().join("from_phone")
    }
}

pub fn config_path() -> PathBuf {
    home().join(".config/airpipe/config.toml")
}

pub fn state_dir() -> PathBuf {
    home().join(".local/state/airpipe")
}

pub fn sock_path() -> PathBuf {
    match std::env::var("XDG_RUNTIME_DIR") {
        Ok(d) => PathBuf::from(d).join("airpipe/daemon.sock"),
        Err(_) => PathBuf::from(format!("/tmp/airpipe-{}.sock", uid())),
    }
}

fn uid() -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(0)
}

pub fn home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Expand a leading `~/` (and bare `~`) to $HOME.
pub fn expand_tilde(p: &str) -> PathBuf {
    if p == "~" {
        return home();
    }
    if let Some(rest) = p.strip_prefix("~/") {
        return home().join(rest);
    }
    PathBuf::from(p)
}

pub fn load() -> (Config, Option<String>) {
    let path = config_path();
    if !path.exists() {
        return (Config::default(), None);
    }
    match std::fs::read_to_string(&path) {
        Ok(s) => match toml::from_str(&s) {
            Ok(c) => (c, None),
            Err(e) => (
                Config::default(),
                Some(format!("config parse error: {e}; using defaults")),
            ),
        },
        Err(e) => (
            Config::default(),
            Some(format!("config unreadable: {e}; using defaults")),
        ),
    }
}

/// Path with `~` collapsed for display.
pub fn display(p: &Path) -> String {
    let h = home();
    if let Ok(rest) = p.strip_prefix(&h) {
        format!("~/{}", rest.display())
    } else {
        p.display().to_string()
    }
}
