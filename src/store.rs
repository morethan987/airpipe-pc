//! Persistence for `paired.json` (protocol.md §4). The identity certificate
//! lives in net.rs; this module only knows the device list.

use std::path::PathBuf;

use crate::config;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PairedDevice {
    pub name: String,
    pub fingerprint: String,
    pub paired_at: String,
    #[serde(default)]
    pub last_ip: Option<String>,
    #[serde(default)]
    pub last_seen: Option<String>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct DeviceList {
    pub devices: Vec<PairedDevice>,
}

pub fn paired_path() -> PathBuf {
    config::state_dir().join("paired.json")
}

pub fn load_devices() -> DeviceList {
    match std::fs::read_to_string(paired_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => DeviceList::default(),
    }
}

pub fn save_devices(list: &DeviceList) -> std::io::Result<()> {
    let dir = config::state_dir();
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join("paired.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(list).unwrap())?;
    std::fs::rename(tmp, paired_path())
}

/// Local RFC3339-ish timestamp (no external chrono dependency).
pub fn now_ts() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // civil-from-days algorithm (Howard Hinnant), UTC+0 offset to keep it simple
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}+00:00")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_devices() {
        let list = DeviceList {
            devices: vec![PairedDevice {
                name: "mi-13p".into(),
                fingerprint: "ab".repeat(32),
                paired_at: now_ts(),
                last_ip: Some("192.168.0.23".into()),
                last_seen: None,
            }],
        };
        let s = serde_json::to_string(&list).unwrap();
        let back: DeviceList = serde_json::from_str(&s).unwrap();
        assert_eq!(back.devices.len(), 1);
        assert_eq!(back.devices[0].fingerprint, "ab".repeat(32));
        // last_seen absent in old files deserializes to None
        let legacy =
            r#"{"devices":[{"name":"x","fingerprint":"f","paired_at":"t","last_ip":null}]}"#;
        let l: DeviceList = serde_json::from_str(legacy).unwrap();
        assert_eq!(l.devices[0].last_seen, None);
    }
}
