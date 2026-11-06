//! `ap` — Airpipe PC CLI + daemon entry point.

use std::{io, process::ExitCode};

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};

// ------------------------------------------------------------------ log ----

static LOG_LEVEL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(2); // Info

pub const L_WARN: u8 = 1;
pub const L_INFO: u8 = 2;
pub const L_DEBUG: u8 = 3;

pub fn log_line(level: u8, args: std::fmt::Arguments<'_>) {
    if level > LOG_LEVEL.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tag = match level {
        L_WARN => "WARN",
        L_INFO => "info",
        _ => "dbg ",
    };
    eprintln!("[{ts:>10} {tag}] {args}");
}

#[macro_export]
macro_rules! alog {
    (Warn, $($t:tt)*) => { $crate::log_line($crate::L_WARN, format_args!($($t)*)) };
    (Info, $($t:tt)*) => { $crate::log_line($crate::L_INFO, format_args!($($t)*)) };
    (Debug, $($t:tt)*) => { $crate::log_line($crate::L_DEBUG, format_args!($($t)*)) };
}

mod cli;
mod clipboard;
mod config;
mod daemon;
mod discovery;
mod ipc;
mod net;
mod pairing;
mod proto;
mod queue;
mod store;
mod transfer;
mod tray;

// ------------------------------------------------------------------ cli ----

#[derive(Parser)]
#[command(
    name = "ap",
    about = "Airpipe: PC ↔ phone clipboard/file pipe",
    arg_required_else_help = true,
    version
)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// start the daemon (foreground; systemd owns autostart)
    Daemon {
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        no_tray: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// daemon status
    Status,
    /// open a pairing window and wait for the phone
    Pair {
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// list paired devices
    Devices,
    /// remove a pairing by name (or --all)
    Unpair {
        name: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// send files/dirs (`-` = stdin); `--clipboard` sends the files copied
    /// in the clipboard (tray equivalent)
    Send {
        #[arg(value_hint = clap::ValueHint::FilePath)]
        paths: Vec<String>,
        #[arg(short, long)]
        clipboard: bool,
    },
    /// push text to the phone (reads stdin without an argument)
    Text { text: Option<String> },
    /// follow daemon logs (journalctl)
    Log {
        #[arg(short, long)]
        follow: bool,
    },
    /// gracefully stop the daemon
    Stop,
    /// show effective config / open editor
    Config {
        #[arg(long)]
        edit: bool,
    },
    /// version info
    Version,
    /// Generate shell completion scripts
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();
    let code = match args.cmd {
        Cmd::Status => cmd_status(),
        Cmd::Pair { timeout } => cmd_pair(timeout),
        Cmd::Devices => cmd_devices(),
        Cmd::Unpair { name, all } => cmd_unpair(name, all),
        Cmd::Send { paths, clipboard } => cmd_send(&paths, clipboard),
        Cmd::Text { text } => cmd_text(text),
        Cmd::Log { follow } => cmd_log(follow),
        Cmd::Stop => cmd_stop(),
        Cmd::Config { edit } => cmd_config(edit),
        Cmd::Completions { shell } => cmd_completions(shell),
        Cmd::Daemon {
            port,
            no_tray,
            verbose,
        } => cmd_daemon(port, no_tray, verbose),
        Cmd::Version => {
            println!(
                "ap {} (protocol v{})",
                env!("CARGO_PKG_VERSION"),
                proto::PROTO_VER
            );
            0
        }
    };
    ExitCode::from(code)
}

fn cmd_completions(shell: Shell) -> u8 {
    let mut cmd = Args::command();
    generate(shell, &mut cmd, "ap", &mut io::stdout());
    0
}

fn ipc() -> Result<cli::Ipc, u8> {
    cli::Ipc::connect().map_err(|e| {
        eprintln!("ap: {e}，please run `ap daemon`.");
        2u8
    })
}

fn cmd_daemon(port: Option<u16>, no_tray: bool, verbose: bool) -> u8 {
    if verbose {
        LOG_LEVEL.store(L_DEBUG, std::sync::atomic::Ordering::Relaxed);
    }
    let (mut cfg, warn) = config::load();
    if let Some(w) = warn {
        eprintln!("ap: {w}");
    }
    if let Some(p) = port {
        cfg.port = Some(p);
    }
    let code = daemon::run(cfg, verbose, no_tray);
    std::process::exit(code);
}

fn cmd_status() -> u8 {
    let Ok(mut c) = ipc() else { return 2 };
    let st = match c.request(serde_json::json!({"cmd": "status"})) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ap: {e}");
            return 1;
        }
    };
    if st.get("ok").and_then(|o| o.as_bool()) != Some(true) {
        eprintln!("ap: {}", st.get("error").cloned().unwrap_or_default());
        return 1;
    }
    let up = st["uptime_s"].as_u64().unwrap_or(0);
    println!("运行时长   {} ({})", up, humantime(up));
    match &st["phone"] {
        serde_json::Value::Null => println!("手机       未连接"),
        p => println!(
            "手机       已连接 {} ({})，在线 {}",
            p["name"].as_str().unwrap_or("?"),
            p["ip"].as_str().unwrap_or("?"),
            humantime(p["since_s"].as_u64().unwrap_or(0))
        ),
    }
    let q = &st["queue"];
    println!(
        "队列       文本 {} / 文件 {} / {}",
        q["texts"].as_u64().unwrap_or(0),
        q["files"].as_u64().unwrap_or(0),
        daemon::human_size(q["bytes"].as_u64().unwrap_or(0))
    );
    let paired = st["paired"].as_array().cloned().unwrap_or_default();
    if paired.is_empty() {
        println!("已配对     （无 — `ap pair` 添加设备）");
    } else {
        println!("已配对     {}", paired.len());
    }
    println!("收件目录   {}", st["recv_dir"].as_str().unwrap_or("?"));
    println!("端口       {}", st["port"].as_u64().unwrap_or(0));
    0
}

fn humantime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, secs % 3600 / 60)
    }
}

fn cmd_devices() -> u8 {
    let Ok(mut c) = ipc() else { return 2 };
    let st = match c.request(serde_json::json!({"cmd": "status"})) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ap: {e}");
            return 1;
        }
    };
    let paired = st["paired"].as_array().cloned().unwrap_or_default();
    if paired.is_empty() {
        println!("（尚未配对任何设备，`ap pair` 开始）");
        return 0;
    }
    for d in paired {
        println!(
            "{:<20} {}  {}  {}",
            d["name"].as_str().unwrap_or("?"),
            &d["fingerprint"].as_str().unwrap_or("?")[..16],
            d["last_ip"].as_str().unwrap_or("-"),
            d["last_seen"].as_str().unwrap_or("-")
        );
    }
    0
}

fn cmd_pair(timeout: Option<u64>) -> u8 {
    let Ok(mut c) = ipc() else { return 2 };
    let req = serde_json::json!({"cmd": "pair", "timeout": timeout.unwrap_or(60)});
    if let Err(e) = c.send_raw(&req.to_string()) {
        eprintln!("ap: {e}");
        return 1;
    }
    let mut got_code = false;
    loop {
        match c.recv() {
            Ok(v) => {
                if let Some(code) = v.get("code").and_then(|c| c.as_str()) {
                    got_code = true;
                    println!("配对码：{code}");
                    println!(
                        "在手机 Airpipe 配对页输入此码（{} 秒内）",
                        v.get("timeout").and_then(|t| t.as_u64()).unwrap_or(60)
                    );
                } else if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
                    println!("配对成功：{name}");
                    return 0;
                } else if v.get("ok").and_then(|o| o.as_bool()) == Some(true) {
                    return 0;
                } else {
                    eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
                    return 1;
                }
            }
            Err(e) => {
                if got_code && matches!(e, cli::IpcError::NotRunning | cli::IpcError::Io(_)) {
                    // daemon closed the stream when the window ended
                }
                eprintln!("ap: {e}");
                return 1;
            }
        }
    }
}

fn cmd_unpair(name: Option<String>, all: bool) -> u8 {
    if !all && name.is_none() {
        eprintln!("ap: 指定设备名或 --all");
        return 1;
    }
    let Ok(mut c) = ipc() else { return 2 };
    let target = name.unwrap_or_else(|| "all".into());
    match c.request(serde_json::json!({"cmd": "unpair", "name": target})) {
        Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => {
            println!("已删除配对：{target}");
            0
        }
        Ok(v) => {
            eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
            1
        }
        Err(e) => {
            eprintln!("ap: {e}");
            1
        }
    }
}

/// Parenthetical after 「已入队 N 项」: reflects the daemon-reported phone
/// state instead of always claiming the phone is offline.
fn queue_hint(v: &serde_json::Value) -> String {
    match v.get("online").and_then(|o| o.as_bool()) {
        Some(true) => "（手机在线，正在发送）".into(),
        Some(false) => "（手机离线，上线后自动发送）".into(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::queue_hint;
    use serde_json::json;

    #[test]
    fn queue_hint_reflects_online_state() {
        assert_eq!(
            queue_hint(&json!({"online": true})),
            "（手机在线，正在发送）"
        );
        assert_eq!(
            queue_hint(&json!({"online": false})),
            "（手机离线，上线后自动发送）"
        );
        assert_eq!(queue_hint(&json!({})), "");
    }
}

fn cmd_send(paths: &[String], clipboard: bool) -> u8 {
    if clipboard {
        if !paths.is_empty() {
            eprintln!("ap: --clipboard 不能与路径参数同时使用");
            return 1;
        }
        let Ok(mut c) = ipc() else { return 2 };
        return match c.request(serde_json::json!({"cmd": "send_clip_files"})) {
            Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => {
                println!(
                    "已入队 {} 个剪贴板文件{}",
                    v["queued"].as_u64().unwrap_or(0),
                    queue_hint(&v)
                );
                0
            }
            Ok(v) => {
                eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
                1
            }
            Err(e) => {
                eprintln!("ap: {e}");
                1
            }
        };
    }
    if paths.is_empty() {
        eprintln!("ap: ap send <路径...>（`-` = stdin；`-c/--clipboard` = 发送剪贴板复制的文件）");
        return 1;
    }
    let Ok(mut c) = ipc() else { return 2 };
    if paths.len() == 1 && paths[0] == "-" {
        return match c.stream_stdin() {
            Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => {
                println!("已入队（stdin）");
                0
            }
            Ok(v) => {
                eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
                1
            }
            Err(e) => {
                eprintln!("ap: {e}");
                1
            }
        };
    }
    let abs: Vec<String> = paths
        .iter()
        .map(|p| cli::absolutize(p).display().to_string())
        .collect();
    match c.request(serde_json::json!({"cmd": "send", "paths": abs})) {
        Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => {
            println!(
                "已入队 {} 项{}",
                v["queued"].as_u64().unwrap_or(0),
                queue_hint(&v)
            );
            0
        }
        Ok(v) => {
            eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
            1
        }
        Err(e) => {
            eprintln!("ap: {e}");
            1
        }
    }
}

fn cmd_text(text: Option<String>) -> u8 {
    let data = match text {
        Some(t) => t,
        None => {
            use std::io::Read as _;
            let mut s = String::new();
            if std::io::stdin().read_to_string(&mut s).is_err() {
                eprintln!("ap: 读 stdin 失败");
                return 1;
            }
            s
        }
    };
    let Ok(mut c) = ipc() else { return 2 };
    match c.request(serde_json::json!({"cmd": "text", "data": data})) {
        Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => 0,
        Ok(v) => {
            eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
            1
        }
        Err(e) => {
            eprintln!("ap: {e}");
            1
        }
    }
}

fn cmd_log(follow: bool) -> u8 {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = std::process::Command::new("journalctl");
    cmd.args(["--user", "-u", "airpipe"]);
    if follow {
        cmd.arg("-f");
    }
    let err = cmd.exec();
    eprintln!("ap: journalctl 启动失败: {err}");
    1
}

fn cmd_stop() -> u8 {
    let Ok(mut c) = ipc() else { return 2 };
    match c.request(serde_json::json!({"cmd": "stop"})) {
        Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => {
            println!("已请求停止");
            0
        }
        Ok(v) => {
            eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
            1
        }
        Err(e) => {
            eprintln!("ap: {e}");
            1
        }
    }
}

fn cmd_config(edit: bool) -> u8 {
    let res = if edit { edit_config() } else { show_config() };

    match res {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("ap: {err}");
            1
        }
    }
}

fn edit_config() -> std::io::Result<()> {
    let path = config::ensure_config_file()?;
    let status = cli::open_in_editor(&path)?;

    if !status.success() {
        let code = status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into());
        return Err(std::io::Error::other(format!("编辑器非正常退出 ({code})")));
    }
    Ok(())
}

fn show_config() -> std::io::Result<()> {
    let (cfg, warn) = config::load();
    if let Some(w) = warn {
        eprintln!("ap: {w}");
    }

    println!("config file {}", config::display(&config::config_path()));
    println!("port        = {}", cfg.port());
    println!("device_name = {}", cfg.device_name());
    println!("recv_dir    = {}", config::display(&cfg.recv_dir()));
    println!(
        "clipboard   auto_text={} auto_image={} max_image_mb={}",
        cfg.clipboard.auto_text, cfg.clipboard.auto_image, cfg.clipboard.max_image_mb
    );
    println!("身份/状态   {}", config::display(&config::state_dir()));
    Ok(())
}
